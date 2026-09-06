#include "Elevator.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <spdlog/spdlog.h>
#include <sstream>
#include <thread>

#include <boost/asio.hpp>
#include <boost/process/v2/process.hpp>
#include <boost/process/v2/stdio.hpp>

#include "utils/StringUtils.h"

#ifdef WINDOWS
#include <Windows.h>
#else
#include <unistd.h>
#endif

// Runs privileged commands without making the whole GUI root.
//
// **Why one-shot rather than a persistent helper.** The first design kept a
// root helper alive and fed it commands over a pipe so the user would
// authenticate once per session. That cannot work on macOS: osascript's
// "with administrator privileges" does not forward stdin to the child, and
// only returns its output once the child exits. Verified directly - a helper
// that prints READY and then reads stdin receives nothing, so the parent
// deadlocked immediately after a successful prompt, which is exactly the
// failure seen on Install.
//
// Each privileged batch is therefore its own elevated command. The cost is a
// prompt per batch rather than per session; ElevationScope keeps that to the
// handful of genuinely user-initiated actions.
namespace {

// Escapes a string for embedding in an AppleScript double-quoted literal.
std::string EscapeForAppleScript(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 8);
  for(auto c : s) {
    if(c == '\\' || c == '"')
      out += '\\';
    out += c;
  }
  return out;
}

constexpr auto EXIT_MARKER = "__PCBU_EXIT__=";

// Runs one shell command with elevation, returning its combined output.
//
// Executed verbatim: callers must never interpolate untrusted input. There is
// deliberately no sanitising layer, which would give false confidence rather
// than real safety.
ShellCmdResult RunElevatedOnce(const std::string &command) {
#ifdef WINDOWS
  // ShellExecute "runas" raises UAC but returns no pipes, so the command's
  // output and exit code cannot be captured. Left unimplemented rather than
  // silently discarding the result.
  (void)command;
  spdlog::error("Elevator: elevation is not implemented on Windows yet.");
  return {-1, "Not implemented."};
#else
  boost::asio::io_context ctx{};
  boost::asio::readable_pipe out{ctx};

  // Append the real exit code so it survives the wrapper, which otherwise
  // reports only its own status and would mask a failed command.
  auto wrapped = fmt::format("{} 2>&1; echo {}$?", command, EXIT_MARKER);

  std::unique_ptr<boost::process::v2::process> proc{};
  try {
#ifdef APPLE
    auto script = fmt::format(R"(do shell script "{}" with administrator privileges)",
                              EscapeForAppleScript(wrapped));
    proc = std::make_unique<boost::process::v2::process>(
        ctx, "/usr/bin/osascript", std::vector<std::string>{"-e", script},
        boost::process::v2::process_stdio{{}, out, out});
#else
    // pkexec runs a program rather than a shell string, so invoke sh directly.
    proc = std::make_unique<boost::process::v2::process>(
        ctx, "/usr/bin/pkexec", std::vector<std::string>{"/bin/sh", "-c", wrapped},
        boost::process::v2::process_stdio{{}, out, out});
#endif
  } catch(const std::exception &ex) {
    spdlog::error("Elevator: failed to launch elevation. ({})", ex.what());
    return {-1, ex.what()};
  }

  std::string output{};
  for(;;) {
    boost::system::error_code ec;
    char chunk[4096];
    auto n = out.read_some(boost::asio::buffer(chunk), ec);
    if(ec || n == 0)
      break;
    output.append(chunk, n);
  }

  boost::system::error_code waitEc;
  auto wrapperExit = proc->wait(waitEc);

  // Recover the command's own exit code. A cancelled prompt never runs the
  // command, so the marker is absent - an ordinary outcome, not an error.
  int exitCode = wrapperExit;
  auto marker = output.rfind(EXIT_MARKER);
  if(marker != std::string::npos) {
    exitCode = std::atoi(output.c_str() + marker + std::strlen(EXIT_MARKER));
    output.erase(marker);
  } else if(wrapperExit != 0) {
    spdlog::info("Elevator: elevation was cancelled or refused.");
  }

  while(!output.empty() && (output.back() == '\n' || output.back() == '\r'))
    output.pop_back();
  return {exitCode, output};
#endif
}

} // namespace

struct Elevator::Impl {
  // No persistent state: elevation happens per command. Kept so the pimpl
  // and the public header stay stable.
  bool unused{};
};

Elevator::Elevator() : m_Impl(std::make_unique<Impl>()) {}

Elevator::~Elevator() = default;

bool Elevator::IsElevated() const {
  // There is no long-lived privileged session to be inside; each command
  // elevates on its own.
  return Shell::IsRunningAsAdmin();
}

bool Elevator::Elevate() {
  // Nothing to pre-establish. Reports whether elevation is possible here, so
  // a caller can bail before starting a long operation.
  return Shell::IsRunningAsAdmin() || ElevationScope::IsAllowed();
}

ShellCmdResult Elevator::Run(const std::string &command) try {
  // Root already: run directly. Calls RunUserCommand, not RunCommand, since
  // the latter delegates back here when unprivileged.
  if(Shell::IsRunningAsAdmin())
    return Shell::RunUserCommand(command);

  if(!ElevationScope::IsAllowed()) {
    spdlog::debug("Elevator: refusing to prompt outside a user-initiated action.");
    return {-1, "Elevation not permitted here."};
  }
  return RunElevatedOnce(command);
} catch(const std::exception &ex) {
  // Nothing may escape: Run() is called from a Qt worker thread, and an
  // exception crossing that boundary terminates the process rather than
  // surfacing as a failed operation.
  spdlog::error("Elevator: unexpected error running command. ({})", ex.what());
  return {-1, ex.what()};
}

void Elevator::Shutdown() {
  // No persistent helper to tear down.
}

Elevator &GetElevator() {
  static Elevator instance{};
  return instance;
}

namespace {
// Depth rather than a bool so nested scopes behave.
thread_local int g_ElevationDepth = 0;

// Cross-thread windows. Atomic because pairing opens one on the UI thread and
// the write happens on a network thread.
std::atomic<int> g_SessionDepth{0};
} // namespace

ElevationScope::ElevationScope() {
  ++g_ElevationDepth;
}

ElevationScope::~ElevationScope() {
  if(g_ElevationDepth > 0)
    --g_ElevationDepth;
}

bool ElevationScope::IsAllowed() {
  return g_ElevationDepth > 0 || g_SessionDepth.load() > 0;
}

ElevationSession::ElevationSession(std::string reason) : m_Reason(std::move(reason)), m_Open(true) {
  g_SessionDepth.fetch_add(1);
  spdlog::info("Elevation window opened: {}", m_Reason);
}

ElevationSession::~ElevationSession() {
  Close();
}

void ElevationSession::Close() {
  if(!m_Open)
    return;
  m_Open = false;
  g_SessionDepth.fetch_sub(1);
  spdlog::info("Elevation window closed: {}", m_Reason);
}
