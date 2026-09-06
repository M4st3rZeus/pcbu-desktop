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

#include <filesystem>
#include <mutex>
#include <openssl/rand.h>
#include <optional>

#ifdef WINDOWS
#include <Windows.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#ifdef APPLE
#include <mach-o/dyld.h>
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

#ifndef WINDOWS

// Random hex, for the socket name and the auth token. CSPRNG rather than
// rand(): the token is what stops another process on this account from
// driving a root helper.
std::string RandomHex(size_t bytes) {
  std::vector<uint8_t> buf(bytes);
  if(RAND_bytes(buf.data(), static_cast<int>(bytes)) != 1)
    return {};
  static constexpr char digits[] = "0123456789abcdef";
  std::string out{};
  out.reserve(bytes * 2);
  for(auto b : buf) {
    out += digits[(b >> 4) & 0xF];
    out += digits[b & 0xF];
  }
  return out;
}

// Single-quotes a value for safe interpolation into a shell command.
std::string Quote(const std::string &s) {
  std::string out = "'";
  for(auto c : s) {
    if(c == '\'')
      out += "'\\''";
    else
      out += c;
  }
  out += "'";
  return out;
}

// Locates the helper binary next to the running executable.
std::filesystem::path FindHelper() {
  std::error_code ec;
#ifdef APPLE
  uint32_t size = 0;
  _NSGetExecutablePath(nullptr, &size);
  std::string buf(size, '\0');
  if(_NSGetExecutablePath(buf.data(), &size) != 0)
    return {};
  auto self = std::filesystem::canonical(std::filesystem::path(buf.c_str()), ec);
  if(ec)
    self = std::filesystem::path(buf.c_str());
#else
  auto self = std::filesystem::read_symlink("/proc/self/exe", ec);
  if(ec)
    return {};
#endif
  auto dir = self.parent_path();
  for(const auto &candidate : {dir / "pcbu_elevator", dir / "elevator" / "pcbu_elevator"}) {
    if(std::filesystem::exists(candidate))
      return candidate;
  }
  return {};
}

// One request over the helper's socket. Empty result means the channel is
// unusable and the caller should fall back to a fresh prompt.
std::optional<ShellCmdResult> RunOverSocket(const std::string &socketPath, const std::string &token,
                                            const std::string &command) {
  auto fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if(fd < 0)
    return std::nullopt;

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);
  if(::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
    ::close(fd);
    return std::nullopt;
  }

  auto send = [fd](const std::string &line) {
    auto payload = line + "\n";
    auto remaining = payload.size();
    auto p = payload.c_str();
    while(remaining > 0) {
      auto n = ::write(fd, p, remaining);
      if(n <= 0)
        return false;
      p += n;
      remaining -= static_cast<size_t>(n);
    }
    return true;
  };

  if(!send(token) || !send("RUN " + command)) {
    ::close(fd);
    return std::nullopt;
  }

  std::string buffer{};
  char chunk[4096];
  for(;;) {
    auto n = ::read(fd, chunk, sizeof(chunk));
    if(n <= 0)
      break;
    buffer.append(chunk, static_cast<size_t>(n));
  }
  ::close(fd);

  ShellCmdResult result{-1, {}};
  std::ostringstream output{};
  size_t pos = 0;
  while(pos < buffer.size()) {
    auto nl = buffer.find('\n', pos);
    auto line = buffer.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
    pos = (nl == std::string::npos) ? buffer.size() : nl + 1;
    if(line.rfind("OUT ", 0) == 0)
      output << line.substr(4) << "\n";
    else if(line.rfind("EXIT ", 0) == 0)
      result.exitCode = std::atoi(line.c_str() + 5);
  }
  result.output = output.str();
  while(!result.output.empty() && result.output.back() == '\n')
    result.output.pop_back();
  return result;
}

#endif // !WINDOWS

} // namespace

struct Elevator::Impl {
  // Set once the root helper is listening. Guarded because Run() is called
  // from the UI thread and from PairingServer's client thread.
  std::mutex mutex{};
  std::string socketPath{};
  std::string token{};
  bool helperRunning{};
};

Elevator::Elevator() : m_Impl(std::make_unique<Impl>()) {}

Elevator::~Elevator() {
  Shutdown();
}

bool Elevator::IsElevated() const {
  if(Shell::IsRunningAsAdmin())
    return true;
  std::lock_guard lock(m_Impl->mutex);
  return m_Impl->helperRunning;
}

// Starts the privileged helper, prompting once.
//
// This is the whole point of the socket design: one authentication, then
// every later privileged operation reuses the channel without a prompt.
bool Elevator::Elevate() {
  if(Shell::IsRunningAsAdmin())
    return true;

#ifdef WINDOWS
  spdlog::error("Elevator: persistent elevation is not implemented on Windows yet.");
  return false;
#else
  std::lock_guard lock(m_Impl->mutex);
  if(m_Impl->helperRunning)
    return true;

  auto helper = FindHelper();
  if(helper.empty()) {
    spdlog::error("Elevator: helper binary not found next to the executable.");
    return false;
  }

  auto token = RandomHex(24);
  auto socketPath = fmt::format("/tmp/pcbu-{}/{}.sock", getuid(), RandomHex(8));
  if(token.empty() || socketPath.size() >= 100) {
    spdlog::error("Elevator: could not prepare the helper channel.");
    return false;
  }

  // Detached so it survives the elevation wrapper exiting, which is what
  // makes one prompt cover the whole session. The token goes through the
  // environment rather than argv, since argv is world-readable via ps.
  //
  // `</dev/null >/dev/null 2>&1` on the helper is load-bearing, not tidiness.
  // A backgrounded child inherits the wrapper's stdout pipe and holds it open
  // for its whole lifetime, so the parent's read loop waits for an EOF that
  // never arrives - Elevate() hung forever and the app never finished
  // starting. Closing all three descriptors lets the pipe reach EOF as soon
  // as the wrapper itself exits.
  // The braces matter twice over. RunElevatedOnce appends "; echo MARKER=$?"
  // to recover the exit code, and `cmd & ; echo` is a shell syntax error - so
  // without them the launch never ran at all and the marker never appeared.
  auto launch = fmt::format(
      "mkdir -p {} && {{ PCBU_ELEVATOR_TOKEN={} nohup {} {} {} {} </dev/null >/dev/null 2>&1 & }}",
      Quote(std::filesystem::path(socketPath).parent_path().string()), Quote(token), Quote(helper.string()),
      Quote(socketPath), getuid(), getpid());

  auto result = RunElevatedOnce(launch);
  if(result.exitCode != 0) {
    spdlog::warn("Elevator: helper launch was cancelled or failed. (Code={})", result.exitCode);
    return false;
  }

  // Wait for the socket to appear; the helper binds it right after starting.
  for(int i = 0; i < 50; i++) {
    if(std::filesystem::exists(socketPath)) {
      m_Impl->socketPath = socketPath;
      m_Impl->token = token;
      m_Impl->helperRunning = true;
      spdlog::info("Elevator: privileged helper ready; no further prompts this session.");
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  spdlog::error("Elevator: helper did not create its socket.");
  return false;
#endif
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

#ifndef WINDOWS
  // Reuse the helper when it is up. Start it on first use so the prompt
  // happens at a moment the user is expecting it.
  if(!IsElevated())
    Elevate();

  std::string socketPath{};
  std::string token{};
  {
    std::lock_guard lock(m_Impl->mutex);
    socketPath = m_Impl->socketPath;
    token = m_Impl->token;
  }
  if(!socketPath.empty()) {
    if(auto result = RunOverSocket(socketPath, token, command); result.has_value())
      return result.value();
    // Helper is gone: drop it and fall through to a one-shot prompt rather
    // than failing the operation outright.
    spdlog::warn("Elevator: helper channel is dead; falling back to a prompt.");
    std::lock_guard lock(m_Impl->mutex);
    m_Impl->helperRunning = false;
    m_Impl->socketPath.clear();
    m_Impl->token.clear();
  }
#endif

  return RunElevatedOnce(command);
} catch(const std::exception &ex) {
  // Nothing may escape: Run() is called from a Qt worker thread, and an
  // exception crossing that boundary terminates the process rather than
  // surfacing as a failed operation.
  spdlog::error("Elevator: unexpected error running command. ({})", ex.what());
  return {-1, ex.what()};
}

ShellCmdResult Elevator::RunIfElevated(const std::string &command) {
  if(Shell::IsRunningAsAdmin())
    return Shell::RunUserCommand(command);
#ifndef WINDOWS
  {
    std::lock_guard lock(m_Impl->mutex);
    if(!m_Impl->helperRunning)
      return {-1, "No privileged helper running."};
  }
  return Run(command);
#else
  return {-1, "Not implemented."};
#endif
}

void Elevator::Shutdown() {
#ifndef WINDOWS
  std::lock_guard lock(m_Impl->mutex);
  if(!m_Impl->helperRunning)
    return;
  // The helper also exits on its own when this process dies; this just makes
  // teardown immediate on a clean quit.
  std::error_code ec{};
  std::filesystem::remove(m_Impl->socketPath, ec);
  m_Impl->helperRunning = false;
  m_Impl->socketPath.clear();
  m_Impl->token.clear();
#endif
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
