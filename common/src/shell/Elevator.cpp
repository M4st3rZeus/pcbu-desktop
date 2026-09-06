#include "Elevator.h"

#include <chrono>
#include <spdlog/spdlog.h>
#include <sstream>
#include <thread>

#include <boost/asio.hpp>
#include <boost/process/v2/process.hpp>
#include <boost/process/v2/stdio.hpp>

#include "utils/StringUtils.h"

#ifdef WINDOWS
#include <Windows.h>
#elif defined(APPLE)
#include <mach-o/dyld.h>
#include <unistd.h>
#else
#include <unistd.h>
#endif

namespace {

// Absolute path of the running executable.
//
// Must be the real binary path, not the working directory: the app is
// normally launched from Finder or a bundle, where cwd is unrelated to where
// the helper sits.
std::filesystem::path SelfPath() {
  std::error_code ec;
#ifdef WINDOWS
  wchar_t buf[MAX_PATH]{};
  if(GetModuleFileNameW(nullptr, buf, MAX_PATH) == 0)
    return {};
  return std::filesystem::path(buf);
#elif defined(APPLE)
  // macOS has no /proc; _NSGetExecutablePath is the supported route.
  uint32_t size = 0;
  _NSGetExecutablePath(nullptr, &size);
  std::string buf(size, '\0');
  if(_NSGetExecutablePath(buf.data(), &size) != 0)
    return {};
  auto resolved = std::filesystem::canonical(std::filesystem::path(buf.c_str()), ec);
  return ec ? std::filesystem::path(buf.c_str()) : resolved;
#else
  auto self = std::filesystem::read_symlink("/proc/self/exe", ec);
  return ec ? std::filesystem::path{} : self;
#endif
}

// Locates the privileged helper next to the running executable.
std::filesystem::path FindHelper() {
#ifdef WINDOWS
  constexpr auto helperName = "pcbu_elevator.exe";
#else
  constexpr auto helperName = "pcbu_elevator";
#endif

  auto self = SelfPath();
  if(self.empty())
    return {};
  auto exeDir = self.parent_path();

  // Bundle and install layouts put it beside us; a plain cmake build leaves
  // it in the elevator subdirectory.
  for(const auto &candidate : {exeDir / helperName, exeDir / "elevator" / helperName}) {
    if(std::filesystem::exists(candidate))
      return candidate;
  }
  return {};
}

// Escapes a string for embedding inside an AppleScript double-quoted literal.
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

} // namespace

struct Elevator::Impl {
  boost::asio::io_context ctx{};
  std::unique_ptr<boost::process::v2::process> proc{};
  std::unique_ptr<boost::asio::writable_pipe> in{};
  std::unique_ptr<boost::asio::readable_pipe> out{};
  std::string readBuffer{};
  bool ready{};

  // Reads one framed line from the helper. Empty on EOF.
  std::string ReadLine() {
    while(true) {
      auto pos = readBuffer.find('\n');
      if(pos != std::string::npos) {
        auto line = readBuffer.substr(0, pos);
        readBuffer.erase(0, pos + 1);
        while(!line.empty() && line.back() == '\r')
          line.pop_back();
        return line;
      }
      boost::system::error_code ec;
      char chunk[4096];
      auto n = out->read_some(boost::asio::buffer(chunk), ec);
      if(ec || n == 0)
        return {};
      readBuffer.append(chunk, n);
    }
  }

  bool WriteLine(const std::string &line) {
    boost::system::error_code ec;
    auto payload = line + "\n";
    boost::asio::write(*in, boost::asio::buffer(payload), ec);
    return !ec;
  }
};

Elevator::Elevator() : m_Impl(std::make_unique<Impl>()) {}

Elevator::~Elevator() {
  Shutdown();
}

bool Elevator::IsElevated() const {
  if(!m_Impl->ready || !m_Impl->proc)
    return false;
  // running() throws without an error_code, and the process is legitimately
  // gone when the user cancels the prompt - which made the throwing overload
  // reachable on the normal cancel path.
  boost::system::error_code ec;
  return m_Impl->proc->running(ec) && !ec;
}

bool Elevator::Elevate() {
  if(IsElevated())
    return true;

  // Already root (packaged service, or launched with sudo): no helper needed.
  if(Shell::IsRunningAsAdmin()) {
    spdlog::info("Already running with admin rights; no helper needed.");
    m_Impl->ready = true;
    return true;
  }

  auto helper = FindHelper();
  if(helper.empty()) {
    spdlog::error("Elevator: helper binary not found next to the executable.");
    return false;
  }

  try {
    m_Impl->in = std::make_unique<boost::asio::writable_pipe>(m_Impl->ctx);
    m_Impl->out = std::make_unique<boost::asio::readable_pipe>(m_Impl->ctx);

#ifdef WINDOWS
    // ShellExecute with the "runas" verb raises the UAC prompt. It gives no
    // pipes back, so on Windows the helper is launched per batch instead of
    // held open - see Run().
    spdlog::warn("Elevator: persistent helper is not implemented on Windows yet.");
    return false;
#elif defined(APPLE)
    // osascript's "with administrator privileges" is the supported route.
    // AuthorizationExecuteWithPrivileges has been deprecated since 10.7 and
    // should not be used for new work.
    auto script = fmt::format(R"(do shell script "{}" with administrator privileges)",
                              EscapeForAppleScript(helper.string()));
    m_Impl->proc = std::make_unique<boost::process::v2::process>(
        m_Impl->ctx, "/usr/bin/osascript", std::vector<std::string>{"-e", script},
        boost::process::v2::process_stdio{*m_Impl->in, *m_Impl->out, {}});
#else
    // pkexec shows the polkit prompt and keeps stdio wired through.
    m_Impl->proc = std::make_unique<boost::process::v2::process>(
        m_Impl->ctx, "/usr/bin/pkexec", std::vector<std::string>{helper.string()},
        boost::process::v2::process_stdio{*m_Impl->in, *m_Impl->out, {}});
#endif

    // The helper announces itself once it is up and confirmed root. A
    // cancelled prompt closes the pipe instead, which reads as EOF.
    auto line = m_Impl->ReadLine();
    if(line != "READY") {
      spdlog::warn("Elevator: helper did not become ready. (Got='{}')", line);
      Shutdown();
      return false;
    }
    m_Impl->ready = true;
    spdlog::info("Elevator: privileged helper ready.");
    return true;
  } catch(const std::exception &ex) {
    spdlog::error("Elevator: failed to start helper. ({})", ex.what());
    Shutdown();
    return false;
  }
}

ShellCmdResult Elevator::Run(const std::string &command) try {
  // Root already: run directly rather than round-tripping through a helper.
  // Calls RunUserCommand, not RunCommand: the latter now delegates here when
  // unprivileged, and going through it would be a recursive call guarded only
  // by an euid check.
  if(Shell::IsRunningAsAdmin())
    return Shell::RunUserCommand(command);

  if(!IsElevated() && !Elevate())
    return {-1, "Not elevated."};

  if(!m_Impl->WriteLine("RUN " + command)) {
    spdlog::error("Elevator: failed to send command.");
    Shutdown();
    return {-1, "Helper pipe closed."};
  }

  ShellCmdResult result{};
  std::ostringstream output{};
  while(true) {
    auto line = m_Impl->ReadLine();
    if(line.empty() && !IsElevated()) {
      // Helper died mid-command.
      Shutdown();
      return {-1, output.str()};
    }
    if(line == "DONE")
      break;
    if(line.rfind("EXIT ", 0) == 0) {
      result.exitCode = std::atoi(line.substr(5).c_str());
      continue;
    }
    if(line.rfind("OUT ", 0) == 0) {
      output << line.substr(4) << "\n";
      continue;
    }
    if(line.empty()) {
      // EOF without DONE.
      Shutdown();
      break;
    }
  }
  result.output = output.str();
  return result;
} catch(const std::exception &ex) {
  // Nothing here may escape: Run() is called from a Qt worker thread, and an
  // exception crossing that boundary terminates the process rather than
  // surfacing as a failed install.
  spdlog::error("Elevator: unexpected error running command. ({})", ex.what());
  Shutdown();
  return {-1, ex.what()};
}

void Elevator::Shutdown() try {
  boost::system::error_code ec;
  if(m_Impl->proc && m_Impl->proc->running(ec) && !ec) {
    m_Impl->WriteLine("QUIT");
    if(m_Impl->in)
      m_Impl->in->close(ec);
    // The helper exits on stdin close; give it a moment before forcing.
    for(int i = 0; i < 20; i++) {
      boost::system::error_code pollEc;
      if(!m_Impl->proc->running(pollEc) || pollEc)
        break;
      std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    boost::system::error_code killEc;
    if(m_Impl->proc->running(killEc) && !killEc)
      m_Impl->proc->terminate(killEc);
  }
  m_Impl->proc.reset();
  m_Impl->in.reset();
  m_Impl->out.reset();
  m_Impl->readBuffer.clear();
  m_Impl->ready = false;
} catch(const std::exception &ex) {
  // Shutdown runs from destructors and error paths; a throw here would be
  // fatal. Reset what we can and carry on.
  spdlog::warn("Elevator: error during shutdown. ({})", ex.what());
  m_Impl->proc.reset();
  m_Impl->in.reset();
  m_Impl->out.reset();
  m_Impl->readBuffer.clear();
  m_Impl->ready = false;
}

Elevator &GetElevator() {
  static Elevator instance{};
  return instance;
}

namespace {
// Depth rather than a bool so nested scopes behave.
thread_local int g_ElevationDepth = 0;
} // namespace

ElevationScope::ElevationScope() {
  ++g_ElevationDepth;
}

ElevationScope::~ElevationScope() {
  if(g_ElevationDepth > 0)
    --g_ElevationDepth;
}

bool ElevationScope::IsAllowed() {
  return g_ElevationDepth > 0;
}
