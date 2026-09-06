#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

// Privileged helper.
//
// The GUI stays unprivileged; only this runs as root. That split matters for
// more than hygiene: the lock feature needs the app to live in the user's own
// interactive session, and every platform's lock API refuses to act on a
// session the caller is not part of. Relaunching the whole GUI as root would
// silently break it.
//
// Protocol, line-oriented over stdin/stdout so the parent needs no IPC
// library and the helper stays auditable:
//
//   <- READY                 helper is up and running as root
//   -> RUN <shell command>   parent asks for one command
//   <- EXIT <code>           exit status of that command
//   <- OUT <line>            a line of its output (repeated)
//   <- DONE                  end of this command's output
//   -> QUIT                  parent is finished
//
// Security notes:
//
//  * The parent must be the only writer to this pipe. It is spawned by the
//    OS elevation prompt (osascript / UAC / pkexec) with inherited handles,
//    so no other process can address it - there is no socket or named pipe to
//    connect to.
//  * Commands are executed verbatim. This helper deliberately does NOT try to
//    sanitise them: a filter would give false confidence while the real
//    guarantee is that only our own parent can send anything at all. Callers
//    must never interpolate untrusted input into a command.
//  * The helper exits as soon as stdin closes, so it cannot outlive the GUI
//    and leave a root process idling.
namespace {

void Emit(const std::string &line) {
  std::cout << line << std::endl;
  std::cout.flush();
}

// Runs one command, streaming its output back line by line.
int RunCommand(const std::string &cmd) {
#ifdef _WIN32
  auto pipe = _popen(cmd.c_str(), "r");
#else
  auto pipe = popen(cmd.c_str(), "r");
#endif
  if(pipe == nullptr) {
    Emit("OUT failed to start command");
    return -1;
  }

  char buffer[4096];
  while(fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    std::string line(buffer);
    // Strip the trailing newline; the framing supplies its own.
    while(!line.empty() && (line.back() == '\n' || line.back() == '\r'))
      line.pop_back();
    Emit("OUT " + line);
  }

#ifdef _WIN32
  auto status = _pclose(pipe);
  return status;
#else
  auto status = pclose(pipe);
  // pclose returns the wait status, not the exit code.
  if(status == -1)
    return -1;
  if(WIFEXITED(status))
    return WEXITSTATUS(status);
  return -1;
#endif
}

bool IsRoot() {
#ifdef _WIN32
  // On Windows the elevation prompt has already run by the time we exist, so
  // reaching main at all implies the requested integrity level.
  return true;
#else
  return geteuid() == 0;
#endif
}

} // namespace

int main() {
  // Unbuffered so the parent sees each line as it happens rather than at exit.
  setvbuf(stdout, nullptr, _IONBF, 0);

  if(!IsRoot()) {
    Emit("ERROR not running as root");
    return 1;
  }
  Emit("READY");

  std::string line;
  while(std::getline(std::cin, line)) {
    while(!line.empty() && (line.back() == '\n' || line.back() == '\r'))
      line.pop_back();

    if(line == "QUIT")
      break;

    if(line.rfind("RUN ", 0) == 0) {
      auto cmd = line.substr(4);
      if(cmd.empty()) {
        Emit("EXIT -1");
        Emit("DONE");
        continue;
      }
      auto code = RunCommand(cmd);
      Emit("EXIT " + std::to_string(code));
      Emit("DONE");
      continue;
    }

    // Unknown verb. Answer rather than hanging the parent's read.
    Emit("EXIT -1");
    Emit("DONE");
  }

  // Falling out of the loop means stdin closed: the GUI is gone, so we must
  // not linger as an idle root process.
  return 0;
}
