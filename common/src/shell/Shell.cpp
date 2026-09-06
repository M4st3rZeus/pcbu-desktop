#include "Shell.h"

#include "shell/Elevator.h"

#include <openssl/rand.h>

#include <boost/filesystem.hpp>
#ifdef WINDOWS
#include <boost/process/v1.hpp>
#else
#include <boost/asio.hpp>
#include <boost/process/v2/environment.hpp>
#include <boost/process/v2/process.hpp>
#include <boost/process/v2/stdio.hpp>
#endif
#include <fstream>
#include <spdlog/spdlog.h>

#include "utils/StringUtils.h"

#ifdef WINDOWS
#include <boost/process/v1/windows.hpp>
//#include <boost/process/v2/windows/creation_flags.hpp>
#undef CreateFile

#define SHELL_NAME "cmd.exe"
#define SHELL_CMD_ARG "/c"
#elif LINUX
#define SHELL_NAME "bash"
#define SHELL_CMD_ARG "-c"
#elif APPLE
#define SHELL_NAME "zsh"
#define SHELL_CMD_ARG "-c"
#endif

bool Shell::IsRunningAsAdmin() {
#ifdef WINDOWS
  BOOL isAdmin = FALSE;
  PSID adminGroup = nullptr;
  SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
  if(!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
    spdlog::error("AllocateAndInitializeSid failed. (Code={})", GetLastError());
    return false;
  }
  if(!CheckTokenMembership(nullptr, adminGroup, &isAdmin)) {
    spdlog::error("CheckTokenMembership failed. (Code={})", GetLastError());
    isAdmin = FALSE;
  }
  if(adminGroup)
    FreeSid(adminGroup);
  return isAdmin;
#else
  return geteuid() == 0;
#endif
}

// Runs a command with the privileges the operation needs.
//
// Already root: run it directly. Otherwise route through the privileged
// helper, which prompts once per session rather than once per command. This
// finishes what the previous osascript stub was reaching for, without making
// the whole GUI root - the lock server has to stay in the user's own session.
//
// Callers must never interpolate untrusted input: the command is executed
// verbatim, exactly as with RunUserCommand.
ShellCmdResult Shell::RunCommand(const std::string &cmd) {
  if(IsRunningAsAdmin())
    return RunUserCommand(cmd);
  if(!ElevationScope::IsAllowed()) {
    // Outside a user-initiated action: run unprivileged and let the caller
    // handle the failure rather than prompting out of nowhere.
    return RunUserCommand(cmd);
  }
  return GetElevator().Run(cmd);
}

ShellCmdResult Shell::RunUserCommand(const std::string &cmd) {
#ifdef WINDOWS
  boost::process::v1::ipstream outStream{};
  boost::process::v1::ipstream errStream{};
  boost::process::v1::child proc(fmt::format("{0} {1} \"{2}\"", SHELL_NAME, SHELL_CMD_ARG, cmd), boost::process::v1::std_out > outStream,
                                 boost::process::v1::std_err > errStream, boost::process::v1::windows::create_no_window);
  std::string output{};
  std::string line{};
  while(outStream && std::getline(outStream, line) && !line.empty())
    output.append(line + "\n");
  while(errStream && std::getline(errStream, line) && !line.empty())
    output.append(line + "\n");
  proc.wait();
#else
  boost::asio::io_context ctx{};
  boost::asio::readable_pipe pipe{ctx};
  boost::process::v2::process proc(ctx, boost::process::v2::environment::find_executable(SHELL_NAME), {SHELL_CMD_ARG, cmd},
                                   boost::process::v2::process_stdio{{}, pipe, pipe}

#ifdef WINDOWS
                                   ,
                                   boost::process::v2::windows::process_creation_flags<CREATE_NO_WINDOW>{}
#endif
  );

  std::string output{};
  boost::system::error_code ec;
  boost::asio::read(pipe, boost::asio::dynamic_buffer(output), ec);
  proc.wait();
#endif

  spdlog::debug("Process exit. Code: {} Command: '{}' Output: '{}'", proc.exit_code(), cmd, StringUtils::Trim(output));
  auto result = ShellCmdResult();
  result.exitCode = proc.exit_code();
  result.output = output;
  return result;
}

void Shell::SpawnCommand(const std::string &cmd) {
#ifdef WINDOWS
  boost::process::v1::child proc(fmt::format("{0} {1} \"{2}\"", SHELL_NAME, SHELL_CMD_ARG, cmd), boost::process::v1::windows::create_no_window);
  proc.detach();
#else
  boost::asio::io_context ctx{};
  boost::process::v2::process proc(ctx, boost::process::v2::environment::find_executable(SHELL_NAME), {SHELL_CMD_ARG, cmd}
#ifdef WINDOWS
                                   ,
                                   boost::process::v2::windows::process_creation_flags<CREATE_NO_WINDOW>{}
#endif
  );
  proc.detach();
#endif
}

namespace {

// Single-quotes a path for safe use in a shell command.
//
// Paths reach the shell through the elevation wrapper, and a single stray
// metacharacter turns a file copy into arbitrary code. Wrapping in single
// quotes disables every expansion; the only character that needs care is a
// literal quote, closed and re-opened around an escaped one.
std::string ShellQuote(const std::string &s) {
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

// Hex name for a staging file. Deliberately not StringUtils::RandomString:
// that charset contains ;, |, $, <, > and friends, so an interpolated
// filename could break - or hijack - the command it lands in.
std::string RandomHexName(size_t bytes) {
  std::vector<uint8_t> buf(bytes);
  // CSPRNG, not rand(): the staging file briefly holds content destined for a
  // root-owned path, and a predictable name in a world-writable /tmp invites
  // a symlink race.
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

// Retries a failed filesystem operation through the privileged helper.
//
// Only permission failures are worth escalating: a missing parent or an
// invalid path fails identically as root, and prompting for those would train
// users to click through auth dialogs.
bool ElevatedFallback(const boost::system::error_code &ec, const std::string &command) {
  if(Shell::IsRunningAsAdmin())
    return false;
  // Only user-initiated actions may prompt. Without this a failed startup
  // read would ask for a password before any window is on screen.
  if(!ElevationScope::IsAllowed())
    return false;
  if(ec && ec != boost::system::errc::permission_denied &&
     ec != boost::system::errc::operation_not_permitted)
    return false;
  return GetElevator().Run(command).exitCode == 0;
}

} // namespace

bool Shell::CreateDir(const std::filesystem::path &path) {
  boost::system::error_code ec{};
  boost::filesystem::create_directories(boost::filesystem::path(path), ec);
  if(!ec.failed())
    return true;
  // Permission denied and we are not root: retry through the privileged
  // helper, which prompts once per session. Everything under
  // /etc/pc-bio-unlock and the PAM/credential-provider paths lands here.
  return ElevatedFallback(ec, fmt::format("mkdir -p {}", ShellQuote(path.string())));
}

bool Shell::RemoveDir(const std::filesystem::path &path) {
  boost::system::error_code ec{};
  boost::filesystem::remove(boost::filesystem::path(path), ec);
  if(!ec.failed())
    return true;
  return ElevatedFallback(ec, fmt::format("rm -R {}", ShellQuote(path.string())));
}

bool Shell::CreateFile(const std::filesystem::path &path) {
  std::ofstream file(path);
  if(file.is_open())
    return true;
  boost::system::error_code ec{boost::system::errc::permission_denied, boost::system::generic_category()};
  return ElevatedFallback(ec, fmt::format("touch {}", ShellQuote(path.string())));
}

bool Shell::RemoveFile(const std::filesystem::path &path) {
  boost::system::error_code ec{};
  boost::filesystem::remove(boost::filesystem::path(path), ec);
  if(!ec.failed())
    return true;
  return ElevatedFallback(ec, fmt::format("rm -f {}", ShellQuote(path.string())));
}

std::vector<uint8_t> Shell::ReadBytes(const std::filesystem::path &path) try {
  {
    std::ifstream file{};
    file.open(path, std::ios_base::binary);
    if(file)
      return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
  }

  // Root-owned, mode 600 files are the normal case here, not an error: the
  // paired-devices store is deliberately readable only by root so that
  // pcbu_auth can use it at the login screen. Without an elevated fallback
  // the desktop app simply saw an empty list for a store that was fine.
  if(IsRunningAsAdmin() || !ElevationScope::IsAllowed() || !std::filesystem::exists(path)) {
    spdlog::error("Failed to open file '{}'.", path.string());
    return {};
  }

  // Copy to a staging file this user can read, rather than piping the content
  // through the helper's line protocol - the store is text today but the same
  // path is used for binary payloads.
  auto temp = std::filesystem::temp_directory_path() /
              fmt::format("pcbu_read_{}", RandomHexName(8));
  // RunIfElevated, not Run: a read must never be the thing that raises a
  // password prompt. If no helper is up yet the read fails and the caller
  // shows an empty list, which is recoverable - a prompt appearing before the
  // window is not.
  auto result = GetElevator().RunIfElevated(fmt::format("cat {} > {} && chown {} {}", ShellQuote(path.string()),
                                                        ShellQuote(temp.string()), getuid(),
                                                        ShellQuote(temp.string())));
  std::vector<uint8_t> data{};
  if(result.exitCode == 0) {
    std::ifstream staged(temp, std::ios_base::binary);
    if(staged)
      data.assign(std::istreambuf_iterator<char>(staged), std::istreambuf_iterator<char>());
  } else {
    spdlog::error("Failed to read '{}' even with elevation. (Code={}, Output={})", path.string(), result.exitCode,
                  result.output);
  }
  // Always remove the copy: it may hold the encrypted password blob.
  std::error_code rmEc{};
  std::filesystem::remove(temp, rmEc);
  return data;
} catch(const std::exception &ex) {
  spdlog::error("Failed to read '{}': {}", path.string(), ex.what());
  return {};
}

bool Shell::WriteBytes(const std::filesystem::path &path, const std::vector<uint8_t> &data) try {
  {
    std::ofstream file(path, std::ios::out | std::ios::binary);
    file.write(reinterpret_cast<const char *>(data.data()), (std::streamsize)data.size());
    file.close();
    if(!file.fail() && !file.bad())
      return true;
  }
  if(IsRunningAsAdmin())
    return false;
  if(!ElevationScope::IsAllowed())
    return false;

  // Cannot pipe binary content through the helper's line protocol, so stage
  // it in a temp file the user can write and have root move it into place.
  // The staged copy is removed even on failure - it may hold the encrypted
  // password blob.
  auto temp = std::filesystem::temp_directory_path() /
              fmt::format("pcbu_stage_{}", RandomHexName(8));
  {
    std::ofstream tmpFile(temp, std::ios::out | std::ios::binary);
    if(!tmpFile)
      return false;
    tmpFile.write(reinterpret_cast<const char *>(data.data()), (std::streamsize)data.size());
    tmpFile.close();
    if(tmpFile.fail() || tmpFile.bad()) {
      std::error_code rmEc{};
      std::filesystem::remove(temp, rmEc);
      return false;
    }
  }

  auto result = GetElevator().Run(fmt::format("mkdir -p {} && mv -f {} {}",
                                               ShellQuote(path.parent_path().string()),
                                               ShellQuote(temp.string()),
                                               ShellQuote(path.string())));
  auto moved = result.exitCode == 0;
  std::error_code rmEc{};
  std::filesystem::remove(temp, rmEc);
  if(!moved)
    spdlog::error("Failed to write '{}' even with elevation. (Code={}, Output={})", path.string(), result.exitCode,
                  result.output);
  return moved;
} catch(const std::exception &ex) {
  // Called from a Qt worker thread during install; an escaping exception
  // would terminate the app instead of failing the operation.
  spdlog::error("Failed to write '{}': {}", path.string(), ex.what());
  return false;
}
