/*
 *  Author: SpringHack - springhack@live.cn
 *  Last modified: 2022-02-07 23:42:50
 *  Filename: hook.cc
 *  Description: Created by SpringHack using vim automatically.
 */
#define _POSIX_C_SOURCE 200112L

/* C++ standard library  */
#include <iostream>
#include <map>
#include <memory>
#include <string>

/* C standard library */
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/* Linux */
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <syscall.h>

/* Macros */
#define INFO DoLog()
#define INFO_START DoLog("[INFO] ", false)
#define INFO_END DoLog("")
#define INLINE DoLog("\n -> ", false)
#define LOG(__level__) __level__
#define FATAL(...)                           \
  do {                                       \
    fprintf(stderr, "[FATAL] " __VA_ARGS__); \
    fputc('\n', stderr);                     \
    exit(EXIT_FAILURE);                      \
  } while (0)

/* Registers */
#if defined(__aarch64__)
#define GET_REG(child, name, regs) regs.name
#define SET_REG(child, name, data, regs)                        \
  {                                                             \
    struct user_regs_struct fake_regs;                          \
    memcpy(&fake_regs, &regs, sizeof(struct user_regs_struct)); \
    fake_regs.name = reinterpret_cast<long>(str_addr);          \
    struct iovec vec;                                           \
    vec.iov_base = &fake_regs;                                  \
    vec.iov_len = sizeof(user_regs_struct);                     \
    ptrace(PTRACE_SETREGSET, child, NT_PRSTATUS, &vec);         \
  }
#else
#define GET_REG(child, name, ...) \
  real_get_reg(child, offsetof(struct user, regs.name))
#define SET_REG(child, name, data, ...) \
  real_set_reg(child, offsetof(struct user, regs.name), data)
long real_get_reg(pid_t child, int off) {
  long val = ptrace(PTRACE_PEEKUSER, child, off);
  return val;
}
void real_set_reg(pid_t child, int off, void *data) {
  ptrace(PTRACE_POKEUSER, child, off, data);
}
#endif  // __aarch64__

// Log Util
struct DoLog {
  bool end_;
  bool debug_;
  DoLog(const std::string &start = "[INFO] ", bool end = true) {
    debug_ = !getenv("DEBUG");
    if (!debug_) {
      std::cerr << start;
    }
    end_ = end;
  }
  template <typename T>
  DoLog &operator<<(T t) {
    if (!debug_) {
      std::cerr << t;
    }
    return *this;
  }
  ~DoLog() {
    if (!debug_ && end_) {
      std::cerr << std::endl;
    }
  }
};

// Methods
std::string read_string(pid_t child, unsigned long addr) {
  char *val = reinterpret_cast<char *>(malloc(4096));
  int allocated = 4096;
  int read = 0;
  unsigned long tmp;
  while (1) {
    if (read + sizeof tmp > allocated) {
      allocated *= 2;
      val = reinterpret_cast<char *>(realloc(val, allocated));
    }
    tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
    if (errno != 0) {
      val[read] = 0;
      break;
    }
    memcpy(val + read, &tmp, sizeof tmp);
    if (memchr(&tmp, 0, sizeof tmp) != NULL) break;
    read += sizeof tmp;
  }
  std::string rv(val);
  free(val);
  return rv;
}

bool write_string(pid_t child, unsigned long addr, const std::string &str,
                  user_regs_struct regs) {
#if defined(__aarch64__)
  char *stack_addr = reinterpret_cast<char *>(GET_REG(child, sp, regs));
#else
  char *stack_addr = reinterpret_cast<char *>(GET_REG(child, rsp, regs));
#endif  // __aarch64__
  stack_addr -= 128 + str.length();
  char *str_addr = stack_addr;

  std::unique_ptr<char> buffer(new char[str.length() + 100]);
  char *buf_ptr = buffer.get();
  memset(buf_ptr, 0, sizeof(str.length() + 100));
  strcpy(buf_ptr, str.c_str());
  do {
    int i;
    char val[sizeof(long)];
    for (i = 0; i < sizeof(long); ++i, ++buf_ptr) {
      val[i] = *buf_ptr;
      if (*buf_ptr == '\0') break;
    }
    ptrace(PTRACE_POKETEXT, child, stack_addr, *(long *)val);
    stack_addr += sizeof(long);
  } while (*buf_ptr);
#if defined(__aarch64__)
  SET_REG(child, regs[1], str_addr, regs);
#else
  SET_REG(child, rsi, str_addr);
#endif  // __aarch64__
  return true;
}

// Hooks
void HOOK_SYS_openat(const std::map<std::string, std::string> &binds, pid_t pid,
                     user_regs_struct regs) {
#if defined(__aarch64__)
  long addr = GET_REG(pid, regs[1], regs);
#else
  long addr = GET_REG(pid, rsi, regs);
#endif  // __aarch64__
  std::string file = read_string(pid, addr);
  LOG(INLINE) << "openat=" << file;
  auto it = binds.find(file);
  if (it != binds.end()) {
    LOG(INLINE) << "openat(hooked)=" << it->second;
    write_string(pid, addr, it->second, regs);
  }
}

void do_hook_process(const std::map<std::string, std::string> &binds,
                     long syscall, pid_t pid, user_regs_struct regs) {
  switch (syscall) {
    case SYS_openat:
      return HOOK_SYS_openat(binds, pid, regs);
    default:
      return;
  }
}

// Main
int main(int argc, char **argv) {
  /* parse binds */
  std::map<std::string, std::string> binds;
  int offset = 1;
  while (offset < argc) {
    if ((strcmp(argv[offset], "-b") == 0 ||
         strcmp(argv[offset], "--bind") == 0) &&
        offset + 1 < argc) {
      char *host = argv[offset + 1];
      char *guest = strchr(host, ':');
      *guest = '\0';
      ++guest;
      binds.insert({std::string(host), std::string(guest)});
      offset += 2;
    } else {
      break;
    }
  }

  for (const auto it : binds) {
    LOG(INFO) << "bind=" << it.first << ":" << it.second;
  }

  if (offset + 1 >= argc) {
    FATAL("Need execvp arguments !");
  }

  pid_t pid = fork();
  switch (pid) {
    case -1: /* error */
      FATAL("%s", strerror(errno));
    case 0: /* child */
      ptrace(PTRACE_TRACEME, 0, 0, 0);
      /* because we're now a tracee, execvp will block until the parent
       * attaches and allows us to continue. */
      execvp(argv[offset], argv + offset);
      FATAL("%s", strerror(errno));
  }

  /* parent */
  waitpid(pid, 0, 0);  // sync with execvp
  ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

  for (;;) {
    /* enter next system call */
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) FATAL("%s", strerror(errno));
    if (waitpid(pid, 0, 0) == -1) FATAL("%s", strerror(errno));

    /* gather system call arguments */
    struct user_regs_struct regs;
    struct iovec vec;
    vec.iov_base = &regs;
    vec.iov_len = sizeof(user_regs_struct);
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &vec) == -1) {
      FATAL("%s", strerror(errno));
    }
#if defined(__aarch64__)
    long syscall = regs.regs[8];
#else
    long syscall = regs.orig_rax;
#endif  //__aarch64__

    /* print a representation of the system call */
#if defined(__aarch64__)
    LOG(INFO_START) << "syscall=" << syscall << "(" << (long)regs.regs[0]
                    << ", " << (long)regs.regs[1] << ", " << (long)regs.regs[2]
                    << ", " << (long)regs.regs[3] << ", " << (long)regs.regs[4]
                    << ", " << (long)regs.regs[5] << ")";
#else
    LOG(INFO_START) << "syscall=" << syscall << "(" << (long)regs.rdi << ", "
                    << (long)regs.rsi << ", " << (long)regs.rdx << ", "
                    << (long)regs.r10 << ", " << (long)regs.r8 << ", "
                    << (long)regs.r9 << ")";
#endif  // __aarch64__

    /* do hook process */
    do_hook_process(binds, syscall, pid, regs);

    /* run system call and stop on exit */
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) FATAL("%s", strerror(errno));
    if (waitpid(pid, 0, 0) == -1) FATAL("%s", strerror(errno));

    /* get system call result */
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &vec) == -1) {
      LOG(INFO_END) << " = ?";
      // system call was _exit(2) or similar
      if (errno == ESRCH)
#if defined(__aarch64__)
        exit(regs.regs[0]);
#else
        exit(regs.rdi);
#endif  // __aarch64__
      FATAL("%s", strerror(errno));
    }

    /* print system call result */
#if defined(__aarch64__)
    LOG(INFO_END) << " = " << (long)regs.regs[8];
#else
    LOG(INFO_END) << " = " << (long)regs.rax;
#endif  // __aarch64__
  }
}
