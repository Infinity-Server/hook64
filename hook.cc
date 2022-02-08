/*
 *  Author: SpringHack - springhack@live.cn
 *  Last modified: 2022-02-08 13:22:47
 *  Filename: hook.cc
 *  Description: Created by SpringHack using vim automatically.
 */
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
#if defined(__aarch64__)
#define ARCH_REG_SP sp
#define ARCH_REG_SYSCALL_NR regs[8]
#define ARCH_REG_SYSCALL_RET regs[0]
#define ARCH_REG_SYSCALL_ARG0 regs[0]
#define ARCH_REG_SYSCALL_ARG1 regs[1]
#define ARCH_REG_SYSCALL_ARG2 regs[2]
#define ARCH_REG_SYSCALL_ARG3 regs[3]
#define ARCH_REG_SYSCALL_ARG4 regs[4]
#define ARCH_REG_SYSCALL_ARG5 regs[5]
#endif  // __aarch64__

#if defined(__x86_64__)
#define ARCH_REG_SP rsp
#define ARCH_REG_SYSCALL_NR orig_rax
#define ARCH_REG_SYSCALL_RET rax
#define ARCH_REG_SYSCALL_ARG0 rdi
#define ARCH_REG_SYSCALL_ARG1 rsi
#define ARCH_REG_SYSCALL_ARG2 rdx
#define ARCH_REG_SYSCALL_ARG3 r10
#define ARCH_REG_SYSCALL_ARG4 r8
#define ARCH_REG_SYSCALL_ARG5 r9
#endif  // __x86_64__

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
  char *stack_addr =
      reinterpret_cast<char *>(GET_REG(child, ARCH_REG_SP, regs));
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
  SET_REG(child, ARCH_REG_SYSCALL_ARG1, str_addr, regs);
  return true;
}

// Hooks
void HOOK_SYS_openat(const std::map<std::string, std::string> &binds, pid_t pid,
                     user_regs_struct regs) {
  long addr = GET_REG(pid, ARCH_REG_SYSCALL_ARG1, regs);
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
      if (!guest) {
        guest = host;
      } else {
        *guest = '\0';
        ++guest;
      }
      binds.insert({std::string(host), std::string(guest)});
      offset += 2;
    } else {
      break;
    }
  }

  for (const auto it : binds) {
    LOG(INFO) << "bind=" << it.first << ":" << it.second;
  }

  if (offset >= argc) {
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
    long syscall = GET_REG(pid, ARCH_REG_SYSCALL_NR, regs);

    /* print a representation of the system call */
    LOG(INFO_START) << "syscall=" << syscall << "("
                    << GET_REG(pid, ARCH_REG_SYSCALL_ARG0, regs) << ", "
                    << GET_REG(pid, ARCH_REG_SYSCALL_ARG1, regs) << ", "
                    << GET_REG(pid, ARCH_REG_SYSCALL_ARG2, regs) << ", "
                    << GET_REG(pid, ARCH_REG_SYSCALL_ARG3, regs) << ", "
                    << GET_REG(pid, ARCH_REG_SYSCALL_ARG4, regs) << ", "
                    << GET_REG(pid, ARCH_REG_SYSCALL_ARG5, regs) << ")";

    /* do hook process */
    do_hook_process(binds, syscall, pid, regs);

    /* run system call and stop on exit */
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) FATAL("%s", strerror(errno));
    if (waitpid(pid, 0, 0) == -1) FATAL("%s", strerror(errno));

    /* get system call result */
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &vec) == -1) {
      LOG(INFO_END) << " = ?";
      // system call was _exit(2) or similar
      if (errno == ESRCH) exit(GET_REG(pid, ARCH_REG_SYSCALL_ARG0, regs));
      FATAL("%s", strerror(errno));
    }

    /* print system call result */
    LOG(INFO_END) << " = " << GET_REG(pid, ARCH_REG_SYSCALL_RET, regs);
  }
}
