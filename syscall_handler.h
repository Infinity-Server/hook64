#ifndef _SYSCALL_HANDLER_H_
#define _SYSCALL_HANDLER_H_

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

// Log Util
struct DoLog {
  bool end_;
  bool debug_;
  DoLog(const std::string &start = "[INFO] ", bool end = true);
  ~DoLog();
  template <typename T>
  DoLog &operator<<(T t) {
    if (!debug_) {
      std::cerr << t;
    }
    return *this;
  }
};

void HOOK_SYS_openat(const std::map<std::string, std::string> &binds, pid_t pid, user_regs_struct regs);

#endif  // _SYSCALL_HANDLER_H_
