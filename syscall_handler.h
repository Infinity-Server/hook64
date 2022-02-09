/*
 *  Author: SpringHack - springhack@live.cn
 *  Last modified: 2022-02-09 23:46:25
 *  Filename: syscall_handler.h
 *  Description: Created by SpringHack using vim automatically.
 */
#ifndef _SYSCALL_HANDLER_H_
#define _SYSCALL_HANDLER_H_

/* C++ standard library  */
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>

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
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>

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

void HOOK_SYS_openat(const std::map<std::string, std::string> &binds, pid_t pid,
                     user_regs_struct regs);

#endif  // _SYSCALL_HANDLER_H_
