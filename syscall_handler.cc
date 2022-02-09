/*
 *  Author: SpringHack - springhack@live.cn
 *  Last modified: 2022-02-08 13:22:47
 *  Filename: hook.cc
 *  Description: Created by SpringHack using vim automatically.
 */

#include "syscall_handler.h"

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
    long ret = ptrace(PTRACE_SETREGSET, child, NT_PRSTATUS, &vec);         \
    LOG(INFO) << "POKETEXT=" << ret; \
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

// typedef struct {
//   const char* syscall;
//   const char* name;
//   const char* _;
//   const char* __;
//   const char* arg_1;
//   const char* arg_2;
//   const char* arg_3;
//   const char* arg_4;
//   const char* arg_5;
//   const char* arg_6;
// } node;
// static node syscallent[] = {
// #include "calls.h"
// };
// 
// typedef struct {
//   std::string name;
//   bool args_is_str[6];
// } call_item;
// 
// std::map<long, call_item> calls;

// Log Util
DoLog::DoLog(const std::string &start, bool end) {
    debug_ = !getenv("DEBUG");
    if (!debug_) {
      std::cerr << start;
    }
    end_ = end;
  }
DoLog::~DoLog() {
    if (!debug_ && end_) {
      std::cerr << std::endl;
    }
  }

// Methods
std::string read_string(pid_t child, unsigned long addr) {
  char *val = reinterpret_cast<char *>(malloc(4096));
  unsigned int allocated = 4096;
  unsigned int read = 0;
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
    unsigned int i;
    char val[sizeof(long)];
    for (i = 0; i < sizeof(long); ++i, ++buf_ptr) {
      val[i] = *buf_ptr;
      if (*buf_ptr == '\0') break;
    }
    long ret = ptrace(PTRACE_POKETEXT, child, stack_addr, *(long *)val);
    LOG(INFO) << "POKETEXT=" << ret;
    stack_addr += sizeof(long);
  } while (*buf_ptr);
  SET_REG(child, ARCH_REG_SYSCALL_ARG1, str_addr, regs);
  return true;
}

// Hooks
void HOOK_SYS_openat(const std::map<std::string, std::string> &binds, pid_t pid,
                     user_regs_struct regs) {
  struct iovec vec;
  vec.iov_base = &regs;
  vec.iov_len = sizeof(user_regs_struct);
  if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &vec) == -1) {
    FATAL("%s", strerror(errno));
  }
  long addr = GET_REG(pid, ARCH_REG_SYSCALL_ARG1, regs);
  std::string file = read_string(pid, addr);
  // LOG(INLINE) << "openat=" << file;
  auto it = binds.find(file);
  if (it != binds.end()) {
    // LOG(INLINE) << "openat(hooked)=" << it->second;
    write_string(pid, addr, it->second, regs);
  }
}
