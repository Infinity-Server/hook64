/*
 *  Author: SpringHack - springhack@live.cn
 *  Last modified: 2022-02-09 23:30:36
 *  Filename: syscall_handler.cc
 *  Description: Created by SpringHack using vim automatically.
 */

#include "syscall_handler.h"

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
  LOG(INFO) << "target: openat=" << file;
  auto it = binds.find(file);
  if (it != binds.end()) {
    LOG(INFO) << "target: openat(hooked)=" << it->second;
    write_string(pid, addr, it->second, regs);
  }
}
