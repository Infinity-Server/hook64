/*
 *  Author: SpringHack - springhack@live.cn
 *  Last modified: 2022-02-09 23:46:12
 *  Filename: hook64.cc
 *  Description: Created by SpringHack using vim automatically.
 */
#include "syscall_handler.h"

enum SYSCALL_STATE { SYSCALL_ENTERED, SYSCALL_EXITED };
struct child_syscall_state_t {
  SYSCALL_STATE st;
  int no;
};
static void toggle_syscall_state(child_syscall_state_t &st) {
  st.st = (st.st == SYSCALL_ENTERED ? SYSCALL_EXITED : SYSCALL_ENTERED);
}
static std::unordered_map<pid_t, child_syscall_state_t> chld_sysc_map;

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

  LOG(INFO) << "hook: forking ...";

  const pid_t child = fork();
  if (!child) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execvp(argv[offset], argv + offset);
    FATAL("%s", strerror(errno));
  }

  LOG(INFO) << "hook: waiting for initial stop of child " << child << " ...";
  int status;
  do {
    waitpid(child, &status, 0);
  } while (!WIFSTOPPED(status));
  LOG(INFO) << "hook: initial stop observed ...";

  int ptrace_options = 0;
  ptrace_options |= PTRACE_O_EXITKILL;
  ptrace_options |= PTRACE_O_TRACECLONE;
  ptrace_options |= PTRACE_O_TRACESYSGOOD;

  LOG(INFO) << "hook: setting ptrace options ...";
  ptrace(PTRACE_SETOPTIONS, child, 0, ptrace_options);
  LOG(INFO) << "hook: ptrace options set ...";

  auto wait_for_syscall_entry_or_exit = [](pid_t pid) -> pid_t {
    siginfo_t si;
    uintptr_t sig = 0;

    for (;;) {
      if (pid != -1) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, (void *)sig) == -1) {
          LOG(INFO) << "hook: failed to ptrace(PTRACE_SYSCALL): "
                    << strerror(errno);
          return -1;
        }
      }

      sig = 0;
      pid = -1;

      int status;
      pid_t child_waited = waitpid(-1, &status, __WALL);
      if (child_waited == -1) {
        LOG(INFO) << "hook: waitpid(1) failed : " << strerror(errno);
        return -1;
      } else {
        if (WIFSTOPPED(status)) {
          pid = child_waited;

          const int stopsig = WSTOPSIG(status);
          if (stopsig == (SIGTRAP | 0x80)) {
            return child_waited;
          } else if (stopsig == SIGTRAP) {
            const unsigned int event = (unsigned int)status >> 16;
            switch (event) {
              case PTRACE_EVENT_VFORK:
                LOG(INFO) << "hook: ptrace event (PTRACE_EVENT_VFORK)";
                break;
              case PTRACE_EVENT_FORK:
                LOG(INFO) << "hook: ptrace event (PTRACE_EVENT_FORK)";
                break;
              case PTRACE_EVENT_CLONE: {
                pid_t new_child;
                ptrace(PTRACE_GETEVENTMSG, child_waited, 0, &new_child);
                LOG(INFO) << "hook: ptrace event (PTRACE_EVENT_CLONE) ["
                          << new_child << "]";
                break;
              }
              case PTRACE_EVENT_VFORK_DONE:
                LOG(INFO) << "hook: ptrace event (PTRACE_EVENT_VFORK_DONE)";
                break;
              case PTRACE_EVENT_EXEC:
                LOG(INFO) << "hook: ptrace event (PTRACE_EVENT_EXEC)";
                break;
              case PTRACE_EVENT_EXIT:
                LOG(INFO) << "hook: ptrace event (PTRACE_EVENT_EXIT)";
                break;
              case PTRACE_EVENT_STOP:
                LOG(INFO) << "hook: ptrace event (PTRACE_EVENT_STOP)";
                break;
              case PTRACE_EVENT_SECCOMP:
                LOG(INFO) << "hook: ptrace event (PTRACE_EVENT_SECCOMP)";
                break;
              default:
                LOG(INFO) << "hook: unknown ptrace event " << event;
                break;
            }
          } else if (ptrace(PTRACE_GETSIGINFO, child_waited, 0, &si) < 0) {
            LOG(INFO) << "hook: group-stop [" << stopsig << "]";

          } else {
            LOG(INFO) << "hook: signal-delivery-stop [" << stopsig << "]";

            sig = stopsig;
          }
        } else {
          LOG(INFO) << "hook: child terminated";
        }
      }
    }
  };

  pid_t pid = child; /* handle initial signal-delivery-stop */
  for (;;) {
    pid = wait_for_syscall_entry_or_exit(pid);
    if (pid == -1) break;

    child_syscall_state_t &st = chld_sysc_map[pid];
    struct user_regs_struct regs;
    struct iovec vec;
    vec.iov_base = &regs;
    vec.iov_len = sizeof(user_regs_struct);
    switch (st.st) {
      case SYSCALL_ENTERED: {
        /* gather system call arguments */
        if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &vec) == -1) {
          FATAL("%s", strerror(errno));
        }
        st.no = GET_REG(pid, ARCH_REG_SYSCALL_NR, regs);

        if (st.no == SYS_openat) {
          HOOK_SYS_openat(binds, pid, regs);
        }
        break;
      }

      case SYSCALL_EXITED: {
        ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &vec);
        int res = GET_REG(pid, ARCH_REG_SYSCALL_RET, regs);
        LOG(INFO) << "hook: SYSCALL [" << st.no << "] = " << res;
        break;
      }

      default:
        __builtin_unreachable();
    }

    toggle_syscall_state(st);
  }

  return 0;
}
