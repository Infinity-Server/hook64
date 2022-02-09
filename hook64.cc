#include <unordered_map>
#include <asm/unistd.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <array>
#include <thread>
#include <mutex>
#include <sys/syscall.h>
#include <string.h>

#include "syscall_handler.h"

enum SYSCALL_STATE { SYSCALL_ENTERED, SYSCALL_EXITED };
struct child_syscall_state_t {
  SYSCALL_STATE st;
  int no;
};
static void toggle_syscall_state(child_syscall_state_t& st) {
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

  fprintf(stderr, "parent: forking...\n");

  const pid_t child = fork();
  if (!child) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execvp(argv[offset], argv + offset);
    FATAL("%s", strerror(errno));
  }

  fprintf(stderr, "parent: waiting for initial stop of child %d...\n", child);
  int status;
  do {
    waitpid(child, &status, 0);
  } while (!WIFSTOPPED(status));
  fprintf(stderr, "parent: initial stop observed\n");

  int ptrace_options = 0;
  ptrace_options |= PTRACE_O_TRACESYSGOOD;
  ptrace_options |= PTRACE_O_EXITKILL;
  ptrace_options |= PTRACE_O_TRACECLONE;

  fprintf(stderr, "parent: setting ptrace options...\n");
  ptrace(PTRACE_SETOPTIONS, child, 0, ptrace_options);
  fprintf(stderr, "ptrace options set!\n");

  auto wait_for_syscall_entry_or_exit = [](pid_t pid) -> pid_t {
    siginfo_t si;
    uintptr_t sig = 0;

    for (;;) {
      if (pid != -1) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, (void *)sig) == -1) {
          fprintf(stderr,
                  "parent: failed to ptrace(PTRACE_SYSCALL): %s\n",
                  strerror(errno));
          return -1;
        }
      }

      sig = 0;
      pid = -1;

      int status;
      pid_t child_waited = waitpid(-1, &status, __WALL);
      if (child_waited == -1) {
        fprintf(stderr, "parent: waitpid(1) failed : %s\n",
                strerror(errno));
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
              fprintf(stderr, "parent: ptrace event (PTRACE_EVENT_VFORK)\n");
              break;
            case PTRACE_EVENT_FORK:
              fprintf(stderr, "parent: ptrace event (PTRACE_EVENT_FORK)\n");
              break;
            case PTRACE_EVENT_CLONE: {
              pid_t new_child;
              ptrace(PTRACE_GETEVENTMSG, child_waited, 0, &new_child);
              fprintf(stderr,
                      "parent: ptrace event (PTRACE_EVENT_CLONE) [%d]\n",
                      new_child);
              break;
            }
            case PTRACE_EVENT_VFORK_DONE:
              fprintf(stderr, "parent: ptrace event (PTRACE_EVENT_VFORK_DONE)\n");
              break;
            case PTRACE_EVENT_EXEC:
              fprintf(stderr, "parent: ptrace event (PTRACE_EVENT_EXEC)\n");
              break;
            case PTRACE_EVENT_EXIT:
              fprintf(stderr, "parent: ptrace event (PTRACE_EVENT_EXIT)\n");
              break;
            case PTRACE_EVENT_STOP:
              fprintf(stderr, "parent: ptrace event (PTRACE_EVENT_STOP)\n");
              break;
            case PTRACE_EVENT_SECCOMP:
              fprintf(stderr, "parent: ptrace event (PTRACE_EVENT_SECCOMP)\n");
              break;
            default:
              fprintf(stderr, "parent: unknown ptrace event %u\n", event);
              break;
            }
          } else if (ptrace(PTRACE_GETSIGINFO, child_waited, 0, &si) < 0) {
            fprintf(stderr, "parent: group-stop [%d]\n",
                    stopsig);

          } else {
            fprintf(stderr, "parent: signal-delivery-stop [%d]\n",
                    stopsig);

            sig = stopsig;
          }
        } else {
          fprintf(stderr, "parent: child terminated\n");
        }
      }
    }
  };

  pid_t pid = child; /* handle initial signal-delivery-stop */
  for (;;) {
    pid = wait_for_syscall_entry_or_exit(pid);
    if (pid == -1)
      break;

    child_syscall_state_t &st = chld_sysc_map[pid];
    switch (st.st) {
    case SYSCALL_ENTERED: {
      //
      // getting the syscall number
      //
      int no;

#if defined(__i386__)
      no = ptrace(PTRACE_PEEKUSER, pid,
                  __builtin_offsetof(struct user, regs.orig_eax));
#elif defined(__x86_64__)
      no = ptrace(PTRACE_PEEKUSER, pid,
                  __builtin_offsetof(struct user, regs.orig_rax));
#elif defined(__arm__)
      no = ptrace(PTRACE_PEEKUSER, pid,
                  __builtin_offsetof(struct user, regs.uregs[7]));
#else
#error "unknown architecture"
#endif

      st.no = no;
      if (st.no == SYS_openat) {
        HOOK_SYS_openat(binds, pid, {});
      }
      break;
    }

    case SYSCALL_EXITED: {
      //
      // getting the syscall return value
      //
      int res;

#if defined(__i386__)
      res = ptrace(PTRACE_PEEKUSER, pid,
                   __builtin_offsetof(struct user, regs.eax));
#elif defined(__x86_64__)
      res = ptrace(PTRACE_PEEKUSER, pid,
                   __builtin_offsetof(struct user, regs.rax));
#elif defined(__arm__)
      res = ptrace(PTRACE_PEEKUSER, pid,
                   __builtin_offsetof(struct user, regs.uregs[0]));
#else
#error "unknown architecture"
#endif

      fprintf(stderr, "parent: [%d] SYSCALL [%d] = %d\n", pid,
              st.no, res);
      break;
    }

    default:
      __builtin_unreachable();
    }

    toggle_syscall_state(st);
  }

  return 0;
}
