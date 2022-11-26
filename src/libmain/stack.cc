#include <unistd.h>          // for _exit, write
#include <signal.h>          // for sigaction, sigfillset, stack_t, siginfo_t
#include <ucontext.h>        // for REG_RSP, ucontext_t, greg_t, mcontext_t
#include <boost/format.hpp>  // for basic_altstringbuf<>::int_type, basic_al...
#include <cstring>           // for strlen
#include <cstddef>           // for ptrdiff_t
#include <cstdlib>           // for abort
#include <functional>        // for function
#include <memory>            // for allocator, make_unique, unique_ptr
#include <vector>            // for vector

#include "error.hh"          // for SysError, Error
#include "shared.hh"         // for defaultStackOverflowHandler, detectStack...

namespace nix {


static void sigsegvHandler(int signo, siginfo_t * info, void * ctx)
{
    /* Detect stack overflows by comparing the faulting address with
       the stack pointer.  Unfortunately, getting the stack pointer is
       not portable. */
    bool haveSP = true;
    char * sp = 0;
#if defined(__x86_64__) && defined(REG_RSP)
    sp = (char *) ((ucontext_t *) ctx)->uc_mcontext.gregs[REG_RSP];
#elif defined(REG_ESP)
    sp = (char *) ((ucontext_t *) ctx)->uc_mcontext.gregs[REG_ESP];
#else
    haveSP = false;
#endif

    if (haveSP) {
        ptrdiff_t diff = (char *) info->si_addr - sp;
        if (diff < 0) diff = -diff;
        if (diff < 4096) {
            nix::stackOverflowHandler(info, ctx);
        }
    }

    /* Restore default behaviour (i.e. segfault and dump core). */
    struct sigaction act;
    sigfillset(&act.sa_mask);
    act.sa_handler = SIG_DFL;
    act.sa_flags = 0;
    if (sigaction(SIGSEGV, &act, 0)) abort();
}


void detectStackOverflow()
{
#if defined(SA_SIGINFO) && defined (SA_ONSTACK)
    /* Install a SIGSEGV handler to detect stack overflows.  This
       requires an alternative stack, otherwise the signal cannot be
       delivered when we're out of stack space. */
    stack_t stack;
    stack.ss_size = 4096 * 4 + MINSIGSTKSZ;
    static auto stackBuf = std::make_unique<std::vector<char>>(stack.ss_size);
    stack.ss_sp = stackBuf->data();
    if (!stack.ss_sp) throw Error("cannot allocate alternative stack");
    stack.ss_flags = 0;
    if (sigaltstack(&stack, 0) == -1) throw SysError("cannot set alternative stack");

    struct sigaction act;
    sigfillset(&act.sa_mask);
    act.sa_sigaction = sigsegvHandler;
    act.sa_flags = SA_SIGINFO | SA_ONSTACK;
    if (sigaction(SIGSEGV, &act, 0))
        throw SysError("resetting SIGSEGV");
#endif
}

std::function<void(siginfo_t * info, void * ctx)> stackOverflowHandler(defaultStackOverflowHandler);

void defaultStackOverflowHandler(siginfo_t * info, void * ctx) {
    char msg[] = "error: stack overflow (possible infinite recursion)\n";
    [[gnu::unused]] auto res = write(2, msg, strlen(msg));
    _exit(1); // maybe abort instead?
}

}
