#include <chrono>      // for nanoseconds, duration_cast, duration, high_res...
#include <memory>      // for allocator

#include "function-trace.hh"
#include "logging.hh"  // for Logger, printMsg
#include "error.hh"    // for lvlInfo

namespace nix {

FunctionCallTrace::FunctionCallTrace(const Pos & pos) : pos(pos) {
    auto duration = std::chrono::high_resolution_clock::now().time_since_epoch();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
    printMsg(lvlInfo, "function-trace entered %1% at %2%", pos, ns.count());
}

FunctionCallTrace::~FunctionCallTrace() {
    auto duration = std::chrono::high_resolution_clock::now().time_since_epoch();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
    printMsg(lvlInfo, "function-trace exited %1% at %2%", pos, ns.count());
}

}
