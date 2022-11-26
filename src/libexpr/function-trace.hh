#pragma once



#include "nixexpr.hh"  // for Pos

namespace nix {

struct FunctionCallTrace
{
    const Pos pos;
    FunctionCallTrace(const Pos & pos);
    ~FunctionCallTrace();
};
}
