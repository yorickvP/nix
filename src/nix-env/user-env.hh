#pragma once

#include <string>       // for string

#include "get-drvs.hh"  // for DrvInfos
#include "types.hh"     // for Path

namespace nix {
class EvalState;

DrvInfos queryInstalled(EvalState & state, const Path & userEnv);

bool createUserEnv(EvalState & state, DrvInfos & elems,
    const Path & profile, bool keepDerivations,
    const std::string & lockToken);

}
