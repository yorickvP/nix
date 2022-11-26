#pragma once

#include <map>          // for map
#include <optional>     // for optional
#include <string>       // for string, basic_string
#include <string_view>  // for string_view

#include "args.hh"      // for Args
#include "types.hh"     // for Path, Strings

namespace nix {

class EvalState;
class Bindings;

struct MixEvalArgs : virtual Args
{
    static constexpr auto category = "Common evaluation options";

    MixEvalArgs();

    Bindings * getAutoArgs(EvalState & state);

    Strings searchPath;

    std::optional<std::string> evalStoreUrl;

private:
    std::map<std::string, std::string> autoArgs;
};

Path lookupFileArg(EvalState & state, std::string_view s);

}
