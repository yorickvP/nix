#pragma once

#include <string>       // for string
#include <string_view>  // for string_view

#include "error.hh"     // for MakeError
#include "nixexpr.hh"   // for EvalError

namespace nix {
class EvalState;
struct Value;

MakeError(JSONParseError, EvalError);

void parseJSON(EvalState & state, const std::string_view & s, Value & v);

}
