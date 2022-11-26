#pragma once

#include <stdint.h>     // for uint32_t
#include <string>       // for string, basic_string
#include <string_view>  // for string_view
#include <utility>      // for pair
#include <vector>       // for vector

#include "error.hh"     // for Error, MakeError

namespace nix {
class Bindings;
class EvalState;
class PosIdx;
class Suggestions;
class Symbol;
struct Value;

MakeError(AttrPathNotFound, Error);
MakeError(NoPositionInfo, Error);

std::pair<Value *, PosIdx> findAlongAttrPath(
    EvalState & state,
    const std::string & attrPath,
    Bindings & autoArgs,
    Value & vIn);

/* Heuristic to find the filename and lineno or a nix value. */
std::pair<std::string, uint32_t> findPackageFilename(EvalState & state, Value & v, std::string what);

std::vector<Symbol> parseAttrPath(EvalState & state, std::string_view s);

}
