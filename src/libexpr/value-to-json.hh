#pragma once



#include <iosfwd>    // for ostream

#include "types.hh"  // for PathSet

namespace nix {

class JSONPlaceholder;
class EvalState;
class PosIdx;
struct Value;

void printValueAsJSON(EvalState & state, bool strict,
    Value & v, const PosIdx pos, JSONPlaceholder & out, PathSet & context, bool copyToStore = true);

void printValueAsJSON(EvalState & state, bool strict,
    Value & v, const PosIdx pos, std::ostream & str, PathSet & context, bool copyToStore = true);

}
