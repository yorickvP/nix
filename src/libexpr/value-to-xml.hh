#pragma once



#include <iosfwd>    // for ostream

#include "types.hh"  // for PathSet

namespace nix {
class EvalState;
class PosIdx;
struct Value;

void printValueAsXML(EvalState & state, bool strict, bool location,
    Value & v, std::ostream & out, PathSet & context, const PosIdx pos);

}
