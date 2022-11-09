#pragma once

#include <cassert>

#include "value.hh"
#include "nixexpr.hh"

#if HAVE_BOEHMGC
#include <gc/gc_allocator.h>
#endif

namespace nix {

void decompileExpr(Expr* e, const SymbolTable& st, std::ostream& str);
Expr* compileExpr(Expr* e);

}

