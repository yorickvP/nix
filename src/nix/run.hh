#pragma once

#include <string>    // for string

#include "types.hh"  // for Strings

namespace nix {
class Store;
template <typename T> class ref;

void runProgramInStore(ref<Store> store,
    const std::string & program,
    const Strings & args);

}
