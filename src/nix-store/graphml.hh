#pragma once

#include "path.hh"  // for StorePathSet

namespace nix {
class Store;
template <typename T> class ref;

void printGraphML(ref<Store> store, StorePathSet && roots);

}
