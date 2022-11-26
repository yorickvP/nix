#pragma once

#include "path.hh"  // for StorePathSet

namespace nix {
class Store;
template <typename T> class ref;

void printDotGraph(ref<Store> store, StorePathSet && roots);

}
