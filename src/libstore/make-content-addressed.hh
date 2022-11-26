#pragma once

#include <map>      // for map

#include "path.hh"  // for StorePath (ptr only), StorePathSet

namespace nix {
class Store;

std::map<StorePath, StorePath> makeContentAddressed(
    Store & srcStore,
    Store & dstStore,
    const StorePathSet & storePaths);

}
