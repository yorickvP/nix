#pragma once

#include <map>             // for map
#include <string>          // for string, allocator
#include <string_view>     // for string_view
#include <utility>         // for pair

#include "fs-accessor.hh"  // for FSAccessor, FSAccessor::Stat
#include "ref.hh"          // for ref
#include "types.hh"        // for Path, StringSet

namespace nix {
class Store;

class RemoteFSAccessor : public FSAccessor
{
    ref<Store> store;

    std::map<std::string, ref<FSAccessor>> nars;

    Path cacheDir;

    std::pair<ref<FSAccessor>, Path> fetch(const Path & path_, bool requireValidPath = true);

    friend class BinaryCacheStore;

    Path makeCacheFile(std::string_view hashPart, const std::string & ext);

    ref<FSAccessor> addToCache(std::string_view hashPart, std::string && nar);

public:

    RemoteFSAccessor(ref<Store> store,
        const /* FIXME: use std::optional */ Path & cacheDir = "");

    Stat stat(const Path & path) override;

    StringSet readDirectory(const Path & path) override;

    std::string readFile(const Path & path, bool requireValidPath = true) override;

    std::string readLink(const Path & path) override;
};

}
