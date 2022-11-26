#pragma once

#include <map>                   // for map
#include <memory>                // for shared_ptr
#include <utility>               // for pair
#include <vector>                // for max, vector

#include "types.hh"              // for Path
#include "fetchers.hh"           // for Input
#include "libfetchers/attrs.hh"  // for Attrs

namespace nix {
class Store;
template <typename T> class ref;
}  // namespace nix

namespace nix::fetchers {

struct Registry
{
    enum RegistryType {
        Flag = 0,
        User = 1,
        System = 2,
        Global = 3,
        Custom = 4,
    };

    RegistryType type;

    struct Entry
    {
        Input from, to;
        Attrs extraAttrs;
        bool exact = false;
    };

    std::vector<Entry> entries;

    Registry(RegistryType type)
        : type(type)
    { }

    static std::shared_ptr<Registry> read(
        const Path & path, RegistryType type);

    void write(const Path & path);

    void add(
        const Input & from,
        const Input & to,
        const Attrs & extraAttrs);

    void remove(const Input & input);
};

typedef std::vector<std::shared_ptr<Registry>> Registries;

std::shared_ptr<Registry> getUserRegistry();

std::shared_ptr<Registry> getCustomRegistry(const Path & p);

Path getUserRegistryPath();

Registries getRegistries(ref<Store> store);

void overrideRegistry(
    const Input & from,
    const Input & to,
    const Attrs & extraAttrs);

std::pair<Input, Attrs> lookupInRegistries(
    ref<Store> store,
    const Input & input);

}
