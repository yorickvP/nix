#include <string>         // for string, basic_string, allocator
#include <vector>         // for vector

#include "command.hh"     // for registerCommand2, StorePathsCommand
#include "shared.hh"      // for PrintFreed
#include "store-cast.hh"  // for require
#include "gc-store.hh"    // for GCOptions, GcStore, GCOptions::gcDeleteSpec...
#include "path.hh"        // for StorePath, StorePathSet
#include "ref.hh"         // for ref, nix

namespace nix {
class Store;
}  // namespace nix

using namespace nix;

struct CmdStoreDelete : StorePathsCommand
{
    GCOptions options { .action = GCOptions::gcDeleteSpecific };

    CmdStoreDelete()
    {
        addFlag({
            .longName = "ignore-liveness",
            .description = "Do not check whether the paths are reachable from a root.",
            .handler = {&options.ignoreLiveness, true}
        });
    }

    std::string description() override
    {
        return "delete paths from the Nix store";
    }

    std::string doc() override
    {
        return
          #include "store-delete.md"
          ;
    }

    void run(ref<Store> store, std::vector<StorePath> && storePaths) override
    {
        auto & gcStore = require<GcStore>(*store);

        for (auto & path : storePaths)
            options.pathsToDelete.insert(path);

        GCResults results;
        PrintFreed freed(true, results);
        gcStore.collectGarbage(options, results);
    }
};

static auto rCmdStoreDelete = registerCommand2<CmdStoreDelete>({"store", "delete"});
