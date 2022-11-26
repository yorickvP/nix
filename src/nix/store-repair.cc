#include <string>        // for string, basic_string, allocator
#include <vector>        // for vector

#include "command.hh"    // for registerCommand2, StorePathsCommand
#include "store-api.hh"  // for Store
#include "path.hh"       // for StorePath
#include "ref.hh"        // for ref, nix

using namespace nix;

struct CmdStoreRepair : StorePathsCommand
{
    std::string description() override
    {
        return "repair store paths";
    }

    std::string doc() override
    {
        return
          #include "store-repair.md"
          ;
    }

    void run(ref<Store> store, std::vector<StorePath> && storePaths) override
    {
        for (auto & path : storePaths)
            store->repairPath(path);
    }
};

static auto rStoreRepair = registerCommand2<CmdStoreRepair>({"store", "repair"});
