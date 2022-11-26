#include <string>        // for string, basic_string, allocator

#include "command.hh"    // for registerCommand2, StoreCommand
#include "store-api.hh"  // for Store
#include "ref.hh"        // for ref, nix

using namespace nix;

struct CmdOptimiseStore : StoreCommand
{
    std::string description() override
    {
        return "replace identical files in the store by hard links";
    }

    std::string doc() override
    {
        return
          #include "optimise-store.md"
          ;
    }

    void run(ref<Store> store) override
    {
        store->optimiseStore();
    }
};

static auto rCmdOptimiseStore = registerCommand2<CmdOptimiseStore>({"store", "optimise"});
