#include <boost/lexical_cast.hpp>  // for bad_lexical_cast
#include <cstdint>                 // for uint64_t
#include <string>                  // for string, basic_string, allocator

#include "command.hh"              // for registerCommand2, StoreCommand
#include "common-args.hh"          // for MixDryRun
#include "shared.hh"               // for PrintFreed
#include "store-cast.hh"           // for require
#include "gc-store.hh"             // for GCOptions, GcStore, GCOptions::gcD...
#include "ref.hh"                  // for ref, nix

namespace nix {
class Store;
}  // namespace nix

using namespace nix;

struct CmdStoreGC : StoreCommand, MixDryRun
{
    GCOptions options;

    CmdStoreGC()
    {
        addFlag({
            .longName = "max",
            .description = "Stop after freeing *n* bytes of disk space.",
            .labels = {"n"},
            .handler = {&options.maxFreed}
        });
    }

    std::string description() override
    {
        return "perform garbage collection on a Nix store";
    }

    std::string doc() override
    {
        return
          #include "store-gc.md"

          ;
    }

    void run(ref<Store> store) override
    {
        auto & gcStore = require<GcStore>(*store);

        options.action = dryRun ? GCOptions::gcReturnDead : GCOptions::gcDeleteDead;
        GCResults results;
        PrintFreed freed(options.action == GCOptions::gcDeleteDead, results);
        gcStore.collectGarbage(options, results);
    }
};

static auto rCmdStoreGC = registerCommand2<CmdStoreGC>({"store", "gc"});
