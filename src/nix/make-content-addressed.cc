#include <assert.h>                   // for assert
#include <iostream>                   // for cout
#include <map>                        // for operator!=, map, _Rb_tree_iterator
#include <string>                     // for string, basic_string, allocator
#include <utility>                    // for pair
#include <vector>                     // for vector

#include "command.hh"                 // for registerCommand2, CopyCommand
#include "store-api.hh"               // for openStore, Store
#include "make-content-addressed.hh"  // for makeContentAddressed
#include "common-args.hh"             // for MixJSON
#include "json.hh"                    // for JSONObject
#include "installables.hh"            // for Realise, Realise::Outputs
#include "logging.hh"                 // for Logger, notice
#include "path.hh"                    // for StorePaths, StorePathSet
#include "ref.hh"                     // for ref, nix

using namespace nix;

struct CmdMakeContentAddressed : virtual CopyCommand, virtual StorePathsCommand, MixJSON
{
    CmdMakeContentAddressed()
    {
        realiseMode = Realise::Outputs;
    }

    std::string description() override
    {
        return "rewrite a path or closure to content-addressed form";
    }

    std::string doc() override
    {
        return
          #include "make-content-addressed.md"
          ;
    }

    void run(ref<Store> srcStore, StorePaths && storePaths) override
    {
        auto dstStore = dstUri.empty() ? openStore() : openStore(dstUri);

        auto remappings = makeContentAddressed(*srcStore, *dstStore,
            StorePathSet(storePaths.begin(), storePaths.end()));

        if (json) {
            JSONObject jsonRoot(std::cout);
            JSONObject jsonRewrites(jsonRoot.object("rewrites"));
            for (auto & path : storePaths) {
                auto i = remappings.find(path);
                assert(i != remappings.end());
                jsonRewrites.attr(srcStore->printStorePath(path), srcStore->printStorePath(i->second));
            }
        } else {
            for (auto & path : storePaths) {
                auto i = remappings.find(path);
                assert(i != remappings.end());
                notice("rewrote '%s' to '%s'",
                    srcStore->printStorePath(path),
                    srcStore->printStorePath(i->second));
            }
        }
    }
};

static auto rCmdMakeContentAddressed = registerCommand2<CmdMakeContentAddressed>({"store", "make-content-addressed"});
