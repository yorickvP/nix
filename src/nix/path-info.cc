#include <stddef.h>            // for size_t
#include <stdint.h>            // for uint64_t
#include <boost/format.hpp>    // for basic_altstringbuf<>::int_type, basic_...
#include <array>               // for array
#include <iostream>            // for cout, ostream, operator<<, endl
#include <list>                // for operator!=, list
#include <map>                 // for operator!=, _Rb_tree_const_iterator
#include <optional>            // for optional
#include <string>              // for allocator, operator<<, string, operator+
#include <utility>             // for pair
#include <vector>              // for vector, max

#include "command.hh"          // for registerCommand, StorePathsCommand
#include "store-api.hh"        // for Store, AllowInvalid
#include "json.hh"             // for JSONPlaceholder
#include "common-args.hh"      // for MixJSON
#include "args.hh"             // for Command::Category
#include "content-address.hh"  // for renderContentAddress
#include "fmt.hh"              // for fmt
#include "hash.hh"             // for SRI
#include "path-info.hh"        // for ValidPathInfo
#include "path.hh"             // for StorePaths, StorePathSet
#include "ref.hh"              // for ref, nix
#include "types.hh"            // for Strings, StringSet
#include "util.hh"             // for concatStringsSep

using namespace nix;

struct CmdPathInfo : StorePathsCommand, MixJSON
{
    bool showSize = false;
    bool showClosureSize = false;
    bool humanReadable = false;
    bool showSigs = false;

    CmdPathInfo()
    {
        addFlag({
            .longName = "size",
            .shortName = 's',
            .description = "Print the size of the NAR serialisation of each path.",
            .handler = {&showSize, true},
        });

        addFlag({
            .longName = "closure-size",
            .shortName = 'S',
            .description = "Print the sum of the sizes of the NAR serialisations of the closure of each path.",
            .handler = {&showClosureSize, true},
        });

        addFlag({
            .longName = "human-readable",
            .shortName = 'h',
            .description = "With `-s` and `-S`, print sizes in a human-friendly format such as `5.67G`.",
            .handler = {&humanReadable, true},
        });

        addFlag({
            .longName = "sigs",
            .description = "Show signatures.",
            .handler = {&showSigs, true},
        });
    }

    std::string description() override
    {
        return "query information about store paths";
    }

    std::string doc() override
    {
        return
          #include "path-info.md"

          ;
    }

    Category category() override { return catSecondary; }

    void printSize(uint64_t value)
    {
        if (!humanReadable) {
            std::cout << fmt("\t%11d", value);
            return;
        }

        static const std::array<char, 9> idents{{
            ' ', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'
        }};
        size_t power = 0;
        double res = value;
        while (res > 1024 && power < idents.size()) {
            ++power;
            res /= 1024;
        }
        std::cout << fmt("\t%6.1f%c", res, idents.at(power));
    }

    void run(ref<Store> store, StorePaths && storePaths) override
    {
        size_t pathLen = 0;
        for (auto & storePath : storePaths)
            pathLen = std::max(pathLen, store->printStorePath(storePath).size());

        if (json) {
            JSONPlaceholder jsonRoot(std::cout);
            store->pathInfoToJSON(jsonRoot,
                // FIXME: preserve order?
                StorePathSet(storePaths.begin(), storePaths.end()),
                true, showClosureSize, SRI, AllowInvalid);
        }

        else {

            for (auto & storePath : storePaths) {
                auto info = store->queryPathInfo(storePath);
                auto storePathS = store->printStorePath(info->path);

                std::cout << storePathS;

                if (showSize || showClosureSize || showSigs)
                    std::cout << std::string(std::max(0, (int) pathLen - (int) storePathS.size()), ' ');

                if (showSize)
                    printSize(info->narSize);

                if (showClosureSize)
                    printSize(store->getClosureSize(info->path).first);

                if (showSigs) {
                    std::cout << '\t';
                    Strings ss;
                    if (info->ultimate) ss.push_back("ultimate");
                    if (info->ca) ss.push_back("ca:" + renderContentAddress(*info->ca));
                    for (auto & sig : info->sigs) ss.push_back(sig);
                    std::cout << concatStringsSep(" ", ss);
                }

                std::cout << std::endl;
            }

        }
    }
};

static auto rCmdPathInfo = registerCommand<CmdPathInfo>("path-info");
