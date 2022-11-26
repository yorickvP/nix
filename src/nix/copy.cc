#include <set>              // for set
#include <string>           // for allocator, string
#include <vector>           // for vector

#include "command.hh"       // for BuiltPathsCommand, registerCommand, CopyC...
#include "store-api.hh"     // for copyPaths, CheckSigsFlag, NoCheckSigs
#include "args.hh"          // for Command::Category
#include "derived-path.hh"  // for BuiltPaths, BuiltPath
#include "installables.hh"  // for Realise, Realise::Outputs
#include "realisation.hh"   // for RealisedPath::Set, RealisedPath
#include "ref.hh"           // for ref, nix
#include "repair-flag.hh"   // for NoRepair

using namespace nix;

struct CmdCopy : virtual CopyCommand, virtual BuiltPathsCommand
{
    CheckSigsFlag checkSigs = CheckSigs;

    SubstituteFlag substitute = NoSubstitute;

    using BuiltPathsCommand::run;

    CmdCopy()
        : BuiltPathsCommand(true)
    {
        addFlag({
            .longName = "no-check-sigs",
            .description = "Do not require that paths are signed by trusted keys.",
            .handler = {&checkSigs, NoCheckSigs},
        });

        addFlag({
            .longName = "substitute-on-destination",
            .shortName = 's',
            .description = "Whether to try substitutes on the destination store (only supported by SSH stores).",
            .handler = {&substitute, Substitute},
        });

        realiseMode = Realise::Outputs;
    }

    std::string description() override
    {
        return "copy paths between Nix stores";
    }

    std::string doc() override
    {
        return
          #include "copy.md"
          ;
    }

    Category category() override { return catSecondary; }

    void run(ref<Store> srcStore, BuiltPaths && paths) override
    {
        auto dstStore = getDstStore();

        RealisedPath::Set stuffToCopy;

        for (auto & builtPath : paths) {
            auto theseRealisations = builtPath.toRealisedPaths(*srcStore);
            stuffToCopy.insert(theseRealisations.begin(), theseRealisations.end());
        }

        copyPaths(
            *srcStore, *dstStore, stuffToCopy, NoRepair, checkSigs, substitute);
    }
};

static auto rCmdCopy = registerCommand<CmdCopy>("copy");
