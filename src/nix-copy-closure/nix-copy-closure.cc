#include <boost/format.hpp>  // for basic_format, basic_altstringbuf<>::int_...
#include <list>              // for _List_iterator
#include <map>               // for operator!=, _Rb_tree_const_iterator, _Rb...
#include <string>            // for allocator, operator==, basic_string, cha...

#include "shared.hh"         // for parseCmdLine, printVersion, showManPage
#include "store-api.hh"      // for openStore, copyClosure, NoCheckSigs, NoS...
#include "legacy.hh"         // for MainFunction, RegisterLegacyCommand
#include "error.hh"          // for UsageError, lvlError
#include "fmt.hh"            // for format
#include "logging.hh"        // for Logger, printMsg
#include "realisation.hh"    // for RealisedPath::Set, RealisedPath
#include "ref.hh"            // for ref, nix
#include "repair-flag.hh"    // for NoRepair
#include "types.hh"          // for PathSet, Strings

using namespace nix;

static int main_nix_copy_closure(int argc, char ** argv)
{
    {
        auto gzip = false;
        auto toMode = true;
        auto includeOutputs = false;
        auto dryRun = false;
        auto useSubstitutes = NoSubstitute;
        std::string sshHost;
        PathSet storePaths;

        parseCmdLine(argc, argv, [&](Strings::iterator & arg, const Strings::iterator & end) {
            if (*arg == "--help")
                showManPage("nix-copy-closure");
            else if (*arg == "--version")
                printVersion("nix-copy-closure");
            else if (*arg == "--gzip" || *arg == "--bzip2" || *arg == "--xz") {
                if (*arg != "--gzip")
                    printMsg(lvlError, format("Warning: '%1%' is not implemented, falling back to gzip") % *arg);
                gzip = true;
            } else if (*arg == "--from")
                toMode = false;
            else if (*arg == "--to")
                toMode = true;
            else if (*arg == "--include-outputs")
                includeOutputs = true;
            else if (*arg == "--show-progress")
                printMsg(lvlError, "Warning: '--show-progress' is not implemented");
            else if (*arg == "--dry-run")
                dryRun = true;
            else if (*arg == "--use-substitutes" || *arg == "-s")
                useSubstitutes = Substitute;
            else if (sshHost.empty())
                sshHost = *arg;
            else
                storePaths.insert(*arg);
            return true;
        });

        if (sshHost.empty())
            throw UsageError("no host name specified");

        auto remoteUri = "ssh://" + sshHost + (gzip ? "?compress=true" : "");
        auto to = toMode ? openStore(remoteUri) : openStore();
        auto from = toMode ? openStore() : openStore(remoteUri);

        RealisedPath::Set storePaths2;
        for (auto & path : storePaths)
            storePaths2.insert(from->followLinksToStorePath(path));

        copyClosure(*from, *to, storePaths2, NoRepair, NoCheckSigs, useSubstitutes);

        return 0;
    }
}

static RegisterLegacyCommand r_nix_copy_closure("nix-copy-closure", main_nix_copy_closure);
