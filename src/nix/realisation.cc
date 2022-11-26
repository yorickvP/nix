#include <nlohmann/json.hpp>         // for basic_json, basic_json<>::object_t
#include <iostream>                  // for cout, ostream, operator<<, basic...
#include <optional>                  // for optional
#include <set>                       // for operator!=, _Rb_tree_const_iterator
#include <string>                    // for string, basic_string, operator<<
#include <type_traits>               // for remove_reference<>::type
#include <utility>                   // for pair
#include <variant>                   // for get_if
#include <vector>                    // for vector

#include "command.hh"                // for registerCommand, registerCommand2
#include "common-args.hh"            // for MixJSON
#include "args.hh"                   // for Command, Command::Category, Mult...
#include "derived-path.hh"           // for BuiltPaths, BuiltPath
#include "error.hh"                  // for UsageError
#include "experimental-features.hh"  // for Xp
#include "globals.hh"                // for Settings, settings
#include "realisation.hh"            // for RealisedPath::Set, RealisedPath
#include "ref.hh"                    // for ref, nix
#include "store-api.hh"              // for Store

using namespace nix;

struct CmdRealisation : virtual NixMultiCommand
{
    CmdRealisation() : MultiCommand(RegisterCommand::getCommandsFor({"realisation"}))
    { }

    std::string description() override
    {
        return "manipulate a Nix realisation";
    }

    Category category() override { return catUtility; }

    void run() override
    {
        if (!command)
            throw UsageError("'nix realisation' requires a sub-command.");
        command->second->prepare();
        command->second->run();
    }
};

static auto rCmdRealisation = registerCommand<CmdRealisation>("realisation");

struct CmdRealisationInfo : BuiltPathsCommand, MixJSON
{
    std::string description() override
    {
        return "query information about one or several realisations";
    }

    std::string doc() override
    {
        return
            #include "realisation/info.md"

            ;
    }

    Category category() override { return catSecondary; }

    void run(ref<Store> store, BuiltPaths && paths) override
    {
        settings.requireExperimentalFeature(Xp::CaDerivations);
        RealisedPath::Set realisations;

        for (auto & builtPath : paths) {
            auto theseRealisations = builtPath.toRealisedPaths(*store);
            realisations.insert(theseRealisations.begin(), theseRealisations.end());
        }

        if (json) {
            nlohmann::json res = nlohmann::json::array();
            for (auto & path : realisations) {
                nlohmann::json currentPath;
                if (auto realisation = std::get_if<Realisation>(&path.raw))
                    currentPath = realisation->toJSON();
                else
                    currentPath["opaquePath"] = store->printStorePath(path.path());

                res.push_back(currentPath);
            }
            std::cout << res.dump();
        }
        else {
            for (auto & path : realisations) {
                if (auto realisation = std::get_if<Realisation>(&path.raw)) {
                    std::cout <<
                        realisation->id.to_string() << " " <<
                        store->printStorePath(realisation->outPath);
                } else
                    std::cout << store->printStorePath(path.path());

                std::cout << std::endl;
            }
        }
    }
};

static auto rCmdRealisationInfo = registerCommand2<CmdRealisationInfo>({"realisation", "info"});
