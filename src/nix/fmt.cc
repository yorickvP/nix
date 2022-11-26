#include <memory>           // for allocator, __shared_ptr_access, shared_ptr
#include <string>           // for string, operator+, basic_string
#include <vector>           // for vector

#include "command.hh"       // for registerCommand, SourceExprCommand, catSe...
#include "run.hh"           // for runProgramInStore
#include "args.hh"          // for Command::Category
#include "config.hh"        // for Setting
#include "globals.hh"       // for Settings, settings
#include "installables.hh"  // for App, Installable, UnresolvedApp
#include "ref.hh"           // for ref, nix
#include "types.hh"         // for Strings

namespace nix {
class Store;
}  // namespace nix

using namespace nix;

struct CmdFmt : SourceExprCommand {
    std::vector<std::string> args;

    CmdFmt() { expectArgs({.label = "args", .handler = {&args}}); }

    std::string description() override {
        return "reformat your code in the standard style";
    }

    std::string doc() override {
        return
          #include "fmt.md"
          ;
    }

    Category category() override { return catSecondary; }

    Strings getDefaultFlakeAttrPaths() override {
        return Strings{"formatter." + settings.thisSystem.get()};
    }

    Strings getDefaultFlakeAttrPathPrefixes() override { return Strings{}; }

    void run(ref<Store> store) override
    {
        auto evalState = getEvalState();
        auto evalStore = getEvalStore();

        auto installable = parseInstallable(store, ".");
        auto app = installable->toApp(*evalState).resolve(evalStore, store);

        Strings programArgs{app.program};

        // Propagate arguments from the CLI
        if (args.empty()) {
            // Format the current flake out of the box
            programArgs.push_back(".");
        } else {
            // User wants more power, let them decide which paths to include/exclude
            for (auto &i : args) {
                programArgs.push_back(i);
            }
        }

        runProgramInStore(store, app.program, programArgs);
    };
};

static auto r2 = registerCommand<CmdFmt>("fmt");
