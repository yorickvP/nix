#include <stddef.h>           // for size_t
#include <boost/format.hpp>   // for basic_altstringbuf<>::int_type, basic_a...
#include <list>               // for operator!=, _List_iterator, list, _List...
#include <memory>             // for allocator, __shared_ptr_access, shared_ptr
#include <optional>           // for optional
#include <string>             // for operator+, basic_string, char_traits
#include <string_view>        // for string_view
#include <tuple>              // for tuple_element<>::type
#include <utility>            // for move, pair

#include "command.hh"         // for completeFlakeRef, registerCommand, Sour...
#include "store-api.hh"       // for Store
#include "local-fs-store.hh"  // for LocalFSStore
#include "args.hh"            // for completePath, Command::Category
#include "attr-set.hh"        // for Attr, Bindings
#include "config.hh"          // for Setting
#include "derived-path.hh"    // for DerivedPath, DerivedPath::Built
#include "error.hh"           // for Error
#include "eval-inline.hh"     // for EvalState::allocValue
#include "eval.hh"            // for EvalState
#include "flake/flake.hh"     // for LockFlags
#include "flake/flakeref.hh"  // for parseFlakeRefWithFragmentAndOutputsSpec
#include "flake/lockfile.hh"  // for InputPath
#include "fmt.hh"             // for fmt
#include "globals.hh"         // for Settings, settings
#include "installables.hh"    // for InstallableFlake, Installable
#include "nixexpr.hh"         // for noPos
#include "path.hh"            // for StorePath
#include "ref.hh"             // for ref, nix
#include "types.hh"           // for Path, Strings, PathSet
#include "util.hh"            // for absPath
#include "value.hh"           // for Value, Value::(anonymous)

using namespace nix;

struct CmdBundle : InstallableCommand
{
    std::string bundler = "github:NixOS/bundlers";
    std::optional<Path> outLink;

    CmdBundle()
    {
        addFlag({
            .longName = "bundler",
            .description = fmt("Use a custom bundler instead of the default (`%s`).", bundler),
            .labels = {"flake-url"},
            .handler = {&bundler},
            .completer = {[&](size_t, std::string_view prefix) {
                completeFlakeRef(getStore(), prefix);
            }}
        });

        addFlag({
            .longName = "out-link",
            .shortName = 'o',
            .description = "Override the name of the symlink to the build result. It defaults to the base name of the app.",
            .labels = {"path"},
            .handler = {&outLink},
            .completer = completePath
        });

    }

    std::string description() override
    {
        return "bundle an application so that it works outside of the Nix store";
    }

    std::string doc() override
    {
        return
          #include "bundle.md"

          ;
    }

    Category category() override { return catSecondary; }

    // FIXME: cut&paste from CmdRun.
    Strings getDefaultFlakeAttrPaths() override
    {
        Strings res{
            "apps." + settings.thisSystem.get() + ".default",
            "defaultApp." + settings.thisSystem.get()
        };
        for (auto & s : SourceExprCommand::getDefaultFlakeAttrPaths())
            res.push_back(s);
        return res;
    }

    Strings getDefaultFlakeAttrPathPrefixes() override
    {
        Strings res{"apps." + settings.thisSystem.get() + "."};
        for (auto & s : SourceExprCommand::getDefaultFlakeAttrPathPrefixes())
            res.push_back(s);
        return res;
    }

    void run(ref<Store> store) override
    {
        auto evalState = getEvalState();

        auto val = installable->toValue(*evalState).first;

        auto [bundlerFlakeRef, bundlerName, outputsSpec] = parseFlakeRefWithFragmentAndOutputsSpec(bundler, absPath("."));
        const flake::LockFlags lockFlags{ .writeLockFile = false };
        InstallableFlake bundler{this,
            evalState, std::move(bundlerFlakeRef), bundlerName, outputsSpec,
            {"bundlers." + settings.thisSystem.get() + ".default",
             "defaultBundler." + settings.thisSystem.get()
            },
            {"bundlers." + settings.thisSystem.get() + "."},
            lockFlags
        };

        auto vRes = evalState->allocValue();
        evalState->callFunction(*bundler.toValue(*evalState).first, *val, *vRes, noPos);

        if (!evalState->isDerivation(*vRes))
            throw Error("the bundler '%s' does not produce a derivation", bundler.what());

        auto attr1 = vRes->attrs->get(evalState->sDrvPath);
        if (!attr1)
            throw Error("the bundler '%s' does not produce a derivation", bundler.what());

        PathSet context2;
        auto drvPath = evalState->coerceToStorePath(attr1->pos, *attr1->value, context2);

        auto attr2 = vRes->attrs->get(evalState->sOutPath);
        if (!attr2)
            throw Error("the bundler '%s' does not produce a derivation", bundler.what());

        auto outPath = evalState->coerceToStorePath(attr2->pos, *attr2->value, context2);

        store->buildPaths({ DerivedPath::Built { drvPath } });

        auto outPathS = store->printStorePath(outPath);

        if (!outLink) {
            auto * attr = vRes->attrs->get(evalState->sName);
            if (!attr)
                throw Error("attribute 'name' missing");
            outLink = evalState->forceStringNoCtx(*attr->value, attr->pos);
        }

        // TODO: will crash if not a localFSStore?
        store.dynamic_pointer_cast<LocalFSStore>()->addPermRoot(outPath, absPath(*outLink));
    }
};

static auto r2 = registerCommand<CmdBundle>("bundle");
