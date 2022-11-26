#include <stddef.h>              // for size_t
#include <boost/format.hpp>      // for format
#include <list>                  // for operator!=, _List_iterator, _List_it...
#include <map>                   // for operator!=, _Rb_tree_const_iterator
#include <memory>                // for shared_ptr
#include <optional>              // for optional, nullopt
#include <sstream>               // for ostringstream, basic_ostringstream<>...
#include <utility>               // for pair
#include <vector>                // for max, vector

#include "user-env.hh"
#include "util.hh"               // for pathExists, enumerate, iterable_wrapper
#include "store-api.hh"          // for Store, bmNormal, bmRepair
#include "path-with-outputs.hh"  // for StorePathWithOutputs, toDerivedPaths
#include "eval.hh"               // for EvalState
#include "eval-inline.hh"        // for EvalState::allocValue, EvalState::fo...
#include "profiles.hh"           // for createGeneration, lockProfile, optim...
#include "pathlocks.hh"          // for PathLocks
#include "attr-set.hh"           // for BindingsBuilder, Attr, Bindings
#include "error.hh"              // for Error
#include "fmt.hh"                // for format
#include "logging.hh"            // for Logger, debug, printInfo
#include "nixexpr.hh"            // for PosIdx, noPos
#include "path.hh"               // for StorePath, StorePathSet
#include "ref.hh"                // for ref
#include "symbol-table.hh"       // for SymbolTable
#include "value.hh"              // for Value, Value::(anonymous)
#include "local-fs-store.hh"     // for LocalFSStore

// IWYU pragma: no_forward_declare nix::LocalFSStore

namespace nix {

DrvInfos queryInstalled(EvalState & state, const Path & userEnv)
{
    DrvInfos elems;
    if (pathExists(userEnv + "/manifest.json"))
        throw Error("profile '%s' is incompatible with 'nix-env'; please use 'nix profile' instead", userEnv);
    Path manifestFile = userEnv + "/manifest.nix";
    if (pathExists(manifestFile)) {
        Value v;
        state.evalFile(manifestFile, v);
        Bindings & bindings(*state.allocBindings(0));
        getDerivations(state, v, "", bindings, elems, false);
    }
    return elems;
}


bool createUserEnv(EvalState & state, DrvInfos & elems,
    const Path & profile, bool keepDerivations,
    const std::string & lockToken)
{
    /* Build the components in the user environment, if they don't
       exist already. */
    std::vector<StorePathWithOutputs> drvsToBuild;
    for (auto & i : elems)
        if (auto drvPath = i.queryDrvPath())
            drvsToBuild.push_back({*drvPath});

    debug(format("building user environment dependencies"));
    state.store->buildPaths(
        toDerivedPaths(drvsToBuild),
        state.repair ? bmRepair : bmNormal);

    /* Construct the whole top level derivation. */
    StorePathSet references;
    Value manifest;
    state.mkList(manifest, elems.size());
    size_t n = 0;
    for (auto & i : elems) {
        /* Create a pseudo-derivation containing the name, system,
           output paths, and optionally the derivation path, as well
           as the meta attributes. */
        std::optional<StorePath> drvPath = keepDerivations ? i.queryDrvPath() : std::nullopt;
        DrvInfo::Outputs outputs = i.queryOutputs(true, true);
        StringSet metaNames = i.queryMetaNames();

        auto attrs = state.buildBindings(7 + outputs.size());

        attrs.alloc(state.sType).mkString("derivation");
        attrs.alloc(state.sName).mkString(i.queryName());
        auto system = i.querySystem();
        if (!system.empty())
            attrs.alloc(state.sSystem).mkString(system);
        attrs.alloc(state.sOutPath).mkString(state.store->printStorePath(i.queryOutPath()));
        if (drvPath)
            attrs.alloc(state.sDrvPath).mkString(state.store->printStorePath(*drvPath));

        // Copy each output meant for installation.
        auto & vOutputs = attrs.alloc(state.sOutputs);
        state.mkList(vOutputs, outputs.size());
        for (const auto & [m, j] : enumerate(outputs)) {
            (vOutputs.listElems()[m] = state.allocValue())->mkString(j.first);
            auto outputAttrs = state.buildBindings(2);
            outputAttrs.alloc(state.sOutPath).mkString(state.store->printStorePath(*j.second));
            attrs.alloc(j.first).mkAttrs(outputAttrs);

            /* This is only necessary when installing store paths, e.g.,
               `nix-env -i /nix/store/abcd...-foo'. */
            state.store->addTempRoot(*j.second);
            state.store->ensurePath(*j.second);

            references.insert(*j.second);
        }

        // Copy the meta attributes.
        auto meta = state.buildBindings(metaNames.size());
        for (auto & j : metaNames) {
            Value * v = i.queryMeta(j);
            if (!v) continue;
            meta.insert(state.symbols.create(j), v);
        }

        attrs.alloc(state.sMeta).mkAttrs(meta);

        (manifest.listElems()[n++] = state.allocValue())->mkAttrs(attrs);

        if (drvPath) references.insert(*drvPath);
    }

    /* Also write a copy of the list of user environment elements to
       the store; we need it for future modifications of the
       environment. */
    std::ostringstream str;
    manifest.print(state.symbols, str, true);
    auto manifestFile = state.store->addTextToStore("env-manifest.nix",
        str.str(), references);

    /* Get the environment builder expression. */
    Value envBuilder;
    state.eval(state.parseExprFromString(
        #include "buildenv.nix.gen.hh"

            , "/"), envBuilder);

    /* Construct a Nix expression that calls the user environment
       builder with the manifest as argument. */
    auto attrs = state.buildBindings(3);
    attrs.alloc("manifest").mkString(
        state.store->printStorePath(manifestFile),
        {state.store->printStorePath(manifestFile)});
    attrs.insert(state.symbols.create("derivations"), &manifest);
    Value args;
    args.mkAttrs(attrs);

    Value topLevel;
    topLevel.mkApp(&envBuilder, &args);

    /* Evaluate it. */
    debug("evaluating user environment builder");
    state.forceValue(topLevel, [&]() { return topLevel.determinePos(noPos); });
    PathSet context;
    Attr & aDrvPath(*topLevel.attrs->find(state.sDrvPath));
    auto topLevelDrv = state.coerceToStorePath(aDrvPath.pos, *aDrvPath.value, context);
    Attr & aOutPath(*topLevel.attrs->find(state.sOutPath));
    auto topLevelOut = state.coerceToStorePath(aOutPath.pos, *aOutPath.value, context);

    /* Realise the resulting store expression. */
    debug("building user environment");
    std::vector<StorePathWithOutputs> topLevelDrvs;
    topLevelDrvs.push_back({topLevelDrv});
    state.store->buildPaths(
        toDerivedPaths(topLevelDrvs),
        state.repair ? bmRepair : bmNormal);

    /* Switch the current user environment to the output path. */
    auto store2 = state.store.dynamic_pointer_cast<LocalFSStore>();

    if (store2) {
        PathLocks lock;
        lockProfile(lock, profile);

        Path lockTokenCur = optimisticLockProfile(profile);
        if (lockToken != lockTokenCur) {
            printInfo("profile '%1%' changed while we were busy; restarting", profile);
            return false;
        }

        debug(format("switching to new user environment"));
        Path generation = createGeneration(ref<LocalFSStore>(store2), profile, topLevelOut);
        switchLink(profile, generation);
    }

    return true;
}


}
