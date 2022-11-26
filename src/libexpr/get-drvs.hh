#pragma once

#include <gc/gc_allocator.h>  // for traceable_allocator
#include <string>             // for string, basic_string, operator<
#include <map>                // for map, map<>::value_compare
#include <list>               // for list
#include <optional>           // for optional
#include <utility>            // for move
#include <type_traits>        // for remove_reference<>::type

#include "path.hh"            // for StorePath
#include "types.hh"           // for StringSet
#include "value.hh"           // for Value (ptr only), NixFloat, NixInt


namespace nix {
class Bindings;
class EvalState;
class Store;
template <typename T> class ref;


struct DrvInfo
{
public:
    typedef std::map<std::string, std::optional<StorePath>> Outputs;

private:
    EvalState * state;

    mutable std::string name;
    mutable std::string system;
    mutable std::optional<std::optional<StorePath>> drvPath;
    mutable std::optional<StorePath> outPath;
    mutable std::string outputName;
    Outputs outputs;

    bool failed = false; // set if we get an AssertionError

    Bindings * attrs = nullptr, * meta = nullptr;

    Bindings * getMeta();

    bool checkMeta(Value & v);

public:
    std::string attrPath; /* path towards the derivation */

    DrvInfo(EvalState & state) : state(&state) { };
    DrvInfo(EvalState & state, std::string attrPath, Bindings * attrs);
    DrvInfo(EvalState & state, ref<Store> store, const std::string & drvPathWithOutputs);

    std::string queryName() const;
    std::string querySystem() const;
    std::optional<StorePath> queryDrvPath() const;
    StorePath requireDrvPath() const;
    StorePath queryOutPath() const;
    std::string queryOutputName() const;
    /** Return the unordered map of output names to (optional) output paths.
     * The "outputs to install" are determined by `meta.outputsToInstall`. */
    Outputs queryOutputs(bool withPaths = true, bool onlyOutputsToInstall = false);

    StringSet queryMetaNames();
    Value * queryMeta(const std::string & name);
    std::string queryMetaString(const std::string & name);
    NixInt queryMetaInt(const std::string & name, NixInt def);
    NixFloat queryMetaFloat(const std::string & name, NixFloat def);
    bool queryMetaBool(const std::string & name, bool def);
    void setMeta(const std::string & name, Value * v);

    /*
    MetaInfo queryMetaInfo(EvalState & state) const;
    MetaValue queryMetaInfo(EvalState & state, const string & name) const;
    */

    void setName(const std::string & s) { name = s; }
    void setDrvPath(StorePath path) { drvPath = {{std::move(path)}}; }
    void setOutPath(StorePath path) { outPath = {{std::move(path)}}; }

    void setFailed() { failed = true; };
    bool hasFailed() { return failed; };
};


#if HAVE_BOEHMGC
typedef std::list<DrvInfo, traceable_allocator<DrvInfo>> DrvInfos;
#else
typedef std::list<DrvInfo> DrvInfos;
#endif


/* If value `v' denotes a derivation, return a DrvInfo object
   describing it. Otherwise return nothing. */
std::optional<DrvInfo> getDerivation(EvalState & state,
    Value & v, bool ignoreAssertionFailures);

void getDerivations(EvalState & state, Value & v, const std::string & pathPrefix,
    Bindings & autoArgs, DrvInfos & drvs,
    bool ignoreAssertionFailures);


}
