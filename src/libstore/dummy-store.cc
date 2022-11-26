#include <memory>          // for shared_ptr, allocator
#include <optional>        // for optional
#include <set>             // for set, _Rb_tree_const_iterator
#include <string>          // for string, basic_string, operator<
#include <string_view>     // for string_view

#include "store-api.hh"    // for StoreConfig, Store, Store::Params, CheckSi...
#include "callback.hh"     // for Callback
#include "path.hh"         // for StorePath, StorePathSet
#include "repair-flag.hh"  // for RepairFlag
#include "types.hh"        // for StringMap

namespace nix {
struct DrvOutput;
struct Realisation;
struct Sink;
struct Source;
struct ValidPathInfo;

struct DummyStoreConfig : virtual StoreConfig {
    using StoreConfig::StoreConfig;

    const std::string name() override { return "Dummy Store"; }
};

struct DummyStore : public virtual DummyStoreConfig, public virtual Store
{
    DummyStore(const std::string scheme, const std::string uri, const Params & params)
        : DummyStore(params)
    { }

    DummyStore(const Params & params)
        : StoreConfig(params)
        , DummyStoreConfig(params)
        , Store(params)
    { }

    std::string getUri() override
    {
        return *uriSchemes().begin();
    }

    void queryPathInfoUncached(const StorePath & path,
        Callback<std::shared_ptr<const ValidPathInfo>> callback) noexcept override
    {
        callback(nullptr);
    }

    static std::set<std::string> uriSchemes() {
        return {"dummy"};
    }

    std::optional<StorePath> queryPathFromHashPart(const std::string & hashPart) override
    { unsupported("queryPathFromHashPart"); }

    void addToStore(const ValidPathInfo & info, Source & source,
        RepairFlag repair, CheckSigsFlag checkSigs) override
    { unsupported("addToStore"); }

    StorePath addTextToStore(
        std::string_view name,
        std::string_view s,
        const StorePathSet & references,
        RepairFlag repair) override
    { unsupported("addTextToStore"); }

    void narFromPath(const StorePath & path, Sink & sink) override
    { unsupported("narFromPath"); }

    void queryRealisationUncached(const DrvOutput &,
        Callback<std::shared_ptr<const Realisation>> callback) noexcept override
    { callback(nullptr); }
};

static RegisterStoreImplementation<DummyStore, DummyStoreConfig> regDummyStore;

}
