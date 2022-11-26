#pragma once

#include <optional>           // for optional
#include <set>                // for set
#include <string>             // for string, basic_string, allocator, operator<

#include "remote-store.hh"    // for RemoteStore, RemoteStoreConfig, RemoteS...
#include "local-fs-store.hh"  // for LocalFSStore, LocalFSStoreConfig
#include "path.hh"            // for StorePath
#include "ref.hh"             // for ref
#include "store-api.hh"       // for Store::Params, Store, StoreConfig
#include "util.hh"            // for AutoCloseFD

namespace nix {
class FSAccessor;
struct Sink;

struct UDSRemoteStoreConfig : virtual LocalFSStoreConfig, virtual RemoteStoreConfig
{
    UDSRemoteStoreConfig(const Store::Params & params)
        : StoreConfig(params)
        , LocalFSStoreConfig(params)
        , RemoteStoreConfig(params)
    {
    }

    const std::string name() override { return "Local Daemon Store"; }
};

class UDSRemoteStore : public virtual UDSRemoteStoreConfig, public virtual LocalFSStore, public virtual RemoteStore
{
public:

    UDSRemoteStore(const Params & params);
    UDSRemoteStore(const std::string scheme, std::string path, const Params & params);

    std::string getUri() override;

    static std::set<std::string> uriSchemes()
    { return {"unix"}; }

    bool sameMachine() override
    { return true; }

    ref<FSAccessor> getFSAccessor() override
    { return LocalFSStore::getFSAccessor(); }

    void narFromPath(const StorePath & path, Sink & sink) override
    { LocalFSStore::narFromPath(path, sink); }

private:

    struct Connection : RemoteStore::Connection
    {
        AutoCloseFD fd;
        void closeWrite() override;
    };

    ref<RemoteStore::Connection> openConnection() override;
    std::optional<std::string> path;
};

}
