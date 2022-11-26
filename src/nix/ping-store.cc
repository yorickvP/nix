#include <optional>      // for optional
#include <string>        // for string, basic_string, allocator

#include "command.hh"    // for registerCommand2, StoreCommand
#include "store-api.hh"  // for Store
#include "logging.hh"    // for Logger, notice
#include "ref.hh"        // for ref, nix

using namespace nix;

struct CmdPingStore : StoreCommand
{
    std::string description() override
    {
        return "test whether a store can be accessed";
    }

    std::string doc() override
    {
        return
          #include "ping-store.md"
          ;
    }

    void run(ref<Store> store) override
    {
        notice("Store URL: %s", store->getUri());
        store->connect();
        if (auto version = store->getVersion())
            notice("Version: %s", *version);
    }
};

static auto rCmdPingStore = registerCommand2<CmdPingStore>({"store", "ping"});
