#include <memory>           // for allocator, __shared_ptr_access, shared_ptr
#include <optional>         // for optional
#include <set>              // for operator!=, _Rb_tree_const_iterator, _Rb_...
#include <string>           // for string, basic_string
#include <vector>           // for vector

#include "command.hh"       // for registerCommand2, CopyCommand, Installabl...
#include "store-api.hh"     // for Store
#include "store-cast.hh"    // for require
#include "log-store.hh"     // for LogStore
#include "args.hh"          // for Command::Category
#include "error.hh"         // for Error
#include "installables.hh"  // for Installable
#include "path.hh"          // for StorePathSet
#include "ref.hh"           // for ref, nix

using namespace nix;

struct CmdCopyLog : virtual CopyCommand, virtual InstallablesCommand
{
    std::string description() override
    {
        return "copy build logs between Nix stores";
    }

    std::string doc() override
    {
        return
          #include "store-copy-log.md"
          ;
    }

    Category category() override { return catUtility; }

    void run(ref<Store> srcStore) override
    {
        auto & srcLogStore = require<LogStore>(*srcStore);

        auto dstStore = getDstStore();
        auto & dstLogStore = require<LogStore>(*dstStore);

        StorePathSet drvPaths;

        for (auto & i : installables)
            for (auto & drvPath : i->toDrvPaths(getEvalStore()))
                drvPaths.insert(drvPath);

        for (auto & drvPath : drvPaths) {
            if (auto log = srcLogStore.getBuildLog(drvPath))
                dstLogStore.addBuildLog(drvPath, *log);
            else
                throw Error("build log for '%s' is not available", srcStore->printStorePath(drvPath));
        }
    }
};

static auto rCmdCopyLog = registerCommand2<CmdCopyLog>({"store", "copy-log"});
