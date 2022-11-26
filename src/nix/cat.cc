#include <iostream>         // for cout, ostream
#include <string>           // for string, allocator, basic_string, operator<<

#include "command.hh"       // for registerCommand2, StoreCommand
#include "store-api.hh"     // for Store
#include "fs-accessor.hh"   // for FSAccessor, FSAccessor::Stat, FSAccessor:...
#include "nar-accessor.hh"  // for makeNarAccessor
#include "args.hh"          // for completePath, Args
#include "error.hh"         // for Error
#include "ref.hh"           // for ref, nix
#include "types.hh"         // for Path
#include "util.hh"          // for readFile

using namespace nix;

struct MixCat : virtual Args
{
    std::string path;

    void cat(ref<FSAccessor> accessor)
    {
        auto st = accessor->stat(path);
        if (st.type == FSAccessor::Type::tMissing)
            throw Error("path '%1%' does not exist", path);
        if (st.type != FSAccessor::Type::tRegular)
            throw Error("path '%1%' is not a regular file", path);

        std::cout << accessor->readFile(path);
    }
};

struct CmdCatStore : StoreCommand, MixCat
{
    CmdCatStore()
    {
        expectArgs({
            .label = "path",
            .handler = {&path},
            .completer = completePath
        });
    }

    std::string description() override
    {
        return "print the contents of a file in the Nix store on stdout";
    }

    std::string doc() override
    {
        return
          #include "store-cat.md"
          ;
    }

    void run(ref<Store> store) override
    {
        cat(store->getFSAccessor());
    }
};

struct CmdCatNar : StoreCommand, MixCat
{
    Path narPath;

    CmdCatNar()
    {
        expectArgs({
            .label = "nar",
            .handler = {&narPath},
            .completer = completePath
        });
        expectArg("path", &path);
    }

    std::string description() override
    {
        return "print the contents of a file inside a NAR file on stdout";
    }

    std::string doc() override
    {
        return
          #include "nar-cat.md"
          ;
    }

    void run(ref<Store> store) override
    {
        cat(makeNarAccessor(readFile(narPath)));
    }
};

static auto rCmdCatStore = registerCommand2<CmdCatStore>({"store", "cat"});
static auto rCmdCatNar = registerCommand2<CmdCatNar>({"nar", "cat"});
