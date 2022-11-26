#include <boost/format.hpp>  // for basic_altstringbuf<>::int_type, basic_al...
#include <functional>        // for function
#include <iostream>          // for cout
#include <set>               // for operator!=, set, _Rb_tree_const_iterator
#include <string>            // for string, allocator, basic_string, operator+
#include <string_view>       // for string_view

#include "command.hh"        // for registerCommand2, StoreCommand
#include "store-api.hh"      // for Store
#include "fs-accessor.hh"    // for FSAccessor, FSAccessor::Stat, FSAccessor...
#include "nar-accessor.hh"   // for listNar, makeNarAccessor
#include "common-args.hh"    // for MixJSON
#include "json.hh"           // for JSONPlaceholder
#include "args.hh"           // for completePath, Args, Command
#include "error.hh"          // for UsageError, Error
#include "fmt.hh"            // for fmt
#include "logging.hh"        // for Logger, logger
#include "ref.hh"            // for ref, nix
#include "types.hh"          // for Path
#include "util.hh"           // for baseNameOf, readFile

using namespace nix;

struct MixLs : virtual Args, MixJSON
{
    std::string path;

    bool recursive = false;
    bool verbose = false;
    bool showDirectory = false;

    MixLs()
    {
        addFlag({
            .longName = "recursive",
            .shortName = 'R',
            .description = "List subdirectories recursively.",
            .handler = {&recursive, true},
        });

        addFlag({
            .longName = "long",
            .shortName = 'l',
            .description = "Show detailed file information.",
            .handler = {&verbose, true},
        });

        addFlag({
            .longName = "directory",
            .shortName = 'd',
            .description = "Show directories rather than their contents.",
            .handler = {&showDirectory, true},
        });
    }

    void listText(ref<FSAccessor> accessor)
    {
        std::function<void(const FSAccessor::Stat &, const Path &, const std::string &, bool)> doPath;

        auto showFile = [&](const Path & curPath, const std::string & relPath) {
            if (verbose) {
                auto st = accessor->stat(curPath);
                std::string tp =
                    st.type == FSAccessor::Type::tRegular ?
                        (st.isExecutable ? "-r-xr-xr-x" : "-r--r--r--") :
                    st.type == FSAccessor::Type::tSymlink ? "lrwxrwxrwx" :
                    "dr-xr-xr-x";
                auto line = fmt("%s %20d %s", tp, st.fileSize, relPath);
                if (st.type == FSAccessor::Type::tSymlink)
                    line += " -> " + accessor->readLink(curPath);
                logger->cout(line);
                if (recursive && st.type == FSAccessor::Type::tDirectory)
                    doPath(st, curPath, relPath, false);
            } else {
                logger->cout(relPath);
                if (recursive) {
                    auto st = accessor->stat(curPath);
                    if (st.type == FSAccessor::Type::tDirectory)
                        doPath(st, curPath, relPath, false);
                }
            }
        };

        doPath = [&](const FSAccessor::Stat & st, const Path & curPath,
            const std::string & relPath, bool showDirectory)
        {
            if (st.type == FSAccessor::Type::tDirectory && !showDirectory) {
                auto names = accessor->readDirectory(curPath);
                for (auto & name : names)
                    showFile(curPath + "/" + name, relPath + "/" + name);
            } else
                showFile(curPath, relPath);
        };

        auto st = accessor->stat(path);
        if (st.type == FSAccessor::Type::tMissing)
            throw Error("path '%1%' does not exist", path);
        doPath(st, path,
            st.type == FSAccessor::Type::tDirectory ? "." : std::string(baseNameOf(path)),
            showDirectory);
    }

    void list(ref<FSAccessor> accessor)
    {
        if (path == "/") path = "";

        if (json) {
            JSONPlaceholder jsonRoot(std::cout);
            if (showDirectory)
                throw UsageError("'--directory' is useless with '--json'");
            listNar(jsonRoot, accessor, path, recursive);
        } else
            listText(accessor);
    }
};

struct CmdLsStore : StoreCommand, MixLs
{
    CmdLsStore()
    {
        expectArgs({
            .label = "path",
            .handler = {&path},
            .completer = completePath
        });
    }

    std::string description() override
    {
        return "show information about a path in the Nix store";
    }

    std::string doc() override
    {
        return
          #include "store-ls.md"

          ;
    }

    void run(ref<Store> store) override
    {
        list(store->getFSAccessor());
    }
};

struct CmdLsNar : Command, MixLs
{
    Path narPath;

    CmdLsNar()
    {
        expectArgs({
            .label = "nar",
            .handler = {&narPath},
            .completer = completePath
        });
        expectArg("path", &path);
    }

    std::string doc() override
    {
        return
          #include "nar-ls.md"

          ;
    }

    std::string description() override
    {
        return "show information about a path inside a NAR file";
    }

    void run() override
    {
        list(makeNarAccessor(readFile(narPath)));
    }
};

static auto rCmdLsStore = registerCommand2<CmdLsStore>({"store", "ls"});
static auto rCmdLsNar = registerCommand2<CmdLsNar>({"nar", "ls"});
