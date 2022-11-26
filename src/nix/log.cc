#include <iostream>         // for cout, ostream
#include <list>             // for list, operator!=, _List_iterator, _List_i...
#include <memory>           // for allocator, __shared_ptr_access, shared_ptr
#include <optional>         // for optional
#include <string>           // for operator<<, string
#include <variant>          // for visit

#include "command.hh"       // for registerCommand, InstallableCommand, catS...
#include "shared.hh"        // for RunPager
#include "store-api.hh"     // for getDefaultSubstituters, Store
#include "log-store.hh"     // for LogStore
#include "progress-bar.hh"  // for stopProgressBar
#include "args.hh"          // for Command::Category
#include "derived-path.hh"  // for DerivedPath, DerivedPath::Built, DerivedP...
#include "error.hh"         // for Error
#include "globals.hh"       // for Settings, settings
#include "installables.hh"  // for Installable
#include "logging.hh"       // for Logger, printInfo
#include "ref.hh"           // for ref, nix
#include "util.hh"          // for overloaded

using namespace nix;

struct CmdLog : InstallableCommand
{
    std::string description() override
    {
        return "show the build log of the specified packages or paths, if available";
    }

    std::string doc() override
    {
        return
          #include "log.md"
          ;
    }

    Category category() override { return catSecondary; }

    void run(ref<Store> store) override
    {
        settings.readOnlyMode = true;

        auto subs = getDefaultSubstituters();

        subs.push_front(store);

        auto b = installable->toDerivedPath();

        RunPager pager;
        for (auto & sub : subs) {
            auto * logSubP = dynamic_cast<LogStore *>(&*sub);
            if (!logSubP) {
                printInfo("Skipped '%s' which does not support retrieving build logs", sub->getUri());
                continue;
            }
            auto & logSub = *logSubP;

            auto log = std::visit(overloaded {
                [&](const DerivedPath::Opaque & bo) {
                    return logSub.getBuildLog(bo.path);
                },
                [&](const DerivedPath::Built & bfd) {
                    return logSub.getBuildLog(bfd.drvPath);
                },
            }, b.raw());
            if (!log) continue;
            stopProgressBar();
            printInfo("got build log for '%s' from '%s'", installable->what(), logSub.getUri());
            std::cout << *log;
            return;
        }

        throw Error("build log of '%s' is not available", installable->what());
    }
};

static auto rCmdLog = registerCommand<CmdLog>("log");
