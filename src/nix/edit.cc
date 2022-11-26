#include <unistd.h>          // for execvp
#include <boost/format.hpp>  // for basic_altstringbuf<>::int_type, basic_al...
#include <list>              // for list, operator!=, _List_iterator, _List_...
#include <memory>            // for allocator, __shared_ptr_access, shared_ptr
#include <string>            // for char_traits, operator+, string, basic_st...
#include <vector>            // for vector

#include "command.hh"        // for editorFor, registerCommand, InstallableC...
#include "attr-path.hh"      // for findPackageFilename, NoPositionInfo
#include "progress-bar.hh"   // for stopProgressBar
#include "args.hh"           // for Command::Category
#include "error.hh"          // for Error, SysError
#include "installables.hh"   // for Installable
#include "ref.hh"            // for ref, nix
#include "util.hh"           // for restoreProcessContext, stringsToCharPtrs

namespace nix {
class EvalState;
class Store;
}  // namespace nix

using namespace nix;

struct CmdEdit : InstallableCommand
{
    std::string description() override
    {
        return "open the Nix expression of a Nix package in $EDITOR";
    }

    std::string doc() override
    {
        return
          #include "edit.md"

          ;
    }

    Category category() override { return catSecondary; }

    void run(ref<Store> store) override
    {
        auto state = getEvalState();

        const auto [file, line] = [&] {
            auto [v, pos] = installable->toValue(*state);

            try {
                return findPackageFilename(*state, *v, installable->what());
            } catch (NoPositionInfo &) {
                throw Error("cannot find position information for '%s", installable->what());
            }
        }();

        stopProgressBar();

        auto args = editorFor(file, line);

        restoreProcessContext();

        execvp(args.front().c_str(), stringsToCharPtrs(args).data());

        std::string command;
        for (const auto &arg : args) command += " '" + arg + "'";
        throw SysError("cannot run command%s", command);
    }
};

static auto rCmdEdit = registerCommand<CmdEdit>("edit");
