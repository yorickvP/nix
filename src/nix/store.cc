#include <optional>    // for optional
#include <string>      // for string, basic_string, allocator
#include <utility>     // for pair

#include "command.hh"  // for registerCommand, NixMultiCommand, RegisterCommand
#include "args.hh"     // for Command, Command::Category, MultiCommand
#include "error.hh"    // for UsageError
#include "ref.hh"      // for ref, nix

using namespace nix;

struct CmdStore : virtual NixMultiCommand
{
    CmdStore() : MultiCommand(RegisterCommand::getCommandsFor({"store"}))
    { }

    std::string description() override
    {
        return "manipulate a Nix store";
    }

    Category category() override { return catUtility; }

    void run() override
    {
        if (!command)
            throw UsageError("'nix store' requires a sub-command.");
        command->second->prepare();
        command->second->run();
    }
};

static auto rCmdStore = registerCommand<CmdStore>("store");
