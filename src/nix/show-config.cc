#include <nlohmann/json.hpp>  // for basic_json, json
#include <boost/format.hpp>   // for basic_altstringbuf<>::int_type, basic_a...
#include <string>             // for allocator, string

#include "command.hh"         // for registerCommand, catUtility
#include "common-args.hh"     // for MixJSON
#include "args.hh"            // for Command, Command::Category
#include "config.hh"          // for GlobalConfig, globalConfig
#include "logging.hh"         // for Logger, logger
#include "ref.hh"             // for nix

using namespace nix;

struct CmdShowConfig : Command, MixJSON
{
    std::string description() override
    {
        return "show the Nix configuration";
    }

    Category category() override { return catUtility; }

    void run() override
    {
        if (json) {
            // FIXME: use appropriate JSON types (bool, ints, etc).
            logger->cout("%s", globalConfig.toJSON().dump());
        } else {
            logger->cout("%s", globalConfig.toKeyValue());
        }
    }
};

static auto rShowConfig = registerCommand<CmdShowConfig>("show-config");
