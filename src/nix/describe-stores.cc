#include <nlohmann/json.hpp>  // for basic_json<>::object_t, basic_json, bas...
#include <functional>         // for function
#include <iostream>           // for endl, operator<<, ostream, basic_ostream
#include <memory>             // for allocator, __shared_ptr_access, shared_ptr
#include <string>             // for string, char_traits, operator<<
#include <vector>             // for vector

#include "command.hh"         // for registerCommand, catUtility
#include "common-args.hh"     // for MixJSON
#include "store-api.hh"       // for StoreConfig, Implementations, Implement...
#include "args.hh"            // for Command, Command::Category
#include "ref.hh"             // for nix

using namespace nix;

struct CmdDescribeStores : Command, MixJSON
{
    std::string description() override
    {
        return "show registered store types and their available options";
    }

    Category category() override { return catUtility; }

    void run() override
    {
        auto res = nlohmann::json::object();
        for (auto & implem : *Implementations::registered) {
            auto storeConfig = implem.getConfig();
            auto storeName = storeConfig->name();
            res[storeName] = storeConfig->toJSON();
        }
        if (json) {
            std::cout << res;
        } else {
            for (auto & [storeName, storeConfig] : res.items()) {
                std::cout << "## " << storeName << std::endl << std::endl;
                for (auto & [optionName, optionDesc] : storeConfig.items()) {
                    std::cout << "### " << optionName << std::endl << std::endl;
                    std::cout << optionDesc["description"].get<std::string>() << std::endl;
                    std::cout << "default: " << optionDesc["defaultValue"] << std::endl <<std::endl;
                    if (!optionDesc["aliases"].empty())
                        std::cout << "aliases: " << optionDesc["aliases"] << std::endl << std::endl;
                }
            }
        }
    }
};

static auto rDescribeStore = registerCommand<CmdDescribeStores>("describe-stores");
