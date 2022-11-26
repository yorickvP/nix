#include <nlohmann/json.hpp>  // for basic_json<>::object_t, basic_json, json
#include <assert.h>           // for assert
#include <stdint.h>           // for int64_t
#include <boost/format.hpp>   // for basic_altstringbuf<>::int_type, basic_a...
#include <cctype>             // for tolower
#include <initializer_list>   // for initializer_list
#include <map>                // for map, map<>::mapped_type, operator!=
#include <optional>           // for optional
#include <set>                // for set
#include <string>             // for string, basic_string, allocator, operator<
#include <type_traits>        // for remove_reference<>::type
#include <utility>            // for tuple_element<>::type
#include <variant>            // for get_if
#include <vector>             // for vector

#include "flake.hh"           // for ConfigFile
#include "fetch-settings.hh"  // for FetchSettings, fetchSettings
#include "ansicolor.hh"       // for ANSI_NORMAL, ANSI_RED
#include "config.hh"          // for Setting, GlobalConfig, globalConfig
#include "fmt.hh"             // for fmt
#include "logging.hh"         // for warn, Logger, logger
#include "types.hh"           // for Path, Explicit
#include "util.hh"            // for get, concatStringsSep, createDirs, dirOf

namespace nix::flake {

// setting name -> setting value -> allow or ignore.
typedef std::map<std::string, std::map<std::string, bool>> TrustedList;

Path trustedListPath()
{
    return getDataDir() + "/nix/trusted-settings.json";
}

static TrustedList readTrustedList()
{
    auto path = trustedListPath();
    if (!pathExists(path)) return {};
    auto json = nlohmann::json::parse(readFile(path));
    return json;
}

static void writeTrustedList(const TrustedList & trustedList)
{
    auto path = trustedListPath();
    createDirs(dirOf(path));
    writeFile(path, nlohmann::json(trustedList).dump());
}

void ConfigFile::apply()
{
    std::set<std::string> whitelist{"bash-prompt", "bash-prompt-prefix", "bash-prompt-suffix", "flake-registry"};

    for (auto & [name, value] : settings) {

        auto baseName = hasPrefix(name, "extra-") ? std::string(name, 6) : name;

        // FIXME: Move into libutil/config.cc.
        std::string valueS;
        if (auto* s = std::get_if<std::string>(&value))
            valueS = *s;
        else if (auto* n = std::get_if<int64_t>(&value))
            valueS = fmt("%d", *n);
        else if (auto* b = std::get_if<Explicit<bool>>(&value))
            valueS = b->t ? "true" : "false";
        else if (auto ss = std::get_if<std::vector<std::string>>(&value))
            valueS = concatStringsSep(" ", *ss); // FIXME: evil
        else
            assert(false);

        if (!whitelist.count(baseName) && !nix::fetchSettings.acceptFlakeConfig) {
            bool trusted = false;
            auto trustedList = readTrustedList();
            auto tlname = get(trustedList, name);
            if (auto saved = tlname ? get(*tlname, valueS) : nullptr) {
                trusted = *saved;
                warn("Using saved setting for '%s = %s' from ~/.local/share/nix/trusted-settings.json.", name,valueS);
            } else {
                // FIXME: filter ANSI escapes, newlines, \r, etc.
                if (std::tolower(logger->ask(fmt("do you want to allow configuration setting '%s' to be set to '" ANSI_RED "%s" ANSI_NORMAL "' (y/N)?", name, valueS)).value_or('n')) == 'y') {
                    trusted = true;
                }
                if (std::tolower(logger->ask(fmt("do you want to permanently mark this value as %s (y/N)?",  trusted ? "trusted": "untrusted" )).value_or('n')) == 'y') {
                    trustedList[name][valueS] = trusted;
                    writeTrustedList(trustedList);
                }
            }
            if (!trusted) {
                warn("ignoring untrusted flake configuration setting '%s'.\nPass '%s' to trust it", name, "--accept-flake-config");
                continue;
            }
        }

        globalConfig.set(name, valueS);
    }
}

}
