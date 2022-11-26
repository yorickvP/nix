#include <stdint.h>          // for uint64_t
#include <boost/format.hpp>  // for basic_altstringbuf<>::int_type, basic_al...
#include <regex>             // for regex, smatch, regex_search, match_resul...
#include <algorithm>         // for max, replace
#include <functional>        // for function
#include <iostream>          // for cout
#include <map>               // for map
#include <memory>            // for allocator, shared_ptr, __shared_ptr_access
#include <sstream>           // for basic_stringbuf<>::int_type, basic_strin...
#include <string>            // for string, basic_string, operator+, char_tr...
#include <vector>            // for vector

#include "command.hh"        // for registerCommand, InstallableCommand
#include "globals.hh"        // for Settings, settings
#include "eval.hh"           // for EvalState, EvalSettings, evalSettings
#include "names.hh"          // for DrvName
#include "common-args.hh"    // for MixJSON
#include "json.hh"           // for JSONObject
#include "eval-cache.hh"     // for AttrCursor
#include "hilite.hh"         // for hiliteMatches
#include "ansicolor.hh"      // for ANSI_GREEN, ANSI_NORMAL
#include "args.hh"           // for Args::Flag
#include "config.hh"         // for Setting
#include "error.hh"          // for Error, lvlInfo
#include "fmt.hh"            // for fmt
#include "installables.hh"   // for Installable
#include "logging.hh"        // for logger, Logger, Activity, actUnknown
#include "nixexpr.hh"        // for EvalError
#include "ref.hh"            // for ref, nix
#include "symbol-table.hh"   // for SymbolStr, Symbol (ptr only), SymbolTable
#include "types.hh"          // for Strings
#include "util.hh"           // for concatStringsSep, concatStrings

namespace nix {
class Store;
}  // namespace nix

using namespace nix;

std::string wrap(std::string prefix, std::string s)
{
    return concatStrings(prefix, s, ANSI_NORMAL);
}

struct CmdSearch : InstallableCommand, MixJSON
{
    std::vector<std::string> res;
    std::vector<std::string> excludeRes;

    CmdSearch()
    {
        expectArgs("regex", &res);
        addFlag(Flag {
            .longName = "exclude",
            .shortName = 'e',
            .description = "Hide packages whose attribute path, name or description contain *regex*.",
            .labels = {"regex"},
            .handler = {[this](std::string s) {
                excludeRes.push_back(s);
            }},
        });
    }

    std::string description() override
    {
        return "search for packages";
    }

    std::string doc() override
    {
        return
          #include "search.md"

          ;
    }

    Strings getDefaultFlakeAttrPaths() override
    {
        return {
            "packages." + settings.thisSystem.get() + ".",
            "legacyPackages." + settings.thisSystem.get() + "."
        };
    }

    void run(ref<Store> store) override
    {
        settings.readOnlyMode = true;
        evalSettings.enableImportFromDerivation.setDefault(false);

        // Empty search string should match all packages
        // Use "^" here instead of ".*" due to differences in resulting highlighting
        // (see #1893 -- libc++ claims empty search string is not in POSIX grammar)
        if (res.empty())
            res.push_back("^");

        std::vector<std::regex> regexes;
        std::vector<std::regex> excludeRegexes;
        regexes.reserve(res.size());
        excludeRegexes.reserve(excludeRes.size());

        for (auto & re : res)
            regexes.push_back(std::regex(re, std::regex::extended | std::regex::icase));

        for (auto & re : excludeRes)
            excludeRegexes.emplace_back(re, std::regex::extended | std::regex::icase);

        auto state = getEvalState();

        auto jsonOut = json ? std::make_unique<JSONObject>(std::cout) : nullptr;

        uint64_t results = 0;

        std::function<void(eval_cache::AttrCursor & cursor, const std::vector<Symbol> & attrPath, bool initialRecurse)> visit;

        visit = [&](eval_cache::AttrCursor & cursor, const std::vector<Symbol> & attrPath, bool initialRecurse)
        {
            auto attrPathS = state->symbols.resolve(attrPath);

            Activity act(*logger, lvlInfo, actUnknown,
                fmt("evaluating '%s'", concatStringsSep(".", attrPathS)));
            try {
                auto recurse = [&]()
                {
                    for (const auto & attr : cursor.getAttrs()) {
                        auto cursor2 = cursor.getAttr(state->symbols[attr]);
                        auto attrPath2(attrPath);
                        attrPath2.push_back(attr);
                        visit(*cursor2, attrPath2, false);
                    }
                };

                if (cursor.isDerivation()) {
                    DrvName name(cursor.getAttr(state->sName)->getString());

                    auto aMeta = cursor.maybeGetAttr(state->sMeta);
                    auto aDescription = aMeta ? aMeta->maybeGetAttr(state->sDescription) : nullptr;
                    auto description = aDescription ? aDescription->getString() : "";
                    std::replace(description.begin(), description.end(), '\n', ' ');
                    auto attrPath2 = concatStringsSep(".", attrPathS);

                    std::vector<std::smatch> attrPathMatches;
                    std::vector<std::smatch> descriptionMatches;
                    std::vector<std::smatch> nameMatches;
                    bool found = false;

                    for (auto & regex : excludeRegexes) {
                        if (
                            std::regex_search(attrPath2, regex)
                            || std::regex_search(name.name, regex)
                            || std::regex_search(description, regex))
                            return;
                    }

                    for (auto & regex : regexes) {
                        found = false;
                        auto addAll = [&found](std::sregex_iterator it, std::vector<std::smatch> & vec) {
                            const auto end = std::sregex_iterator();
                            while (it != end) {
                                vec.push_back(*it++);
                                found = true;
                            }
                        };

                        addAll(std::sregex_iterator(attrPath2.begin(), attrPath2.end(), regex), attrPathMatches);
                        addAll(std::sregex_iterator(name.name.begin(), name.name.end(), regex), nameMatches);
                        addAll(std::sregex_iterator(description.begin(), description.end(), regex), descriptionMatches);

                        if (!found)
                            break;
                    }

                    if (found)
                    {
                        results++;
                        if (json) {
                            auto jsonElem = jsonOut->object(attrPath2);
                            jsonElem.attr("pname", name.name);
                            jsonElem.attr("version", name.version);
                            jsonElem.attr("description", description);
                        } else {
                            auto name2 = hiliteMatches(name.name, nameMatches, ANSI_GREEN, "\e[0;2m");
                            if (results > 1) logger->cout("");
                            logger->cout(
                                "* %s%s",
                                wrap("\e[0;1m", hiliteMatches(attrPath2, attrPathMatches, ANSI_GREEN, "\e[0;1m")),
                                name.version != "" ? " (" + name.version + ")" : "");
                            if (description != "")
                                logger->cout(
                                    "  %s", hiliteMatches(description, descriptionMatches, ANSI_GREEN, ANSI_NORMAL));
                        }
                    }
                }

                else if (
                    attrPath.size() == 0
                    || (attrPathS[0] == "legacyPackages" && attrPath.size() <= 2)
                    || (attrPathS[0] == "packages" && attrPath.size() <= 2))
                    recurse();

                else if (initialRecurse)
                    recurse();

                else if (attrPathS[0] == "legacyPackages" && attrPath.size() > 2) {
                    auto attr = cursor.maybeGetAttr(state->sRecurseForDerivations);
                    if (attr && attr->getBool())
                        recurse();
                }

            } catch (EvalError & e) {
                if (!(attrPath.size() > 0 && attrPathS[0] == "legacyPackages"))
                    throw;
            }
        };

        for (auto & cursor : installable->getCursors(*state))
            visit(*cursor, cursor->getAttrPath(), true);

        if (!json && !results)
            throw Error("no results for the given search term(s)!");
    }
};

static auto rCmdSearch = registerCommand<CmdSearch>("search");
