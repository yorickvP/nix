#pragma once

#include <nlohmann/json_fwd.hpp>  // for json
#include <stdint.h>               // for uint64_t
#include <variant>                // for variant
#include <optional>               // for optional
#include <map>                    // for map, map<>::value_compare
#include <string>                 // for string, basic_string, operator<

namespace nix {
template <typename T> struct Explicit;
}  // namespace nix

namespace nix::fetchers {

typedef std::variant<std::string, uint64_t, Explicit<bool>> Attr;
typedef std::map<std::string, Attr> Attrs;

Attrs jsonToAttrs(const nlohmann::json & json);

nlohmann::json attrsToJSON(const Attrs & attrs);

std::optional<std::string> maybeGetStrAttr(const Attrs & attrs, const std::string & name);

std::string getStrAttr(const Attrs & attrs, const std::string & name);

std::optional<uint64_t> maybeGetIntAttr(const Attrs & attrs, const std::string & name);

uint64_t getIntAttr(const Attrs & attrs, const std::string & name);

std::optional<bool> maybeGetBoolAttr(const Attrs & attrs, const std::string & name);

bool getBoolAttr(const Attrs & attrs, const std::string & name);

std::map<std::string, std::string> attrsToQuery(const Attrs & attrs);

}
