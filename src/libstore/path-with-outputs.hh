#pragma once

#include <nlohmann/json_fwd.hpp>  // for json
#include <variant>                // for variant
#include <set>                    // for set
#include <string>                 // for string, basic_string, operator<
#include <string_view>            // for string_view
#include <utility>                // for pair
#include <vector>                 // for vector

#include "path.hh"                // for StorePath
#include "derived-path.hh"        // for DerivedPath
#include "types.hh"               // for StringSet

namespace nix {
class Store;

struct StorePathWithOutputs
{
    StorePath path;
    std::set<std::string> outputs;

    std::string to_string(const Store & store) const;

    DerivedPath toDerivedPath() const;

    static std::variant<StorePathWithOutputs, StorePath> tryFromDerivedPath(const DerivedPath &);
};

std::vector<DerivedPath> toDerivedPaths(const std::vector<StorePathWithOutputs>);

std::pair<std::string_view, StringSet> parsePathWithOutputs(std::string_view s);


/* Split a string specifying a derivation and a set of outputs
   (/nix/store/hash-foo!out1,out2,...) into the derivation path
   and the outputs. */
StorePathWithOutputs parsePathWithOutputs(const Store & store, std::string_view pathWithOutputs);

StorePathWithOutputs followLinksToStorePathWithOutputs(const Store & store, std::string_view pathWithOutputs);

typedef std::set<std::string> OutputNames;

struct AllOutputs {
    bool operator < (const AllOutputs & _) const { return false; }
};

struct DefaultOutputs {
    bool operator < (const DefaultOutputs & _) const { return false; }
};

typedef std::variant<DefaultOutputs, AllOutputs, OutputNames> OutputsSpec;

/* Parse a string of the form 'prefix^output1,...outputN' or
   'prefix^*', returning the prefix and the outputs spec. */
std::pair<std::string, OutputsSpec> parseOutputsSpec(const std::string & s);

std::string printOutputsSpec(const OutputsSpec & outputsSpec);

void to_json(nlohmann::json &, const OutputsSpec &);
void from_json(const nlohmann::json &, OutputsSpec &);

}
