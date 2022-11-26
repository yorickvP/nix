#pragma once

#include <string>    // for basic_string
#include <vector>    // for max, vector

#include "types.hh"  // for Path

namespace nix {
struct BasicDerivation;

struct Package {
    Path path;
    bool active;
    int priority;
    Package(const Path & path, bool active, int priority) : path{path}, active{active}, priority{priority} {}
};

typedef std::vector<Package> Packages;

void buildProfile(const Path & out, Packages && pkgs);

void builtinBuildenv(const BasicDerivation & drv);

}
