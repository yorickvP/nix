#include <map>             // for operator==, _Rb_tree_const_iterator, _Rb_t...
#include <memory>          // for allocator, allocator_traits<>::value_type
#include <string>          // for char_traits, operator+, basic_string, string
#include <utility>         // for pair
#include <vector>          // for vector

#include "builtins.hh"     // for builtinUnpackChannel
#include "tarfile.hh"      // for unpackTarfile
#include "derivations.hh"  // for BasicDerivation
#include "error.hh"        // for Error
#include "types.hh"        // for StringPairs, Path
#include "util.hh"         // for createDirs, readDirectory, renameFile

namespace nix {

void builtinUnpackChannel(const BasicDerivation & drv)
{
    auto getAttr = [&](const std::string & name) {
        auto i = drv.env.find(name);
        if (i == drv.env.end()) throw Error("attribute '%s' missing", name);
        return i->second;
    };

    Path out = getAttr("out");
    auto channelName = getAttr("channelName");
    auto src = getAttr("src");

    createDirs(out);

    unpackTarfile(src, out);

    auto entries = readDirectory(out);
    if (entries.size() != 1)
        throw Error("channel tarball '%s' contains more than one file", src);
    renameFile((out + "/" + entries[0].name), (out + "/" + channelName));
}

}
