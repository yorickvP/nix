#include <algorithm>           // for reverse
#include <optional>            // for optional
#include <string>              // for string, allocator, operator<
#include <type_traits>         // for remove_reference<>::type
#include <utility>             // for move, pair
#include <vector>              // for vector

#include "make-content-addressed.hh"
#include "references.hh"       // for HashModuloSink, RewritingSink
#include "content-address.hh"  // for ContentAddress, FileIngestionMethod
#include "hash.hh"             // for hashString, htSHA256, HashResult
#include "logging.hh"          // for Logger, printInfo
#include "path-info.hh"        // for ValidPathInfo
#include "ref.hh"              // for ref
#include "serialise.hh"        // for StringSink, StringSource
#include "store-api.hh"        // for Store
#include "types.hh"            // for StringMap
#include "util.hh"             // for rewriteStrings

namespace nix {

std::map<StorePath, StorePath> makeContentAddressed(
    Store & srcStore,
    Store & dstStore,
    const StorePathSet & storePaths)
{
    StorePathSet closure;
    srcStore.computeFSClosure(storePaths, closure);

    auto paths = srcStore.topoSortPaths(closure);

    std::reverse(paths.begin(), paths.end());

    std::map<StorePath, StorePath> remappings;

    for (auto & path : paths) {
        auto pathS = srcStore.printStorePath(path);
        auto oldInfo = srcStore.queryPathInfo(path);
        std::string oldHashPart(path.hashPart());

        StringSink sink;
        srcStore.narFromPath(path, sink);

        StringMap rewrites;

        StorePathSet references;
        bool hasSelfReference = false;
        for (auto & ref : oldInfo->references) {
            if (ref == path)
                hasSelfReference = true;
            else {
                auto i = remappings.find(ref);
                auto replacement = i != remappings.end() ? i->second : ref;
                // FIXME: warn about unremapped paths?
                if (replacement != ref)
                    rewrites.insert_or_assign(srcStore.printStorePath(ref), srcStore.printStorePath(replacement));
                references.insert(std::move(replacement));
            }
        }

        sink.s = rewriteStrings(sink.s, rewrites);

        HashModuloSink hashModuloSink(htSHA256, oldHashPart);
        hashModuloSink(sink.s);

        auto narModuloHash = hashModuloSink.finish().first;

        auto dstPath = dstStore.makeFixedOutputPath(
            FileIngestionMethod::Recursive, narModuloHash, path.name(), references, hasSelfReference);

        printInfo("rewriting '%s' to '%s'", pathS, srcStore.printStorePath(dstPath));

        StringSink sink2;
        RewritingSink rsink2(oldHashPart, std::string(dstPath.hashPart()), sink2);
        rsink2(sink.s);
        rsink2.flush();

        ValidPathInfo info { dstPath, hashString(htSHA256, sink2.s) };
        info.references = std::move(references);
        if (hasSelfReference) info.references.insert(info.path);
        info.narSize = sink.s.size();
        info.ca = FixedOutputHash {
            .method = FileIngestionMethod::Recursive,
            .hash = narModuloHash,
        };

        StringSource source(sink2.s);
        dstStore.addToStore(info, source);

        remappings.insert_or_assign(std::move(path), std::move(info.path));
    }

    return remappings;
}

}
