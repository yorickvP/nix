#include <stdint.h>            // for uint64_t, uint32_t
#include <algorithm>           // for equal, reverse
#include <optional>            // for optional
#include <set>                 // for operator!=, set
#include <string>              // for string, allocator, basic_string, opera...
#include <vector>              // for vector

#include "serialise.hh"        // for operator<<, readString, Sink, readInt
#include "store-api.hh"        // for Store, exportMagic, CheckSigsFlag
#include "archive.hh"          // for parseDump, ParseSink
#include "worker-protocol.hh"  // for read, write, Phantom
#include "error.hh"            // for Error
#include "hash.hh"             // for Hash, HashSink, hashString, Base32
#include "path-info.hh"        // for ValidPathInfo
#include "path.hh"             // for StorePath, StorePathSet, StorePaths
#include "ref.hh"              // for ref
#include "repair-flag.hh"      // for NoRepair

namespace nix {

void Store::exportPaths(const StorePathSet & paths, Sink & sink)
{
    auto sorted = topoSortPaths(paths);
    std::reverse(sorted.begin(), sorted.end());

    std::string doneLabel("paths exported");
    //logger->incExpected(doneLabel, sorted.size());

    for (auto & path : sorted) {
        //Activity act(*logger, lvlInfo, format("exporting path '%s'") % path);
        sink << 1;
        exportPath(path, sink);
        //logger->incProgress(doneLabel);
    }

    sink << 0;
}

void Store::exportPath(const StorePath & path, Sink & sink)
{
    auto info = queryPathInfo(path);

    HashSink hashSink(htSHA256);
    TeeSink teeSink(sink, hashSink);

    narFromPath(path, teeSink);

    /* Refuse to export paths that have changed.  This prevents
       filesystem corruption from spreading to other machines.
       Don't complain if the stored hash is zero (unknown). */
    Hash hash = hashSink.currentHash().first;
    if (hash != info->narHash && info->narHash != Hash(info->narHash.type))
        throw Error("hash of path '%s' has changed from '%s' to '%s'!",
            printStorePath(path), info->narHash.to_string(Base32, true), hash.to_string(Base32, true));

    teeSink
        << exportMagic
        << printStorePath(path);
    worker_proto::write(*this, teeSink, info->references);
    teeSink
        << (info->deriver ? printStorePath(*info->deriver) : "")
        << 0;
}

StorePaths Store::importPaths(Source & source, CheckSigsFlag checkSigs)
{
    StorePaths res;
    while (true) {
        auto n = readNum<uint64_t>(source);
        if (n == 0) break;
        if (n != 1) throw Error("input doesn't look like something created by 'nix-store --export'");

        /* Extract the NAR from the source. */
        StringSink saved;
        TeeSource tee { source, saved };
        ParseSink ether;
        parseDump(ether, tee);

        uint32_t magic = readInt(source);
        if (magic != exportMagic)
            throw Error("Nix archive cannot be imported; wrong format");

        auto path = parseStorePath(readString(source));

        //Activity act(*logger, lvlInfo, format("importing path '%s'") % info.path);

        auto references = worker_proto::read(*this, source, Phantom<StorePathSet> {});
        auto deriver = readString(source);
        auto narHash = hashString(htSHA256, saved.s);

        ValidPathInfo info { path, narHash };
        if (deriver != "")
            info.deriver = parseStorePath(deriver);
        info.references = references;
        info.narSize = saved.s.size();

        // Ignore optional legacy signature.
        if (readInt(source) == 1)
            readString(source);

        // Can't use underlying source, which would have been exhausted
        auto source = StringSource(saved.s);
        addToStore(info, source, NoRepair, checkSigs);

        res.push_back(info.path);
    }

    return res;
}

}
