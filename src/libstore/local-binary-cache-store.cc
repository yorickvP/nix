#include <errno.h>                // for ENOENT
#include <unistd.h>               // for getpid
#include <boost/format.hpp>       // for basic_altstringbuf<>::int_type, bas...
#include <atomic>                 // for atomic, __atomic_base
#include <istream>                // for basic_iostream
#include <memory>                 // for allocator, shared_ptr
#include <optional>               // for operator==, optional
#include <set>                    // for set
#include <string>                 // for string, operator+, char_traits, bas...
#include <vector>                 // for vector

#include "binary-cache-store.hh"  // for BinaryCacheStoreConfig, BinaryCache...
#include "config.hh"              // for Setting
#include "error.hh"               // for SysError
#include "fmt.hh"                 // for fmt
#include "path.hh"                // for StorePathSet
#include "serialise.hh"           // for StreamToSourceAdapter, Sink (ptr only)
#include "store-api.hh"           // for StoreConfig, RegisterStoreImplement...
#include "types.hh"               // for Path, StringMap
#include "util.hh"                // for createDirs, DirEntry, getEnv, hasSu...

namespace nix {

struct LocalBinaryCacheStoreConfig : virtual BinaryCacheStoreConfig
{
    using BinaryCacheStoreConfig::BinaryCacheStoreConfig;

    const std::string name() override { return "Local Binary Cache Store"; }
};

class LocalBinaryCacheStore : public virtual LocalBinaryCacheStoreConfig, public virtual BinaryCacheStore
{
private:

    Path binaryCacheDir;

public:

    LocalBinaryCacheStore(
        const std::string scheme,
        const Path & binaryCacheDir,
        const Params & params)
        : StoreConfig(params)
        , BinaryCacheStoreConfig(params)
        , LocalBinaryCacheStoreConfig(params)
        , Store(params)
        , BinaryCacheStore(params)
        , binaryCacheDir(binaryCacheDir)
    {
    }

    void init() override;

    std::string getUri() override
    {
        return "file://" + binaryCacheDir;
    }

    static std::set<std::string> uriSchemes();

protected:

    bool fileExists(const std::string & path) override;

    void upsertFile(const std::string & path,
        std::shared_ptr<std::basic_iostream<char>> istream,
        const std::string & mimeType) override
    {
        auto path2 = binaryCacheDir + "/" + path;
        static std::atomic<int> counter{0};
        Path tmp = fmt("%s.tmp.%d.%d", path2, getpid(), ++counter);
        AutoDelete del(tmp, false);
        StreamToSourceAdapter source(istream);
        writeFile(tmp, source);
        renameFile(tmp, path2);
        del.cancel();
    }

    void getFile(const std::string & path, Sink & sink) override
    {
        try {
            readFile(binaryCacheDir + "/" + path, sink);
        } catch (SysError & e) {
            if (e.errNo == ENOENT)
                throw NoSuchBinaryCacheFile("file '%s' does not exist in binary cache", path);
            throw;
        }
    }

    StorePathSet queryAllValidPaths() override
    {
        StorePathSet paths;

        for (auto & entry : readDirectory(binaryCacheDir)) {
            if (entry.name.size() != 40 ||
                !hasSuffix(entry.name, ".narinfo"))
                continue;
            paths.insert(parseStorePath(
                    storeDir + "/" + entry.name.substr(0, entry.name.size() - 8)
                    + "-" + MissingName));
        }

        return paths;
    }

};

void LocalBinaryCacheStore::init()
{
    createDirs(binaryCacheDir + "/nar");
    createDirs(binaryCacheDir + "/" + realisationsPrefix);
    if (writeDebugInfo)
        createDirs(binaryCacheDir + "/debuginfo");
    createDirs(binaryCacheDir + "/log");
    BinaryCacheStore::init();
}

bool LocalBinaryCacheStore::fileExists(const std::string & path)
{
    return pathExists(binaryCacheDir + "/" + path);
}

std::set<std::string> LocalBinaryCacheStore::uriSchemes()
{
    if (getEnv("_NIX_FORCE_HTTP") == "1")
        return {};
    else
        return {"file"};
}

static RegisterStoreImplementation<LocalBinaryCacheStore, LocalBinaryCacheStoreConfig> regLocalBinaryCacheStore;

}
