#pragma once

#include "nix/fetchers/filtering-source-accessor.hh"
#include "nix/fetchers/merkle-tar-adapter.hh"

namespace nix {

namespace fetchers {
struct PublicKey;
struct Settings;
} // namespace fetchers

struct GitAccessorOptions
{
    bool exportIgnore = false;
    bool smudgeLfs = false;
};

struct GitRepo
{
    virtual ~GitRepo() = default;

    struct Options
    {
        bool create = false;
        bool bare = false;
        bool packfilesOnly = false;
    };

    static ref<GitRepo> openRepo(const std::filesystem::path & path, Options options);

    virtual uint64_t getLastModified(const Hash & rev) = 0;

    virtual bool isShallow() = 0;

    /* Return the commit hash to which a ref points. */
    virtual Hash resolveRef(std::string ref) = 0;

    virtual void setRemote(const std::string & name, const std::string & url) = 0;

    /**
     * Info about a submodule.
     */
    struct Submodule
    {
        CanonPath path;
        std::string url;
        std::string branch;
    };

    struct WorkdirInfo
    {
        bool isDirty = false;

        /* The checked out commit, or nullopt if there are no commits
           in the repo yet. */
        std::optional<Hash> headRev;

        /* All files in the working directory that are unchanged,
           modified or added, but excluding deleted files. */
        std::set<CanonPath> files;

        /* All modified or added files. */
        std::set<CanonPath> dirtyFiles;

        /* The deleted files. */
        std::set<CanonPath> deletedFiles;

        /* The submodules listed in .gitmodules of this workdir. */
        std::vector<Submodule> submodules;
    };

    virtual WorkdirInfo getWorkdirInfo() = 0;

    static WorkdirInfo getCachedWorkdirInfo(const std::filesystem::path & path);

    /* Drop all entries from the getCachedWorkdirInfo() cache. */
    static void invalidateWorkdirInfoCache();

    /* Get the ref that HEAD points to. */
    virtual std::optional<std::string> getWorkdirRef() = 0;

    /**
     * Return the submodules of this repo at the indicated revision,
     * along with the revision of each submodule.
     */
    virtual std::vector<std::tuple<Submodule, Hash>> getSubmodules(const Hash & rev, bool exportIgnore) = 0;

    virtual std::string resolveSubmoduleUrl(const std::string & url) = 0;

    virtual bool hasObject(const Hash & oid) = 0;

    virtual ref<SourceAccessor>
    getAccessor(const Hash & rev, const GitAccessorOptions & options, std::string displayPrefix) = 0;

    virtual ref<SourceAccessor> getAccessor(
        const WorkdirInfo & wd, const GitAccessorOptions & options, MakeNotAllowedError makeNotAllowedError) = 0;

    struct WorkdirSnapshot
    {
        /**
         * The Git tree in the destination repository that holds the
         * snapshot.
         */
        Hash treeHash;

        ref<SourceAccessor> accessor;
    };

    /**
     * Copy the working directory described by `wd` into `dest`
     * (normally the tarball cache) as a Git tree, and return an
     * accessor for that tree. Unlike `getAccessor(wd, options, ...)`,
     * the snapshot doesn't change if the working directory is modified
     * or deleted afterwards.
     *
     * The snapshot has the same files as `getAccessor(wd, options,
     * ...)`. Files that Git considers unchanged from HEAD are not read
     * from disk: their blobs, and entire unchanged subtrees, are copied
     * from this repository. So for those files, the snapshot has what
     * Git would commit, e.g. after normalizing line endings, and the
     * permissions and file type in HEAD (which Git may not check, see
     * `core.fileMode` and `core.symlinks`). This means that a clean
     * working directory has the same contents as HEAD. The exception
     * are files that have a `filter` attribute
     * (like Git LFS), since their blob may be unrelated to the file
     * (like a pointer to it); those are read from disk. Other files are
     * read from disk as is.
     *
     * If `options.smudgeLfs` is set, files stored in Git LFS get the
     * contents that their pointer refers to, like when fetching a
     * commit: from the working directory, Git LFS's local object store
     * or the LFS server, whichever is first to have contents that match
     * the pointer. The resulting blobs are recorded in the fetcher
     * cache of `settings`, so they don't have to be read again.
     *
     * The returned accessor reads from the snapshot, but it reports
     * paths in the working directory (for error messages and `nix
     * edit`), and it throws `makeNotAllowedError` for paths that are not
     * tracked by Git.
     */
    virtual WorkdirSnapshot snapshotWorkdir(
        const fetchers::Settings & settings,
        GitRepo & dest,
        const WorkdirInfo & wd,
        const GitAccessorOptions & options,
        MakeNotAllowedError makeNotAllowedError) = 0;

    virtual void flush() = 0;

    virtual std::unique_ptr<merkle::DirectorySinkWithFinalize> makeDirectorySink() = 0;
    virtual std::unique_ptr<merkle::RegularFileSinkWithFinalize> makeRegularFileSink() = 0;

    virtual void fetch(const std::string & url, const std::string & refspec, bool shallow) = 0;

    /**
     * Verify that commit `rev` is signed by one of the keys in
     * `publicKeys`. Throw an error if it isn't.
     */
    virtual void verifyCommit(const Hash & rev, const std::vector<fetchers::PublicKey> & publicKeys) = 0;

    /**
     * Given a Git tree hash, compute the hash of its NAR
     * serialisation. This is memoised on-disk.
     */
    virtual Hash treeHashToNarHash(const fetchers::Settings & settings, const Hash & treeHash) = 0;

    /**
     * If the specified Git object is a directory with a single entry
     * that is a directory, return the ID of that object.
     * Otherwise, return the passed ID unchanged.
     */
    virtual Hash dereferenceSingletonDirectory(const Hash & oid) = 0;
};

struct GitRepoPool : merkle::FileSinkBuilder
{
    virtual ~GitRepoPool() = default;

    static ref<GitRepoPool> create(const std::filesystem::path & path, GitRepo::Options options);

    virtual uint64_t getRevCount(const Hash & rev) = 0;
};

// A helper to ensure that we don't leak objects returned by libgit2.
template<typename T>
struct Setter
{
    T & t;
    typename T::pointer p = nullptr;

    Setter(T & t)
        : t(t)
    {
    }

    ~Setter()
    {
        if (p)
            t = T(p);
    }

    operator typename T::pointer *()
    {
        return &p;
    }
};

/**
 * Checks that the string can be a valid git reference, branch or tag name.
 * Accepts shorthand references (one-level refnames are allowed), pseudorefs
 * like `HEAD`.
 *
 * @note This is a coarse test to make sure that the refname is at least something
 * that Git can make sense of.
 */
bool isLegalRefName(const std::string & refName);

} // namespace nix
