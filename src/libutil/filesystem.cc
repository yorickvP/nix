#include <sys/time.h>          // for timeval, lutimes
#include <sys/stat.h>          // for stat, mkdir, mode_t, st_atime, st_mtime
#include <errno.h>             // for EEXIST, EXDEV, errno
#include <stdlib.h>            // for mkstemp
#include <unistd.h>            // for getpid, symlink
#include <boost/format.hpp>    // for basic_altstringbuf<>::int_type, basic_...
#include <filesystem>          // for path, directory_entry, operator|, remove
#include <chrono>              // for filesystem
#include <ctime>               // for time_t
#include <optional>            // for optional
#include <sstream>             // for basic_stringbuf<>::int_type, basic_str...
#include <string>              // for string, allocator, basic_string, char_...
#include <system_error>        // for error_code
#include <type_traits>         // for remove_reference<>::type
#include <utility>             // for move, pair

#include "finally.hh"          // for Finally
#include "util.hh"             // for canonPath, getEnv, AutoCloseFD, baseNa...
#include "types.hh"            // for Path
#include "error.hh"    // for SysError, Error
#include "fmt.hh"      // for fmt, format
#include "logging.hh"  // for warn

namespace fs = std::filesystem;

namespace nix {

static Path tempName(Path tmpRoot, const Path & prefix, bool includePid,
    int & counter)
{
    tmpRoot = canonPath(tmpRoot.empty() ? getEnv("TMPDIR").value_or("/tmp") : tmpRoot, true);
    if (includePid)
        return (format("%1%/%2%-%3%-%4%") % tmpRoot % prefix % getpid() % counter++).str();
    else
        return (format("%1%/%2%-%3%") % tmpRoot % prefix % counter++).str();
}

Path createTempDir(const Path & tmpRoot, const Path & prefix,
    bool includePid, bool useGlobalCounter, mode_t mode)
{
    static int globalCounter = 0;
    int localCounter = 0;
    int & counter(useGlobalCounter ? globalCounter : localCounter);

    while (1) {
        checkInterrupt();
        Path tmpDir = tempName(tmpRoot, prefix, includePid, counter);
        if (mkdir(tmpDir.c_str(), mode) == 0) {
#if __FreeBSD__
            /* Explicitly set the group of the directory.  This is to
               work around around problems caused by BSD's group
               ownership semantics (directories inherit the group of
               the parent).  For instance, the group of /tmp on
               FreeBSD is "wheel", so all directories created in /tmp
               will be owned by "wheel"; but if the user is not in
               "wheel", then "tar" will fail to unpack archives that
               have the setgid bit set on directories. */
            if (chown(tmpDir.c_str(), (uid_t) -1, getegid()) != 0)
                throw SysError("setting group of directory '%1%'", tmpDir);
#endif
            return tmpDir;
        }
        if (errno != EEXIST)
            throw SysError("creating directory '%1%'", tmpDir);
    }
}


std::pair<AutoCloseFD, Path> createTempFile(const Path & prefix)
{
    Path tmpl(getEnv("TMPDIR").value_or("/tmp") + "/" + prefix + ".XXXXXX");
    // Strictly speaking, this is UB, but who cares...
    // FIXME: use O_TMPFILE.
    AutoCloseFD fd(mkstemp((char *) tmpl.c_str()));
    if (!fd)
        throw SysError("creating temporary file '%s'", tmpl);
    closeOnExec(fd.get());
    return {std::move(fd), tmpl};
}

void createSymlink(const Path & target, const Path & link,
    std::optional<time_t> mtime)
{
    if (symlink(target.c_str(), link.c_str()))
        throw SysError("creating symlink from '%1%' to '%2%'", link, target);
    if (mtime) {
        struct timeval times[2];
        times[0].tv_sec = *mtime;
        times[0].tv_usec = 0;
        times[1].tv_sec = *mtime;
        times[1].tv_usec = 0;
        if (lutimes(link.c_str(), times))
            throw SysError("setting time of symlink '%s'", link);
    }
}

void replaceSymlink(const Path & target, const Path & link,
    std::optional<time_t> mtime)
{
    for (unsigned int n = 0; true; n++) {
        Path tmp = canonPath(fmt("%s/.%d_%s", dirOf(link), n, baseNameOf(link)));

        try {
            createSymlink(target, tmp, mtime);
        } catch (SysError & e) {
            if (e.errNo == EEXIST) continue;
            throw;
        }

        renameFile(tmp, link);

        break;
    }
}

void setWriteTime(const fs::path & p, const struct stat & st)
{
    struct timeval times[2];
    times[0] = {
        .tv_sec = st.st_atime,
        .tv_usec = 0,
    };
    times[1] = {
        .tv_sec = st.st_mtime,
        .tv_usec = 0,
    };
    if (lutimes(p.c_str(), times) != 0)
        throw SysError("changing modification time of '%s'", p);
}

void copy(const fs::directory_entry & from, const fs::path & to, bool andDelete)
{
    // TODO: Rewrite the `is_*` to use `symlink_status()`
    auto statOfFrom = lstat(from.path().c_str());
    auto fromStatus = from.symlink_status();

    // Mark the directory as writable so that we can delete its children
    if (andDelete && fs::is_directory(fromStatus)) {
        fs::permissions(from.path(), fs::perms::owner_write, fs::perm_options::add | fs::perm_options::nofollow);
    }


    if (fs::is_symlink(fromStatus) || fs::is_regular_file(fromStatus)) {
        fs::copy(from.path(), to, fs::copy_options::copy_symlinks | fs::copy_options::overwrite_existing);
    } else if (fs::is_directory(fromStatus)) {
        fs::create_directory(to);
        for (auto & entry : fs::directory_iterator(from.path())) {
            copy(entry, to / entry.path().filename(), andDelete);
        }
    } else {
        throw Error("file '%s' has an unsupported type", from.path());
    }

    setWriteTime(to, statOfFrom);
    if (andDelete) {
        if (!fs::is_symlink(fromStatus))
            fs::permissions(from.path(), fs::perms::owner_write, fs::perm_options::add | fs::perm_options::nofollow);
        fs::remove(from.path());
    }
}

void renameFile(const Path & oldName, const Path & newName)
{
    fs::rename(oldName, newName);
}

void moveFile(const Path & oldName, const Path & newName)
{
    try {
        renameFile(oldName, newName);
    } catch (fs::filesystem_error & e) {
        auto oldPath = fs::path(oldName);
        auto newPath = fs::path(newName);
        // For the move to be as atomic as possible, copy to a temporary
        // directory
        fs::path temp = createTempDir(newPath.parent_path(), "rename-tmp");
        Finally removeTemp = [&]() { fs::remove(temp); };
        auto tempCopyTarget = temp / "copy-target";
        if (e.code().value() == EXDEV) {
            fs::remove(newPath);
            warn("Can’t rename %s as %s, copying instead", oldName, newName);
            copy(fs::directory_entry(oldPath), tempCopyTarget, true);
            renameFile(tempCopyTarget, newPath);
        }
    }
}

}
