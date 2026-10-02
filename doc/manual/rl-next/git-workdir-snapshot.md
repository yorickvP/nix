---
synopsis: "Git working directories are snapshotted when fetched"
---

When Nix fetches a local Git working directory (e.g. a flake in a Git repository, or `builtins.fetchGit ./.`), it now copies the working directory into its Git cache and evaluates from that copy.
Previously, it read the working directory directly, and only copied it to the Nix store when needed.
So modifying or deleting the working directory during evaluation could cause errors like `the contents have changed`, or files not being found, or other working directories with the same contents to break.

Copying is incremental: files that Git considers unchanged, and directories that only contain such files, are copied from the repository rather than read from disk.
The first time, this takes a while for large repositories.

This changes the contents of some working directories.
Files that Git considers unchanged from `HEAD` now have the contents and permissions they have in `HEAD`, rather than those on disk.
These differ if Git converts files on checkout or ignores some differences, for instance with:

- the `text`, `eol` or `ident` attributes, or `core.autocrlf` (e.g. files with CRLF line endings in a repository checked out by Git for Windows),
- `core.fileMode = false` (e.g. on a FAT file system or under `/mnt` in WSL, where every file appears to be executable),
- `core.symlinks = false`.

As a result, a clean working directory now always has the same contents as its `HEAD` commit.
This also fixes lock files for such repositories, whose recorded NAR hash didn't match the commit, and therefore couldn't be fetched on other machines.
However, the store path of the working directory changes.

Files with a `filter` attribute, like those stored in Git LFS, are still read from disk, since their contents in Git (a pointer) are unrelated to the file.
With `lfs = true`, files stored in Git LFS get the contents that their pointer refers to, taken from the working directory, the local Git LFS store or the LFS server, after checking that they match the pointer.
