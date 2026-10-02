#!/usr/bin/env bash

# Fetching a Git working directory takes a snapshot of it. The evaluator
# only copies the snapshot to the store when needed, so it must not
# depend on the working directory afterwards.

source ../common.sh

requireGit

opts=(--impure --option allow-unsafe-native-code-during-evaluation true)

# A repo with a committed file and an uncommitted change to it.
makeDirtyRepo() {
    local repo="$1"
    createGitRepo "$repo"
    echo hello > "$repo/file"
    git -C "$repo" add file
    git -C "$repo" commit -m init
    echo world > "$repo/file"
}

# Two working directories with the same contents get the same store
# path. Deleting the first one must not break the second one.
repoA=$TEST_ROOT/repoA
repoB=$TEST_ROOT/repoB

deleteA="
  let
    a = builtins.fetchTree \"git+file://$repoA\";
    b = builtins.fetchTree \"git+file://$repoB\";
  in
    assert a.outPath == b.outPath;
    builtins.seq (builtins.exec [ \"sh\" \"-c\" \"rm -rf $repoA && echo null\" ]) b
"

makeDirtyRepo "$repoA"
makeDirtyRepo "$repoB"
[[ $(nix eval "${opts[@]}" --raw --expr "builtins.readFile (($deleteA) + \"/file\")") = world ]]
[[ ! -e $repoA ]]

makeDirtyRepo "$repoA"
path=$(nix eval "${opts[@]}" --raw --expr "($deleteA).outPath")
[[ $(cat "$path/file") = world ]]

# Modifying the working directory during evaluation doesn't affect the
# snapshot, whether it's read lazily or copied to the store.
repo=$TEST_ROOT/repo

modify="
  let
    src = builtins.fetchTree \"git+file://$repo\";
  in
    builtins.seq src (builtins.seq (builtins.exec [ \"sh\" \"-c\" \"echo modified > $repo/file && echo null\" ]) src)
"

makeDirtyRepo "$repo"
[[ $(nix eval "${opts[@]}" --raw --expr "builtins.readFile (($modify) + \"/file\")") = world ]]
[[ $(cat "$repo/file") = modified ]]

makeDirtyRepo "$repo"
path=$(nix eval "${opts[@]}" --raw --expr "($modify).outPath")
[[ $(cat "$path/file") = world ]]

# Permissions come from the working directory.
makeDirtyRepo "$repo"
chmod +x "$repo/file"
path=$(nix eval --impure --raw --expr "(builtins.fetchTree \"git+file://$repo\").outPath")
[[ -x $path/file ]]

readFile() {
    nix eval --impure --expr "builtins.readFile ((builtins.fetchTree \"git+file://$repo\") + \"/$1\")"
}

# Files that Git considers unchanged have their committed contents, even
# if Git converted them on checkout, so a clean working directory has
# the same contents as HEAD.
createGitRepo "$repo"
printf 'a\nb\n' > "$repo/crlf.txt"
printf '$Id$\n' > "$repo/ident.txt"
cat > "$repo/.gitattributes" <<EOF
crlf.txt text eol=crlf
ident.txt ident
EOF
git -C "$repo" add .
git -C "$repo" commit -m init
rm "$repo"/*.txt
git -C "$repo" checkout -- .
[[ -z $(git -C "$repo" status --porcelain) ]]
[[ $(cat "$repo/crlf.txt") = $'a\r\nb\r' ]]
[[ $(cat "$repo/ident.txt") != '$Id$' ]]

[[ $(readFile crlf.txt) = '"a\nb\n"' ]]
[[ $(readFile ident.txt) = '"$Id$\n"' ]]
rev=$(git -C "$repo" rev-parse HEAD)
[[ $(nix eval --impure --raw --expr "(builtins.fetchTree \"git+file://$repo\").narHash") \
   = $(nix eval --raw --expr "(builtins.fetchTree { type = \"git\"; url = \"file://$repo\"; rev = \"$rev\"; }).narHash") ]]

# Except files with a filter (like Git LFS), whose blob may be unrelated
# to the file, so those are read from disk.
createGitRepo "$repo"
git -C "$repo" config filter.upper.clean "tr A-Z a-z"
git -C "$repo" config filter.upper.smudge "tr a-z A-Z"
echo 'file.up filter=upper' > "$repo/.gitattributes"
echo hello > "$repo/file.up"
git -C "$repo" add .
git -C "$repo" commit -m init
rm "$repo/file.up"
git -C "$repo" checkout -- .
# Make sure that Git's cached stat information is up to date, so that
# Git (and libgit2) consider the file unchanged without looking at it.
touch -d '1 minute ago' "$repo/file.up"
git -C "$repo" update-index --refresh
[[ -z $(git -C "$repo" status --porcelain) ]]
[[ $(cat "$repo/file.up") = HELLO ]]

[[ $(readFile file.up) = '"HELLO\n"' ]]

# A clean working directory is the same as HEAD, also with exportIgnore.
sameAsHead() {
    local attrs="type = \"git\"; url = \"file://$repo\"; $1"
    local rev
    rev=$(git -C "$repo" rev-parse HEAD)
    [[ $(nix eval --impure --raw --expr "(builtins.fetchTree { $attrs }).narHash") \
       = $(nix eval --raw --expr "(builtins.fetchTree { $attrs rev = \"$rev\"; }).narHash") ]]
}

createGitRepo "$repo"
mkdir -p "$repo/sub" "$repo/other"
echo a > "$repo/a"
echo ignored > "$repo/sub/ignored"
echo kept > "$repo/sub/kept"
echo x > "$repo/other/x"
echo 'ignored export-ignore' > "$repo/sub/.gitattributes"
git -C "$repo" add .
git -C "$repo" commit -m init
path=$(nix eval --impure --raw --expr "(builtins.fetchTree { type = \"git\"; url = \"file://$repo\"; exportIgnore = true; }).outPath")
[[ ! -e $path/sub/ignored ]]
[[ -e $path/sub/kept ]]
[[ -e $path/other/x ]]
sameAsHead "exportIgnore = true;"
echo '/other export-ignore' > "$repo/.gitattributes"
git -C "$repo" add .
git -C "$repo" commit -m 'ignore other'
path=$(nix eval --impure --raw --expr "(builtins.fetchTree { type = \"git\"; url = \"file://$repo\"; exportIgnore = true; }).outPath")
[[ ! -e $path/other ]]
[[ ! -e $path/sub/ignored ]]
sameAsHead "exportIgnore = true;"
sameAsHead ""

# Git can ignore differences in permissions and symlinks, in which case
# the working directory is still the same as HEAD.
createGitRepo "$repo"
echo '#! /bin/sh' > "$repo/run"
chmod +x "$repo/run"
ln -s run "$repo/link"
git -C "$repo" add .
git -C "$repo" commit -m init
git -C "$repo" config core.fileMode false
git -C "$repo" config core.symlinks false
chmod -x "$repo/run"
rm "$repo/link"
printf run > "$repo/link"
[[ -z $(git -C "$repo" status --porcelain) ]]
path=$(nix eval --impure --raw --expr "(builtins.fetchTree \"git+file://$repo\").outPath")
[[ -x $path/run ]]
[[ $(readlink "$path/link") = run ]]
sameAsHead ""

# The evaluation cache must not return a stale `rev` for a commit with
# the same tree.
flake=$TEST_ROOT/flake
createGitRepo "$flake"
cat > "$flake/flake.nix" <<EOF
{ outputs = { self }: { rev = self.rev; }; }
EOF
git -C "$flake" add flake.nix
git -C "$flake" commit -m one
[[ $(nix eval --raw "$flake#rev") = $(git -C "$flake" rev-parse HEAD) ]]
git -C "$flake" commit --allow-empty -m two
[[ $(nix eval --raw "$flake#rev") = $(git -C "$flake" rev-parse HEAD) ]]

# Git LFS. Instead of requiring git-lfs, emulate its clean filter, which
# turns files into pointers (and leaves pointers alone).
cat > "$TEST_ROOT/lfs-clean" <<'EOF'
#!/bin/sh
tmp=$(mktemp)
cat > "$tmp"
if head -c 8 "$tmp" | grep -q '^version '; then
  cat "$tmp"
else
  printf 'version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %s\n' \
    "$(nix-hash --type sha256 --flat "$tmp")" "$(($(wc -c < "$tmp")))"
fi
rm "$tmp"
EOF
chmod +x "$TEST_ROOT/lfs-clean"

createGitRepo "$repo"
git -C "$repo" config filter.lfs.clean "$TEST_ROOT/lfs-clean"
echo '*.bin filter=lfs -text' > "$repo/.gitattributes"
echo 'hello from lfs' > "$repo/big.bin"
git -C "$repo" add .
git -C "$repo" commit -m init
oid=$(nix-hash --type sha256 --flat "$repo/big.bin")
lfsObject=$repo/.git/lfs/objects/${oid:0:2}/${oid:2:2}/$oid
pointer=$(git -C "$repo" cat-file blob HEAD:big.bin)
[[ $pointer =~ "oid sha256:$oid" ]]

readLfs() {
    nix eval --impure --raw --expr "builtins.readFile ((builtins.fetchTree { type = \"git\"; url = \"file://$repo\"; lfs = $1; }) + \"/big.bin\")"
}

clearFetcherCache() {
    rm -rf "${TEST_HOME:?}/.cache/nix"
}

# The file has been checked out, so its contents come from the working
# directory, whether or not we ask for LFS files.
[[ -z $(git -C "$repo" status --porcelain) ]]
[[ $(readLfs true) = 'hello from lfs' ]]
[[ $(readLfs false) = 'hello from lfs' ]]

# The file hasn't been checked out (i.e. Git checked out the pointer,
# since there's no smudge filter). Without `lfs`, we get the pointer, as
# before. With `lfs`, we get the contents from Git LFS's local store.
rm "$repo/big.bin"
git -C "$repo" checkout -- big.bin
[[ $(cat "$repo/big.bin") = "$pointer" ]]
[[ -z $(git -C "$repo" status --porcelain) ]]
mkdir -p "$(dirname "$lfsObject")"
echo 'hello from lfs' > "$lfsObject"
clearFetcherCache
[[ $(readLfs false) = "$pointer" ]]
[[ $(readLfs true) = 'hello from lfs' ]]

# Once we have the contents, we don't need the store anymore.
rm "$lfsObject"
[[ $(readLfs true) = 'hello from lfs' ]]

# Contents that don't match the pointer are not used. Since there is no
# LFS server, there are no contents to use.
echo 'corrupted' > "$lfsObject"
clearFetcherCache
expectStderr 1 readLfs true | grepQuiet "Git LFS file '$repo/big.bin' has not been checked out and is not in the local Git LFS store"
