#pragma once

#include <stdint.h>    // for uint64_t
#include <functional>  // for function
#include <string>      // for string, basic_string

#include "ref.hh"      // for ref
#include "types.hh"    // for Path

namespace nix {

struct Source;
class FSAccessor;

/* Return an object that provides access to the contents of a NAR
   file. */
ref<FSAccessor> makeNarAccessor(std::string && nar);

ref<FSAccessor> makeNarAccessor(Source & source);

/* Create a NAR accessor from a NAR listing (in the format produced by
   listNar()). The callback getNarBytes(offset, length) is used by the
   readFile() method of the accessor to get the contents of files
   inside the NAR. */
typedef std::function<std::string(uint64_t, uint64_t)> GetNarBytes;

ref<FSAccessor> makeLazyNarAccessor(
    const std::string & listing,
    GetNarBytes getNarBytes);

class JSONPlaceholder;

/* Write a JSON representation of the contents of a NAR (except file
   contents). */
void listNar(JSONPlaceholder & res, ref<FSAccessor> accessor,
    const Path & path, bool recurse);

}
