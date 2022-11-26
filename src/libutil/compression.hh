#pragma once

#include <string>            // for string, basic_string
#include <memory>            // for unique_ptr
#include <string_view>       // for string_view

#include "ref.hh"            // for ref
#include "serialise.hh"      // for BufferedSink, FinishSink
#include "libutil/error.hh"  // for Error, MakeError

namespace nix {

struct CompressionSink : BufferedSink, FinishSink
{
    using BufferedSink::operator ();
    using BufferedSink::write;
    using FinishSink::finish;
};

std::string decompress(const std::string & method, std::string_view in);

std::unique_ptr<FinishSink> makeDecompressionSink(const std::string & method, Sink & nextSink);

std::string compress(const std::string & method, std::string_view in, const bool parallel = false, int level = -1);

ref<CompressionSink> makeCompressionSink(const std::string & method, Sink & nextSink, const bool parallel = false, int level = -1);

MakeError(UnknownCompressionMethod, Error);

MakeError(CompressionError, Error);

}
