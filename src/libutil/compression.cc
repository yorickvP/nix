#include "compression.hh"
#include "tarfile.hh"
#include "util.hh"
#include "finally.hh"
#include "logging.hh"

#include <lzma.h>
#include <bzlib.h>
#include <archive.h>
#include <archive_entry.h>
#include <cstdio>
#include <cstring>

#include <brotli/decode.h>
#include <brotli/encode.h>

#include <iostream>

namespace nix {

// Don't feed brotli too much at once.
struct ChunkedCompressionSink : CompressionSink
{
    uint8_t outbuf[32 * 1024];

    void write(const unsigned char * data, size_t len) override
    {
        const size_t CHUNK_SIZE = sizeof(outbuf) << 2;
        while (len) {
            size_t n = std::min(CHUNK_SIZE, len);
            writeInternal(data, n);
            data += n;
            len -= n;
        }
    }

    virtual void writeInternal(const unsigned char * data, size_t len) = 0;
};

struct ArchiveDecompressionSource : Source
{
    std::unique_ptr<TarArchive> archive;
    Source & src;
    bool isOpen = false;
    ArchiveDecompressionSource(Source & src) : src(src) {}
    ~ArchiveDecompressionSource() override {}
    size_t read(unsigned char * data, size_t len) override {
        struct archive_entry* ae;
        if (!isOpen) {
            archive = std::make_unique<TarArchive>(src, true);
            this->archive->check(archive_read_next_header(this->archive->archive, &ae), "Failed to read header (%s)");
            isOpen = true;
        }
        ssize_t result = archive_read_data(this->archive->archive, data, len);
        if (result > 0) return result;
        this->archive->check(result, "Failed to read compressed data (%s)");
        return result;
    }
};
struct ArchiveCompressionSink : CompressionSink
{
    Sink & nextSink;
    struct archive* archive;
    ArchiveCompressionSink(Sink & nextSink, std::string format, bool parallel) : nextSink(nextSink) {
        archive = archive_write_new();
        if (!archive) throw Error("failed to initialize libarchive");
        check(archive_write_add_filter_by_name(archive, format.c_str()), "Couldn't initialize compression (%s)");
        check(archive_write_set_format_raw(archive));
        if (format == "xz" && parallel) {
            check(archive_write_set_filter_option(archive, format.c_str(), "threads", "0"));
        }
        check(archive_write_set_bytes_per_block(archive, 0));
        check(archive_write_set_bytes_in_last_block(archive, 1));
        check(archive_write_open(archive, this, NULL, ArchiveCompressionSink::callback_write, NULL));
        struct archive_entry *ae = archive_entry_new();
        archive_entry_set_filetype(ae, AE_IFREG);
        check(archive_write_header(archive, ae));
        archive_entry_free(ae);
    }
    ~ArchiveCompressionSink() override {
        if (archive) archive_write_free(archive);
    }
    void finish() override {
        flush();
        check(archive_write_close(archive));
    }
    void check(int err, const char *reason="Failed to compress (%s)") {
        if (err == ARCHIVE_EOF)
            throw EndOfFile("reached end of archive");
        else if (err != ARCHIVE_OK)
            throw Error(reason, archive_error_string(this->archive));
    }
    void write(const unsigned char *data, size_t len) override {
        ssize_t result = archive_write_data(archive, data, len);
        if (result <= 0) check(result);
    }
private:
    static ssize_t callback_write(struct archive *archive, void *_self, const void *buffer, size_t length) {
        ArchiveCompressionSink *self = (ArchiveCompressionSink *)_self;
        self->nextSink((const unsigned char*)buffer, length);
        return length;
    }
};

struct NoneSink : CompressionSink
{
    Sink & nextSink;
    NoneSink(Sink & nextSink) : nextSink(nextSink) { }
    void finish() override { flush(); }
    void write(const unsigned char * data, size_t len) override { nextSink(data, len); }
};

struct XzDecompressionSink : CompressionSink
{
    Sink & nextSink;
    uint8_t outbuf[BUFSIZ];
    lzma_stream strm = LZMA_STREAM_INIT;
    bool finished = false;

    XzDecompressionSink(Sink & nextSink) : nextSink(nextSink)
    {
        lzma_ret ret = lzma_stream_decoder(
            &strm, UINT64_MAX, LZMA_CONCATENATED);
        if (ret != LZMA_OK)
            throw CompressionError("unable to initialise lzma decoder");

        strm.next_out = outbuf;
        strm.avail_out = sizeof(outbuf);
    }

    ~XzDecompressionSink()
    {
        lzma_end(&strm);
    }

    void finish() override
    {
        CompressionSink::flush();
        write(nullptr, 0);
    }

    void write(const unsigned char * data, size_t len) override
    {
        strm.next_in = data;
        strm.avail_in = len;

        while (!finished && (!data || strm.avail_in)) {
            checkInterrupt();

            lzma_ret ret = lzma_code(&strm, data ? LZMA_RUN : LZMA_FINISH);
            if (ret != LZMA_OK && ret != LZMA_STREAM_END)
                throw CompressionError("error %d while decompressing xz file", ret);

            finished = ret == LZMA_STREAM_END;

            if (strm.avail_out < sizeof(outbuf) || strm.avail_in == 0) {
                nextSink(outbuf, sizeof(outbuf) - strm.avail_out);
                strm.next_out = outbuf;
                strm.avail_out = sizeof(outbuf);
            }
        }
    }
};

struct BzipDecompressionSink : ChunkedCompressionSink
{
    Sink & nextSink;
    bz_stream strm;
    bool finished = false;

    BzipDecompressionSink(Sink & nextSink) : nextSink(nextSink)
    {
        memset(&strm, 0, sizeof(strm));
        int ret = BZ2_bzDecompressInit(&strm, 0, 0);
        if (ret != BZ_OK)
            throw CompressionError("unable to initialise bzip2 decoder");

        strm.next_out = (char *) outbuf;
        strm.avail_out = sizeof(outbuf);
    }

    ~BzipDecompressionSink()
    {
        BZ2_bzDecompressEnd(&strm);
    }

    void finish() override
    {
        flush();
        write(nullptr, 0);
    }

    void writeInternal(const unsigned char * data, size_t len) override
    {
        assert(len <= std::numeric_limits<decltype(strm.avail_in)>::max());

        strm.next_in = (char *) data;
        strm.avail_in = len;

        while (strm.avail_in) {
            checkInterrupt();

            int ret = BZ2_bzDecompress(&strm);
            if (ret != BZ_OK && ret != BZ_STREAM_END)
                throw CompressionError("error while decompressing bzip2 file");

            finished = ret == BZ_STREAM_END;

            if (strm.avail_out < sizeof(outbuf) || strm.avail_in == 0) {
                nextSink(outbuf, sizeof(outbuf) - strm.avail_out);
                strm.next_out = (char *) outbuf;
                strm.avail_out = sizeof(outbuf);
            }
        }
    }
};

struct BrotliDecompressionSink : ChunkedCompressionSink
{
    Sink & nextSink;
    BrotliDecoderState * state;
    bool finished = false;

    BrotliDecompressionSink(Sink & nextSink) : nextSink(nextSink)
    {
        state = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
        if (!state)
            throw CompressionError("unable to initialize brotli decoder");
    }

    ~BrotliDecompressionSink()
    {
        BrotliDecoderDestroyInstance(state);
    }

    void finish() override
    {
        flush();
        writeInternal(nullptr, 0);
    }

    void writeInternal(const unsigned char * data, size_t len) override
    {
        const uint8_t * next_in = data;
        size_t avail_in = len;
        uint8_t * next_out = outbuf;
        size_t avail_out = sizeof(outbuf);

        while (!finished && (!data || avail_in)) {
            checkInterrupt();

            if (!BrotliDecoderDecompressStream(state,
                    &avail_in, &next_in,
                    &avail_out, &next_out,
                    nullptr))
                throw CompressionError("error while decompressing brotli file");

            if (avail_out < sizeof(outbuf) || avail_in == 0) {
                nextSink(outbuf, sizeof(outbuf) - avail_out);
                next_out = outbuf;
                avail_out = sizeof(outbuf);
            }

            finished = BrotliDecoderIsFinished(state);
        }
    }
};

ref<std::string> decompress(const std::string & method, const std::string & in)
{
    StringSink ssink;
    auto sink = makeDecompressionSink(method, ssink);
    (*sink)(in);
    sink->finish();
    return ssink.s;
}

ref<CompressionSink> makeDecompressionSink(const std::string & method, Sink & nextSink)
{
    if (method == "none" || method == "")
        return make_ref<NoneSink>(nextSink);
    else if (method == "xz")
        return make_ref<XzDecompressionSink>(nextSink);
    else if (method == "bzip2")
        return make_ref<BzipDecompressionSink>(nextSink);
    else if (method == "br")
        return make_ref<BrotliDecompressionSink>(nextSink);
    else
        throw UnknownCompressionMethod("unknown compression method '%s'", method);
}

struct BrotliCompressionSink : ChunkedCompressionSink
{
    Sink & nextSink;
    uint8_t outbuf[BUFSIZ];
    BrotliEncoderState *state;
    bool finished = false;

    BrotliCompressionSink(Sink & nextSink) : nextSink(nextSink)
    {
        state = BrotliEncoderCreateInstance(nullptr, nullptr, nullptr);
        if (!state)
            throw CompressionError("unable to initialise brotli encoder");
    }

    ~BrotliCompressionSink()
    {
        BrotliEncoderDestroyInstance(state);
    }

    void finish() override
    {
        flush();
        writeInternal(nullptr, 0);
    }

    void writeInternal(const unsigned char * data, size_t len) override
    {
        const uint8_t * next_in = data;
        size_t avail_in = len;
        uint8_t * next_out = outbuf;
        size_t avail_out = sizeof(outbuf);

        while (!finished && (!data || avail_in)) {
            checkInterrupt();

            if (!BrotliEncoderCompressStream(state,
                    data ? BROTLI_OPERATION_PROCESS : BROTLI_OPERATION_FINISH,
                    &avail_in, &next_in,
                    &avail_out, &next_out,
                    nullptr))
                throw CompressionError("error while compressing brotli compression");

            if (avail_out < sizeof(outbuf) || avail_in == 0) {
                nextSink(outbuf, sizeof(outbuf) - avail_out);
                next_out = outbuf;
                avail_out = sizeof(outbuf);
            }

            finished = BrotliEncoderIsFinished(state);
        }
    }
};
std::unique_ptr<Source> makeDecompressionSource(Source & prev) {
    return std::unique_ptr<Source>(new ArchiveDecompressionSource(prev));
}

ref<CompressionSink> makeCompressionSink(const std::string & method, Sink & nextSink, const bool parallel)
{
    std::vector<std::string> la_supports = {
        "bzip2", "compress", "grzip", "gzip", "lrzip", "lz4", "lzip", "lzma", "lzop", "xz", "zstd"
    };
    if (std::find(la_supports.begin(), la_supports.end(), method) != la_supports.end()) {
        return make_ref<ArchiveCompressionSink>(nextSink, method, parallel);
    }
    if (method == "none")
        return make_ref<NoneSink>(nextSink);
    else if (method == "br")
        return make_ref<BrotliCompressionSink>(nextSink);
    else
        throw UnknownCompressionMethod(format("unknown compression method '%s'") % method);
}

ref<std::string> compress(const std::string & method, const std::string & in, const bool parallel)
{
    StringSink ssink;
    auto sink = makeCompressionSink(method, ssink, parallel);
    (*sink)(in);
    sink->finish();
    return ssink.s;
}

}
