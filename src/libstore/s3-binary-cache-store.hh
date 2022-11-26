#pragma once

#include <stdint.h>               // for uint64_t
#include <atomic>                 // for atomic

#include "binary-cache-store.hh"  // for BinaryCacheStore
#include "store-api.hh"           // for Store::Params

namespace nix {

class S3BinaryCacheStore : public virtual BinaryCacheStore
{
protected:

    S3BinaryCacheStore(const Params & params);

public:

    struct Stats
    {
        std::atomic<uint64_t> put{0};
        std::atomic<uint64_t> putBytes{0};
        std::atomic<uint64_t> putTimeMs{0};
        std::atomic<uint64_t> get{0};
        std::atomic<uint64_t> getBytes{0};
        std::atomic<uint64_t> getTimeMs{0};
        std::atomic<uint64_t> head{0};
    };

    virtual const Stats & getS3Stats() = 0;
};

}
