#include "rawbytes.hpp"
#include "mycrypto.hpp"

#ifndef __STRIBOG__
#define __STRIBOG__

class Stribog256 {
    static unsigned        const    _hash_length {  32 };
    static raw_bytes::byte const    _iv          { 0x1 };
public:
    void hash(ByteBlock const & src, ByteBlock & dst) const;
};

class Stribog512 {
    static unsigned        const    _hash_length {  64 };
    static raw_bytes::byte const    _iv          { 0x0 };
public:
    void hash(ByteBlock const & src, ByteBlock & dst) const;
};

#endif /* end of include guard: __STRIBOG__ */
