#include "mycrypto.hpp"

#include <stdint.h>

class SHA256 {
    static unsigned        const    _hash_length { 32 };
public:
    void hash(ByteBlock const & src, ByteBlock & dst) const;
};

void padding(BYTE * ptr, unsigned tail_size, unsigned buf_size, unsigned msg_size);
