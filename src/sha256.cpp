#include <cstring>
#include <machine/endian.h>
#include <iostream>
using std::cerr; using std::endl;

#include "mycrypto.hpp"
#include "sha256.hpp"
#include "rawbytes.hpp"

using namespace raw_bytes;

// ======================== Tables Of Constants ============================= //
static uint32_t consts[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,

    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,

    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,

    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,

    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,

    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,

    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,

    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t const init_h[] =
{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// ============================= Functions ================================== //
void hash_function(byte * dst, byte const * msg, unsigned msg_len);
//void round_function(byte *, byte *, byte const *);
void round_function(uint32_t const * msg_block, uint32_t * prev_h);
// ---------------- Round Function Transformations -------------------------- //
inline uint32_t ch_f(uint32_t x, uint32_t y, uint32_t z);
inline uint32_t maj_f(uint32_t x, uint32_t y, uint32_t z);
inline uint32_t bsigma0(uint32_t x);
inline uint32_t bsigma1(uint32_t x);
inline uint32_t lsigma0(uint32_t x);
inline uint32_t lsigma1(uint32_t x);
// -------------------- Other Transformations ------------------------------- //
void padding(byte * ptr, unsigned tail_size, unsigned buf_size, unsigned msg_size);
uint32_t rotr32(uint32_t x, unsigned short n = 1);
uint32_t rotl32(uint32_t x, unsigned short n = 1);
// ========================================================================== //

// ======================= SHA256 Hash Function ============================ //
void SHA256::hash(ByteBlock const & src, ByteBlock & dst) const
{
    dst = ByteBlock(_hash_length);
    hash_function(dst.byte_ptr(), src.byte_ptr(), src.size());
}

// ============================== Realization =============================== //
void hash_function(byte * dst, byte const * msg, unsigned msg_len)
{
    uint32_t hash[8];
    for (int i = 0; i < 8; i++)
        hash[i] = init_h[i];

    unsigned integral_parts  = msg_len >> 6;                     // msg_len / 64
    unsigned tail_part_len   = msg_len - (integral_parts << 6);  // integral_parts * 64

    auto msg_block = reinterpret_cast<uint32_t const *>(msg);
    for (int i = 0; i < integral_parts; i++, msg_block += 16)
        round_function(msg_block, hash);

    byte padded_msg[128] = { 0 };
    msg += integral_parts << 6;
    for (int i = 0 ; i < tail_part_len; i++)
        padded_msg[i] = msg[i];

    unsigned shift = 0;
    if (tail_part_len > 64 - 9) {
        padding(padded_msg, tail_part_len, 128, msg_len);
        round_function(
            reinterpret_cast<uint32_t *>(padded_msg),
            hash
        );
        shift = 64;
    } else {
        padding(padded_msg, tail_part_len, 64, msg_len);
    }
    round_function(
        reinterpret_cast<uint32_t *>(padded_msg + shift),
        hash
    );

    for (int i = 0; i < 8; i++)
        hash[i] = __builtin_bswap32(hash[i]);
    memcpy(dst, hash, sizeof hash);
}

void round_function(uint32_t const * msg_block, uint32_t * prev_h)
{
    uint32_t m_schedule[64];
    for (int i = 0; i < 16; i++)
        m_schedule[i] = __builtin_bswap32(msg_block[i]);
    for (int t = 16; t < 64; t++)
        m_schedule[t] =
              lsigma1(m_schedule[t-2])
            + m_schedule[t-7]
            + lsigma0(m_schedule[t-15])
            + m_schedule[t-16];

    uint32_t prm[8]; // a, b, ..., h
    memcpy(prm, prev_h, sizeof prm);
    for (int t = 0; t < 64; t++)
    {
        #define var(ch) prm[ch - 'a']

        uint32_t tmp1 =
              var('h')
            + bsigma1( var('e') )
            + ch_f( var('e'), var('f'), var('g') )
            + consts[t]
            + m_schedule[t];

        uint32_t tmp2 =
              bsigma0( var('a') )
            + maj_f( var('a'), var('b'), var('c') );

        for (int i = 6; i >= 0; i--) prm[i+1] = prm[i];
        var('e') = var('e') + tmp1;
        var('a') = tmp1 + tmp2;

        #undef var
    }
    for (int i = 0; i < 8; i++)
        prev_h[i] = prm[i] + prev_h[i];
}

void padding(byte * ptr, unsigned tail_size, unsigned buf_size, unsigned msg_size)
{
    ptr[tail_size] = 0x80;
    memset(ptr + tail_size + 1, 0, buf_size - (tail_size + 1));

    for (ptr += buf_size - 1, msg_size <<= 3; msg_size; msg_size >>= 8)
        *(ptr--) = msg_size & 0xff;
}

uint32_t rotr32(uint32_t x, unsigned short n)
{
    n = n & 0x1f;
    return (x >> n) | (x << (32 - n));
}

uint32_t rotl32(uint32_t x, unsigned short n)
{
    n = n & 0x1f;
    return (x << n) | (x >> (32 - n));
}

inline uint32_t ch_f(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

inline uint32_t maj_f(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t bsigma0(uint32_t x)
{
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

inline uint32_t bsigma1(uint32_t x)
{
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

inline uint32_t lsigma0(uint32_t x)
{
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

inline uint32_t lsigma1(uint32_t x)
{
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}
