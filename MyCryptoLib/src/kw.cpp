#include <stdexcept>
#include <vector>
#include <cstdio>

#include <MyCryptoLib/Rijndael.hpp>
#include <MyCryptoLib/mycrypto.hpp>
#include <MyCryptoLib/kw.hpp>

static const size_t HALFED_WCB = 8;
static const size_t MIN_N_SEMIBLOCKS = 3;

inline size_t ceiled( size_t a, size_t b) {
    return a / b + (a % b ? 1 : 0);
}

static void WrapCipherFunction(std::vector<ByteBlock> & rv, ByteBlock & a, ByteBlock & b, uint64_t iter, const AES256 & alg);
static void UnwrapCipherFunction(std::vector<ByteBlock> & rv, ByteBlock & a, ByteBlock & b, uint64_t iter, const AES256 & alg);

static void WrapShift(std::vector<ByteBlock> & semiblocks);
static void UnwrapShift(std::vector<ByteBlock> & semiblocks);

static void WrapFunction(ByteBlock & dst, const ByteBlock & str, const ByteBlock & key);
static void UnwrapFunction(ByteBlock & dst, const ByteBlock & str, const ByteBlock & key);

static void KwpPad(ByteBlock & dst, const ByteBlock & str);
static void KuwpPad(ByteBlock & block);

static void CheckStringToWrap( const ByteBlock & str );
static void XorWithInt64(ByteBlock & rv, const ByteBlock & block, uint64_t integer);

/* -------------------------------------- Key Wrap Functions ------------------------------------- */
void KeyWrapFunction(ByteBlock & dst, const ByteBlock & str, const ByteBlock & key) {
    static unsigned char pad[] = {
        0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
    };

    if(str.size() % HALFED_WCB)
        throw std::invalid_argument("String to wraped must be divisible by 64 block");

    std::vector<ByteBlock> temp(2);
    temp.front() = ByteBlock(pad, sizeof pad);
    temp.back() = str.deep_copy();

    WrapFunction(dst, join_blocks(temp), key);
}

void KeyUnwrapFunction(ByteBlock & dst, const ByteBlock & src, const ByteBlock & key) {
    static unsigned char pad[] = {
        0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
    };
    size_t padlen = sizeof pad;

    UnwrapFunction(dst, src, key);
    if(memcmp(dst.byte_ptr(), pad, padlen)) {
        throw std::invalid_argument("Failed to unwrap key");
    }
    dst = dst(padlen, dst.size() - padlen);
}

void KeyWrapPaddedFunction(ByteBlock & dst, const ByteBlock & str, const ByteBlock & key) {
    KwpPad(dst, str);
    if(str.size() <= 8) {
        AES256 alg(key);
        alg.encrypt(dst, dst);
    } else {
        WrapFunction(dst, dst, key);
    }
}

void KeyUnwrapPaddedFunction(ByteBlock & dst, const ByteBlock & str, const ByteBlock & key) {
    if(str.size() % HALFED_WCB)
        throw std::invalid_argument("String to wraped must be divisible by 64 block");

    if(str.size() / HALFED_WCB == 2) {
        AES256 alg(key);
        alg.decrypt(str, dst);
    } else {
        UnwrapFunction(dst, str, key);
    }
    KuwpPad(dst);
}
/* ----------------------------------------------------------------------------------------------- */

void WrapFunction(ByteBlock & dst, const ByteBlock & str, const ByteBlock & key) {
    CheckStringToWrap(str);

    size_t n_semiblocks = str.size() / HALFED_WCB;
    size_t n_iter = 6 * (n_semiblocks - 1);
    auto semiblocks = split_blocks(str, HALFED_WCB);

    AES256 alg(key);
    std::vector<ByteBlock> ciphered(2);
    for(size_t t = 1; t <= n_iter; t++) {
        WrapCipherFunction(ciphered, semiblocks.front(), semiblocks[1], t, alg);
        semiblocks.front() = std::move(ciphered.front());
        WrapShift(semiblocks);
        semiblocks.back() = std::move(ciphered.back());
    }

    dst = join_blocks(semiblocks);
}

void UnwrapFunction(ByteBlock & dst, const ByteBlock & str, const ByteBlock & key) {
    size_t n_semiblocks = str.size() / HALFED_WCB;
    size_t n_iter = 6 * (n_semiblocks - 1);
    auto semiblocks = split_blocks(str, HALFED_WCB);

    AES256 alg(key);
    std::vector<ByteBlock> ciphered(2);
    for(size_t t = n_iter; t >= 1; t--) {
        UnwrapCipherFunction(ciphered, semiblocks.front(), semiblocks.back(), t, alg);
        semiblocks.front() = std::move(ciphered.front());
        UnwrapShift(semiblocks);
        semiblocks[1] = std::move(ciphered.back());
    }

    dst = join_blocks(semiblocks);
}

void WrapCipherFunction(std::vector<ByteBlock> & rv, ByteBlock & a, ByteBlock & b, uint64_t iter, const AES256 & alg) {
    rv.front() = std::move(a);
    rv.back() = std::move(b);

    ByteBlock to_encrypt(join_blocks(rv));
    alg.encrypt(to_encrypt, to_encrypt);
    rv = split_blocks(to_encrypt, HALFED_WCB);
    XorWithInt64(rv[0], rv[0], iter);
}

void UnwrapCipherFunction(std::vector<ByteBlock> & rv, ByteBlock & a, ByteBlock & b, uint64_t iter, const AES256 & alg) {
    XorWithInt64(rv.front(), a, iter);
    rv.back() = std::move(b);

    ByteBlock to_decrypt(join_blocks(rv));
    alg.decrypt(to_decrypt, to_decrypt);
    rv = split_blocks(to_decrypt, HALFED_WCB);
}

void WrapShift(std::vector<ByteBlock> & semiblocks) {
    size_t last_item = semiblocks.size() - 2;
    for(size_t i = 1; i <= last_item; i++)
        semiblocks[i] = std::move(semiblocks[i + 1]);
}

void UnwrapShift(std::vector<ByteBlock> & semiblocks) {
    size_t last_item = semiblocks.size() - 2;
    for(size_t i = last_item; i >= 1; i--)
        semiblocks[i + 1] = std::move(semiblocks[i]);
}

void KwpPad(ByteBlock & dst, const ByteBlock & str) {
    std::vector<ByteBlock> result(4);

    static unsigned char padvalue[] = {
        0xA6, 0x59, 0x59, 0xA6
    };

    size_t padlen = 8 * ceiled(str.size(), 8) - str.size();

    const size_t SIZE = 4;
    unsigned char t[SIZE] = { 0 };
    uint32_t vect = __builtin_bswap32(str.size());
    memcpy(t, &vect, SIZE);

    result[0] = ByteBlock(padvalue, sizeof padvalue);
    result[1] = ByteBlock(t, SIZE);
    result[2] = str.deep_copy();
    result[3] = ByteBlock(padlen);

    size_t len = 0;
    for(auto & x : result) len += x.size();
    unsigned char* p = new unsigned char [len];

    size_t pos = 0;
    for(auto & x : result) {
        memcpy(p + pos, x.byte_ptr(), x.size());
        pos += x.size();
    }

    dst = ByteBlock(p, len);
    delete [] p;
}

void KuwpPad(ByteBlock & block) {
    static unsigned char padvalue[] = {
        0xA6, 0x59, 0x59, 0xA6
    };
    size_t padlen = sizeof padvalue;

    if(memcmp(block.byte_ptr(), padvalue, padlen))
        throw std::invalid_argument("Failed to unwrap key");

    uint64_t plen = 0;
    memcpy(&plen, block.byte_ptr() + 4, 4);
    plen = __builtin_bswap32(plen);

    padlen = (block.size() / HALFED_WCB - 1) * 8 - plen;
    if(!padlen || padlen > 7)
        throw std::invalid_argument("Failed to unwrap key");

    ByteBlock tmp = block(block.size() - padlen, padlen);
    for(size_t i = 0; i < padlen; i++)
        if(tmp[i] != 0)
            throw std::invalid_argument("Failed to unwrap key");

    block = block(HALFED_WCB, block.size() - HALFED_WCB - padlen);
}

void CheckStringToWrap( const ByteBlock & str ) {
    if(str.size() % HALFED_WCB)
       throw std::invalid_argument("String to wraped must be divisible by 64 block");

    size_t n_semiblocks = str.size() / HALFED_WCB;
    if(n_semiblocks < MIN_N_SEMIBLOCKS)
       throw std::invalid_argument("String to wraped must be larger");
}

void XorWithInt64(ByteBlock & rv, const ByteBlock & block, uint64_t integer) {
    unsigned char bytes[sizeof integer];
    integer = __builtin_bswap64(integer);
    memcpy(bytes, &integer, sizeof integer);
    xor_blocks(rv, block, ByteBlock(bytes, sizeof bytes));
}
