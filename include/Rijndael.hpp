#ifndef __RIJNDAEL__
#define __RIJNDAEL__

#include <vector>
#include "mycrypto.hpp"
#include "rawbytes.hpp"

#define DWORD 4

typedef unsigned int uint;

struct SBoxContainer {
    static bool is_init;
    static raw_bytes::byte sbox[256];
    static raw_bytes::byte invsbox[256];
    static void init();
};

template <uint Nr>
struct RConstContainer {
    static bool is_init;
    static raw_bytes::dword rconst[Nr];
    static void init();
};

// Nk - number of dwords for key
// Nb - number of dwords for block
// Nr = number of rounds in key expansion
template <uint Nk, uint Nb, uint Nr>
class Rijndael : public SBoxContainer, public RConstContainer<Nr> {
    std::vector<ByteBlock>          round_keys;

public:
	static const int                block_lenght { Nb * DWORD };

	Rijndael(const ByteBlock & key);
    Rijndael(const Rijndael & rhs);
	~Rijndael() {};

    void encrypt(const ByteBlock & src, ByteBlock & dst) const;
	void decrypt(const ByteBlock & src, ByteBlock & dst) const;
};

typedef Rijndael<4, 4, 10> AES128;
typedef Rijndael<6, 4, 12> AES192;
typedef Rijndael<8, 4, 14> AES256;

#endif
