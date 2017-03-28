#include <vector>
using std::vector;

#include <stdexcept>
#include <cstring>

#include "rawbytes.hpp"
using namespace raw_bytes;

#include "Rijndael.hpp"

static const word RIJNDAEL_MODULUS = 0x11B;

template <unsigned short Nb>
class RijndaelState {
	byte * body;
public:
    RijndaelState(byte * ptr) : body(ptr) {}
    byte & at(int i, int j) {
        return body[j * Nb + i];
    }
    operator byte * () { return body; }
	RijndaelState & operator = (const RijndaelState & rhs) {
		memcpy(body, rhs.body, Nb * 4);
		return *this;
	}
};

// ------------------------- Transformations ---------------------------

static void rot_word(byte * target);
static void sub_word(byte * target);

template <uint Nb>
static void add_round_key(byte * target, const byte * round_key);

template <uint Nb>
static void mix_columns(byte * target);

template <uint Nb>
static void shift_rows(byte * target);

template <uint Nb>
static void sub_bytes(byte * target);

template <uint Nb>
static void inv_mix_columns(byte * target);

template <uint Nb>
static void inv_shift_rows(byte * target);

template <uint Nb>
static void inv_sub_bytes(byte * target);

template <uint Nk, uint Nb, uint Nr>
static void key_expansion(const byte * key, vector<ByteBlock> & round_keys);

static byte affine_transform(byte b);
static byte inv_affine_transform(byte b);


// -------------------- initialization ---------------------------

template <uint Nr>
dword RConstContainer<Nr>::rconst[Nr];

template <uint Nr>
bool RConstContainer<Nr>::is_init = false;

template <uint Nr>
void RConstContainer<Nr>::init() {
    for(int i = 0 ; i < Nr; i++)
        rconst[i] = power_field(0x02, i, RIJNDAEL_MODULUS);
}

bool SBoxContainer::is_init = false;
byte SBoxContainer::sbox[256];
byte SBoxContainer::invsbox[256];

void SBoxContainer::init() {
    for(uint i = 0; i < sizeof(sbox); i++) {
        sbox[i] = affine_transform(inverse_poly(i, RIJNDAEL_MODULUS));
		invsbox[i] = inverse_poly(inv_affine_transform(i), RIJNDAEL_MODULUS);
	}
}

static byte affine_transform(byte b) {
    const byte affine_matrix[] = {
        0xf1, 0xe3, 0xc7, 0x8f, 0x1f, 0x3e, 0x7c, 0xf8
    };
    byte affine_shift = 0x63;

    byte result = 0;
    for(int i = 0; i < 8; i++) {
        byte next_bit =
        (0x1 & affine_shift) ^ scalar_product(affine_matrix[i], b);
        affine_shift >>= 1;
        result |= next_bit << i;
    }
    return result;
}
static byte inv_affine_transform(byte b) {
    const byte affine_matrix[] = {
		0xa4, 0x49, 0x92, 0x25, 0x4a, 0x94, 0x29, 0x52
    };
    byte affine_shift = 0x05;

    byte result = 0;
    for(int i = 0; i < 8; i++) {
        byte next_bit =
        (0x1 & affine_shift) ^ scalar_product(affine_matrix[i], b);
        affine_shift >>= 1;
        result |= next_bit << i;
    }
    return result;
}

// -------------------------- the Cipher Class ---------------------------

template <uint Nk, uint Nb, uint Nr>
Rijndael<Nk, Nb, Nr>::Rijndael(const ByteBlock & key) {
    if(key.size() != Nk * DWORD) throw std::invalid_argument("Invalid key length");

    if( !SBoxContainer::is_init ) SBoxContainer::init();
    if( !RConstContainer<Nr>::is_init ) RConstContainer<Nr>::init();

    round_keys.resize(Nr + 1);
    key_expansion<Nk, Nb, Nr>(key.byte_ptr(), round_keys);
}

template <uint Nk, uint Nb, uint Nr>
Rijndael<Nk, Nb, Nr>::Rijndael(const Rijndael & rhs) {
    for(auto & key : rhs.round_keys)
        round_keys.push_back(key.deep_copy());
}

template <uint Nk, uint Nb, uint Nr>
void Rijndael<Nk, Nb, Nr>::encrypt(const ByteBlock & src, ByteBlock & dst) const {
    if(src.size() != Nb * DWORD) throw std::invalid_argument("Invalid msg length");

    if(dst != src) dst = src.deep_copy();
    byte * target = dst.byte_ptr();

    add_round_key<Nb>(target, round_keys[0].byte_ptr());
    for(int i = 1; i < Nr; i++) {
        sub_bytes<Nb>(target);
        shift_rows<Nb>(target);
        mix_columns<Nb>(target);
        add_round_key<Nb>(target, round_keys[i].byte_ptr());
    }
    sub_bytes<Nb>(target);
    shift_rows<Nb>(target);
    add_round_key<Nb>(target, round_keys[Nr].byte_ptr());
}

template <uint Nk, uint Nb, uint Nr>
void Rijndael<Nk, Nb, Nr>::decrypt(const ByteBlock & src, ByteBlock & dst) const {
	if(src.size() != Nb * DWORD) throw std::invalid_argument("Invalid msg length");

    if(dst != src) dst = src.deep_copy();
    byte * target = dst.byte_ptr();

	add_round_key<Nb>(target, round_keys[Nr].byte_ptr());
	for(int i = Nr - 1; i > 0; i--) {
		inv_shift_rows<Nb>(target);
		inv_sub_bytes<Nb>(target);
		add_round_key<Nb>(target, round_keys[i].byte_ptr());
		inv_mix_columns<Nb>(target);
	}
	inv_shift_rows<Nb>(target);
	inv_sub_bytes<Nb>(target);
	add_round_key<Nb>(target, round_keys[0].byte_ptr());
}


// -------------------------- Transformations ---------------------------

template <uint Nk, uint Nb, uint Nr>
static void key_expansion(const byte * key, vector<ByteBlock> & round_keys) {
    byte tmp[DWORD];
    byte w[Nb * (Nr + 1) * DWORD];

    for(int i = 0; i < Nk; i++)
        memcpy(w + DWORD * i, key + DWORD * i, DWORD);

	for(int i = Nk; i < Nb * (Nr + 1); i++) {
        memcpy(tmp, w + (i - 1) * DWORD, DWORD);
        if(i % Nk == 0) {
            rot_word(tmp);
			sub_word(tmp);
			xor_n(tmp, tmp, (byte *) &RConstContainer<Nr>::rconst[i / Nk - 1], DWORD);
        } else if(Nk > 6 && i % Nk == 4) {
            sub_word(tmp);
        }
        xor_n(w + DWORD * i, w + DWORD * (i - Nk), tmp, DWORD);
    }

    for(int i = 0; i < Nr + 1; i++)
        round_keys[i].reset(w + i * Nb * DWORD, Nb * DWORD);
}


template <uint Nb>
static void sub_bytes(byte * target) {
	for(int i = 0; i < Nb * DWORD; i++) target[i] = SBoxContainer::sbox[target[i]];
}

template <uint Nb>
static void inv_sub_bytes(byte * target) {
	for(int i = 0; i < Nb * DWORD; i++) target[i] = SBoxContainer::invsbox[target[i]];
}

template <uint Nb>
static void shift_rows(byte * target_) {
    RijndaelState<Nb> target(target_);
	for(int n_rows = 1; n_rows < DWORD; n_rows++) {
		for(int n_shift = 0; n_shift < n_rows; n_shift++) {
			byte tmp = target.at(n_rows, 0);
			for(int n_cols = 0; n_cols < Nb - 1; n_cols++)
				target.at(n_rows, n_cols) = target.at(n_rows, n_cols + 1);
			target.at(n_rows, Nb - 1) = tmp;
		}
	}
}

template <uint Nb>
static void inv_shift_rows(byte * target_) {
    RijndaelState<Nb> target(target_);
	for(int n_rows = 1; n_rows < DWORD; n_rows++) {
		for(int n_shift = 0; n_shift < n_rows; n_shift++) {
			byte tmp = target.at(n_rows, Nb - 1);
			for(int n_cols = Nb - 1; n_cols > 0; n_cols--)
				target.at(n_rows, n_cols) = target.at(n_rows, n_cols - 1);
			target.at(n_rows, 0) = tmp;
		}
	}
}

template <uint Nb>
static void mix_columns(byte * target_) {
	byte * tmp_ptr = new byte [16];
	RijndaelState<Nb> tmp(tmp_ptr);
    RijndaelState<Nb> target(target_);

	tmp = target;
	for(int i = 0; i < Nb; i++) {
		#define mul(x, y) multiply_field((x), (y), RIJNDAEL_MODULUS)

		target.at(0, i) =
			mul(tmp.at(0, i), 0x2) ^ mul(tmp.at(1, i), 0x3) ^ tmp.at(2, i) ^ tmp.at(3, i);
		target.at(1, i) =
			tmp.at(0, i) ^ mul(tmp.at(1, i), 0x2) ^ mul(tmp.at(2, i), 0x3) ^ tmp.at(3, i);
		target.at(2, i) =
			tmp.at(0, i) ^ tmp.at(1, i) ^ mul(tmp.at(2, i), 0x2) ^ mul(tmp.at(3, i), 0x3);
		target.at(3, i) =
			mul(tmp.at(0, i), 0x3) ^ tmp.at(1, i) ^ tmp.at(2, i) ^ mul(tmp.at(3, i), 0x2);

		#undef mul
	}
	delete [] tmp_ptr;
}

template <uint Nb>
static void inv_mix_columns(byte * target_) {
	byte * tmp_ptr = new byte [16];
	RijndaelState<Nb> tmp(tmp_ptr);
    RijndaelState<Nb> target(target_);

	tmp = target;
	for(int i = 0; i < Nb; i++) {
		#define mul(x, y) multiply_field((x), (y), RIJNDAEL_MODULUS)

		target.at(0, i) =
			mul(tmp.at(0, i), 0xe) ^ mul(tmp.at(1, i), 0xb) ^ mul(tmp.at(2, i), 0xd) ^ mul(tmp.at(3, i), 0x9);
		target.at(1, i) =
			mul(tmp.at(0, i), 0x9) ^ mul(tmp.at(1, i), 0xe) ^ mul(tmp.at(2, i), 0xb) ^ mul(tmp.at(3, i), 0xd);
		target.at(2, i) =
			mul(tmp.at(0, i), 0xd) ^ mul(tmp.at(1, i), 0x9) ^ mul(tmp.at(2, i), 0xe) ^ mul(tmp.at(3, i), 0xb);
		target.at(3, i) =
			mul(tmp.at(0, i), 0xb) ^ mul(tmp.at(1, i), 0xd) ^ mul(tmp.at(2, i), 0x9) ^ mul(tmp.at(3, i), 0xe);

		#undef mul
	}
	delete [] tmp_ptr;
}

template <uint Nb>
static void add_round_key(byte * target, const byte * round_key) {
	xor_n(target, target, round_key, Nb * DWORD);
}

static void sub_word(byte * target) {
	for(int i = 0; i < DWORD; i++) target[i] = SBoxContainer::sbox[target[i]];
}

static void rot_word(byte * target) {
	byte tmp = target[0];
	for(int i = 0; i < DWORD; i++)
		target[i] = target[i+1];
	target[DWORD - 1] = tmp;
}

template class Rijndael<4, 4, 10>;
template class Rijndael<6, 4, 12>;
template class Rijndael<8, 4, 14>;
