#include "mycrypto.hpp"
#include "Stribog.hpp"
#include "rawbytes.hpp"
using namespace raw_bytes;

// ======================== Tables Of Constants ============================= //
#include "StribogData.hpp"

// ============================= Functions ================================== //
void hash_function(byte * dst, byte const * msg, unsigned msg_len, byte iv_value);
void round_function(byte *, byte *, byte const *);
// ---------------- Round Function Transformations -------------------------- //
inline void tranform_composition(byte * target, byte const * mask);
void substitution_transformation(byte * __restrict target);
void permutation_transformation(byte * __restrict target);
void linear_transformation_core(byte * __restrict target);
void xor_transformation(byte * target __restrict, byte const * __restrict mask);
// -------------------- Other Transformations ------------------------------- //
void padding(byte * __restrict dst, byte const * __restrict src, unsigned len);
void squared_add(byte * dst, byte const * lhs, byte const * rhs);
void squared_add(byte * dst, byte const * lhs, unsigned rhs_number);
// ========================================================================== //

// ======================= Stribog Hash Function ============================ //
void Stribog512::hash(ByteBlock const & src, ByteBlock & dst) const
{
    byte hash_output [64];
    hash_function(hash_output, src.byte_ptr(), src.size(), _iv);
    dst.reset(hash_output, _hash_length);
}

void Stribog256::hash(ByteBlock const & src, ByteBlock & dst) const
{
    byte hash_output [64];
    hash_function(hash_output, src.byte_ptr(), src.size(), _iv);
    dst.reset(hash_output, _hash_length);
}

// ============================== Realization =============================== //
void hash_function(byte * destination, byte const * message, unsigned msg_len, byte iv_value)
{
    byte rf_parameter[64]       = {0};  // round function parameter N
    byte epsilon[64]            = {0};  // padding parameter EPSILON

    byte intermidiate_hash[64];         // result of round function on every iter
    memset(intermidiate_hash, iv_value, sizeof intermidiate_hash);

    unsigned integral_parts  = msg_len >> 6;                     // msg_len / 64
    unsigned tail_part_len   = msg_len - (integral_parts << 6);  // integral_parts * 64

    byte const * current_message = message + msg_len;
    // main loop of evaluating hash function
    for (int i = 0; i < integral_parts; i++)
    {
        current_message -= 64;
        round_function( intermidiate_hash,
                        rf_parameter,
                        current_message );
        squared_add(rf_parameter, rf_parameter, 512);
        squared_add(epsilon, epsilon, current_message);
    }

    // last iteration
    byte padded_message[64] = {0};
    padding(padded_message, message, tail_part_len);
    round_function( intermidiate_hash,
                    rf_parameter,
                    padded_message  );
    squared_add(rf_parameter, rf_parameter, tail_part_len << 3);
    squared_add(epsilon, epsilon, padded_message);

    // shuttin down evaluating
    // lets reuse variable padded_message for not creating new array for zero
    memset(padded_message, 0, sizeof padded_message);
    round_function( intermidiate_hash,
                    padded_message,   /* zero */
                    rf_parameter    );
    round_function( intermidiate_hash,
                    padded_message,   /* zero */
                    epsilon         );

    memcpy(destination, intermidiate_hash, sizeof intermidiate_hash);
}

void substitution_transformation(byte * __restrict target)
{
    for (int i = 0; i < 64; i++)
        target[i] = SUBSTITUTION_PI[target[i]];
}

void permutation_transformation(byte * __restrict target)
{
    byte tmp[64];
    for (int i = 0; i < 64; i++)
        tmp[PERMUTATION_TAU[i]] = target[i];
    memcpy(target, tmp, sizeof(tmp));
}


void linear_transformation_core(byte * __restrict target)
{
    #define TAKEBIT(b_ptr, i) ( (*((b_ptr) + (i) / 8)) & (1 << ((63 - (i)) % 8)) )
    // #define TAKEBIT(b_ptr, i) ( (*((b_ptr) + (63 - i) / 8)) & ((1 << (i & 0x7))) )

    byte result[8] = {0};
    for (int b_i = 0; b_i < 64; b_i++) if (TAKEBIT(target, b_i))
    {
        for (int j = 0; j < 8; j++)
            result[j] ^= LINEAR_TRANSFORMATION[b_i][j];
    }
    memcpy(target, result, sizeof result);

    #undef TAKEBIT
}

void linear_transformation(byte * __restrict target)
{
    for(int part = 0; part < 8; part++)
        linear_transformation_core(target + part * 8);
}

void xor_transformation(byte * __restrict target, byte const __restrict * mask)
{
    for(int i = 0; i < 64; i++)
        target[i] ^= mask[i];
}

inline void split_into_bytes(byte * dst, unsigned x)
{
    for (int i = 3; x && i >= 0; i--)
    {
        dst[i] = x & 0xff;
        x >>= 8;
    }
}

void squared_add(byte * dst, byte const * lhs, unsigned rhs_number)
{
    byte rhs [64] = { 0 };
    split_into_bytes(rhs + 60, rhs_number);

    squared_add(dst, lhs, rhs);
}

void squared_add(byte * dst, byte const * lhs, byte const * rhs)
{
    word tmp = 0;
    for (int i = 63; i >= 0; i--)
    {
        tmp = tmp + lhs[i] + rhs[i];
        dst[i] = tmp & 0xff;
        tmp >>= 8;
    }
}

inline void tranform_composition(byte * target, byte const * mask)
{
    xor_transformation(         target, mask    );
    substitution_transformation(target          );
    permutation_transformation( target          );
    linear_transformation(      target          );
}

void round_function(byte * intermidiate_hash,
                    byte * rf_parameter,
                    byte const * message    )
{
    ByteBlock b;

    byte current_mask [ 64 ];
    byte old_hash     [ 64 ];

    memcpy(current_mask,        intermidiate_hash,  sizeof current_mask);
    memcpy(old_hash,            intermidiate_hash,  sizeof old_hash);
    memcpy(intermidiate_hash,   message,            64);

    tranform_composition(current_mask, rf_parameter);
    for(int i = 0; i < 12; i++) {
        // perfoming the next iteration
        tranform_composition(intermidiate_hash, current_mask    );
        // preparing the next mask
        tranform_composition(current_mask,      ITER_CONSTS[i]  );
    }

    xor_transformation(intermidiate_hash, current_mask  );
    xor_transformation(intermidiate_hash, old_hash      );
    xor_transformation(intermidiate_hash, message       );
}

void padding(byte * __restrict dst, byte const * __restrict src, unsigned length)
{
    unsigned start_pos = 64 - length;
    memset(dst, 0, start_pos);
    memcpy(dst + start_pos, src, length);
    if (start_pos) dst[start_pos - 1] = 1;
}
