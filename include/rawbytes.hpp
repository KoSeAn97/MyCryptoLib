#include <tuple>
using std::tuple;
using std::pair;

#include <cstdint>

#ifndef __RAWBYTES__
#define __RAWBYTES__

#define DO_EXACTLY_16_LENGTH(x) ((x) = (x) & 0xffff )

namespace raw_bytes {  // namespace begining

typedef uint8_t byte;     // considered to be  8 bits length
typedef uint16_t word;    // considered to be 16 bits length
typedef uint32_t dword;

// it'll xor n_bytes relevant lhs's ans rhs's bytes and place result at dst
void xor_n(byte * dst, const byte * lhs, const byte * rhs, unsigned int n_bytes);

// position's counting starts with 1
// zero means there isn't any nonzero bits
short nonzero_msb(word number);

// considered deg(lhs) + deg(rhs) < 16
word multiply_poly(word lhs, word rhs);
word multiply_field(word lhs, word rhs, word modulus);

// considered deg(base) < 8
word power_field(word base, word p, word modulus);

// returns (devident / devisor, devident % devisor)
std::pair<word, word> divide_poly(word devident, word devisor);

// Extended Euclidian's algorithm with polynoms
std::tuple<word, word, word> ext_gcd_poly(word a, word b);

// if a isn't zero polynom then return its inverse
// if a is zero then return zero
byte inverse_poly(byte a, word modulus);

// it'll reject bits at positions > 16
short sum_of_bits(word target);

short scalar_product(word lhs, word rhs);

} //namespace ending

#endif
