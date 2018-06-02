#include <tuple>
using std::tuple;
using std::make_tuple;
using std::pair;
using std::make_pair;

#include <MyCryptoLib/rawbytes.hpp>
using namespace raw_bytes;

void raw_bytes::xor_n( byte * dst,
            const byte * lhs,
            const byte * rhs,
            unsigned int n_bytes )
{
	const byte * p_end = dst + n_bytes;
	while(dst != p_end) *(dst++) = *(lhs++) ^ *(rhs++);
}

short raw_bytes::nonzero_msb(word number) {
    short i = 0;
    while(number >> i && i < 16) i++;
    return i;
}

word raw_bytes::multiply_poly(word lhs, word rhs) {
    word result = 0;

    for(word detector = 0x1; detector != 0x100; detector <<= 1, lhs <<= 1)
		if(rhs & detector) result ^= lhs;

    return result;
}

std::pair<word, word> raw_bytes::divide_poly(word lhs, word rhs) {
    short max_shift = 16 - nonzero_msb(rhs);
    word    modulus = rhs << max_shift,
            detector = 1 << 15,
            result = 0;

    for(int shift = 0; shift <= max_shift; shift++)
        if((detector >> shift) & lhs) {
            result = (result << 1) | 1;
            lhs ^= modulus >> shift;
        } else {
            result <<= 1;
        }

    return std::make_pair(result, lhs);
}

std::tuple<word, word, word> raw_bytes::ext_gcd_poly(word a, word b) {
    if(b == 0) return std::make_tuple(a, 1, 0);

    word pdiv, pmod, d, x, y;
    std::tie(pdiv, pmod) = divide_poly(a, b);

    std::tie(d, x, y) = ext_gcd_poly(b, pmod);
    return make_tuple(d, y, x ^ multiply_poly(y, pdiv));
}

byte raw_bytes::inverse_poly(byte a, word modulus) {
    if(a == 0) return 0;
    return std::get<1>(ext_gcd_poly(a, modulus));
}

short raw_bytes::sum_of_bits(word target) {
	short result = 0;
    DO_EXACTLY_16_LENGTH(target);
	while(target) {
		result += target & 0x1;
		target >>= 1;
	}
	return result;
}

short raw_bytes::scalar_product(word lhs, word rhs) {
	return sum_of_bits(lhs & rhs) & 0x1;
}

word raw_bytes::multiply_field(word lhs, word rhs, word modulus) {
    word product = multiply_poly(lhs, rhs);
    return std::get<1>(divide_poly(product, modulus));
}

word raw_bytes::power_field(word base, word p, word modulus) {
    if(p == 0) return 1;
    word result = base;
    for(int i = 0; i < p - 1; i++)
        result = multiply_field(result, base, modulus);
    return result;
}
