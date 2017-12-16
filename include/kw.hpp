#include "mycrypto.hpp"
#include "Rijndael.hpp"


void KeyWrapFunction(ByteBlock & dst, const ByteBlock & src, const ByteBlock & key);
void KeyUnwrapFunction(ByteBlock & dst, const ByteBlock & src, const ByteBlock & key);

void KeyWrapPaddedFunction(ByteBlock & dst, const ByteBlock & str, const ByteBlock & key);
void KeyUnwrapPaddedFunction(ByteBlock & dst, const ByteBlock & str, const ByteBlock & key);
