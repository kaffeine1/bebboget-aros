#ifndef __ASN1_H__
#define __ASN1_H__

#ifndef __BYTEARRAY_H__
#include "bytearray.h"
#endif


class Asn1 {
public:
	static bytea getSeq(bytez const &b, byte const *path, int z);
	static bytea makeASN1(bytez const & b, int typ);
	static bytea addTo(bytez const & seqOrSet, bytez const & dataToAdd);
	static bytea string2Oid(char const * s);
	static bytea encodeOIDInteger(unsigned n);
	static bytea getData(bytez const & ba, int off = 0);

	static byte PK_PATH[];
	static byte MODULO_PATH[];
	static byte EXPONENT_PATH[];
};

#endif // __ASN1_H__
