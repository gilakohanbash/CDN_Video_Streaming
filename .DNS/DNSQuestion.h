#ifndef CB0883DD_7C4B_455F_8CA0_785AC45E8B07
#define CB0883DD_7C4B_455F_8CA0_785AC45E8B07

#include <cstring>
#include <sstream>
#include <span>
#include <cstdint>
#include <vector>

#include "DNSDomainName.h"
#include "Serialization/DNSSerializationBuffer.h"
#include "Serialization/DNSDeserializationBuffer.h"

enum class DNSQType : uint16_t {
	A = 1,
	NS = 2,
	CNAME = 5,
	SOA = 6,
	PTR = 12,
	MX = 15,
	TXT = 16,
	RP = 17,
	AFSDB = 18,
	SIG = 24,
	KEY = 25,
	AAAA = 28,
	LOC = 29,
	SRV = 33,
	NAPTR = 35,
	KX = 36,
	CERT = 37,
	DNAME = 39,
	OPT = 41,
	APL = 42,
	DS = 43,
	SSHFP = 44,
	IPSECKEY = 45,
	RRSIG = 46,
	NSEC = 47,
	DNSKEY = 48,
	DHCID = 49,
	NSEC3 = 50,
	NSEC3PARAM = 51,
	HIP = 55,
	SPF = 99,
	TKEY = 249,
	TSIG = 250,
	IXFR = 251,
	AXFR = 252,
	ANY = 255,
	TA = 32768,
	DLV = 32769
};

enum class DNSQClass : uint16_t {
	IN = 1,
	CS = 2,
	CH = 3,
	HS = 4,
	ANY = 255
};

struct DNSQuestion {
	DNSDomainName QNAME;
	DNSQType QTYPE;
	DNSQClass QCLASS;

    DNSSerializationBuffer serialize(void);
    static DNSQuestion deserialize(DNSDeserializationBuffer& buffer);
};

#endif /* CB0883DD_7C4B_455F_8CA0_785AC45E8B07 */
