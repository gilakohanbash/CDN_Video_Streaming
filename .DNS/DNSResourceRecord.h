#ifndef BE4797BB_FD9C_4C12_B5EE_F83837F2EB07
#define BE4797BB_FD9C_4C12_B5EE_F83837F2EB07

#include <cstring>
#include <sstream>
#include <span>
#include <cstdint>
#include <variant>

#include "DNSDomainName.h"
#include "Serialization/DNSSerializationBuffer.h"
#include "Serialization/DNSDeserializationBuffer.h"

enum class DNSRRType : uint16_t {
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

enum class DNSRRClass : uint16_t {
	IN = 1,
	CS = 2,
	CH = 3,
	HS = 4
};

struct DNSResourceRecord {

	struct RecordDataTypes {
		struct A { /* IPv4 */
			uint32_t ipv4Address;
			A() = default;
			A(const std::string& ipv4Address);
			std::string toString(void);
			DNSSerializationBuffer serialize(void);
			static A deserialize(DNSDeserializationBuffer& buffer);
		};
		struct AAAA { /* IPv6 */
			__uint128_t ipv6Address;
			AAAA() = default;
			AAAA(const std::string& ipv6address);
			std::string toString(void);
			DNSSerializationBuffer serialize(void);
			static AAAA deserialize(DNSDeserializationBuffer& buffer);
		};
	};

	using DNSResourceRecordData = std::variant<RecordDataTypes::A,RecordDataTypes::AAAA>;

	DNSDomainName NAME;
	DNSRRType TYPE;
	DNSRRClass CLASS;
	uint32_t TTL;
	uint16_t RDLENGTH;
	DNSResourceRecordData RDATA;

    DNSSerializationBuffer serialize(void);
    static DNSResourceRecord deserialize(DNSDeserializationBuffer& buffer);
};

#endif /* BE4797BB_FD9C_4C12_B5EE_F83837F2EB07 */
