#ifndef B50533DD_C23C_43DD_BE78_797750A2C96D
#define B50533DD_C23C_43DD_BE78_797750A2C96D

#include <cstdint>
#include <string>
#include <sstream>
#include <span>
#include <vector>

#include "Serialization/DNSSerializationBuffer.h"
#include "Serialization/DNSDeserializationBuffer.h"

enum class DNSOpcode : uint8_t {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2,
    UNKNOWN = 3,
    NOTIFY = 4,
    UPDATE = 5
};

enum class DNSRcode : uint8_t {
    NO_ERROR = 0,
    FORMAT_ERROR = 1,
    SERVER_FAILURE = 2,
    NAME_ERROR = 3,
    NOT_IMPLMEMENTED = 4,
    REFUSED = 5
};

struct DNSHeader {
    uint16_t ID;
    uint16_t QR : 1;
    DNSOpcode OPCODE;
    uint16_t AA : 1;
    uint16_t TC : 1;
    uint16_t RD : 1;
    uint16_t RA : 1;
    uint16_t Z : 1;
    uint16_t AD : 1; // EDNS-only
    uint16_t CD : 1; // EDNS-only
    DNSRcode RCODE;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;

    DNSSerializationBuffer serialize(void);
    static DNSHeader deserialize(DNSDeserializationBuffer& buffer);
};

#endif /* B50533DD_C23C_43DD_BE78_797750A2C96D */
