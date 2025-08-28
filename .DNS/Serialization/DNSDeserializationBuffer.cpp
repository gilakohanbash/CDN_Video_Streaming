
#include <stdexcept>
#include <cstring>
#include <arpa/inet.h>

#include "DNSDeserializationBuffer.h"

DNSDeserializationBuffer::DNSDeserializationBuffer(std::span<const std::byte> data) : span(data) { }

uint8_t DNSDeserializationBuffer::deserializeUInt8(void) {
    uint8_t result;
    if (span.size() < sizeof(result)) {
        throw NotEnoughDataException();
    }
    std::memcpy(&result, span.data(), sizeof(result));
    span = span.subspan(sizeof(result));
    return result;
}

uint16_t DNSDeserializationBuffer::deserializeUInt16(void) {
    uint16_t result;
    if (span.size() < sizeof(result)) {
        throw NotEnoughDataException();
    }
    std::memcpy(&result, span.data(), sizeof(result));
    span = span.subspan(sizeof(result));
    return ntohs(result);
}

uint32_t DNSDeserializationBuffer::deserializeUInt32(void) {
    uint32_t result;
    if (span.size() < sizeof(result)) {
        throw NotEnoughDataException();
    }
    std::memcpy(&result, span.data(), sizeof(result));
    span = span.subspan(sizeof(result));
    return ntohl(result);
}

__uint128_t DNSDeserializationBuffer::deserializeUInt128(void) {
    __uint128_t result;
    if (span.size() < sizeof(result)) {
        throw NotEnoughDataException();
    }
    std::memcpy(&result, span.data(), sizeof(result));
    span = span.subspan(sizeof(result));
    return result;
}

std::string DNSDeserializationBuffer::deserializeDNSLabel(void) {
    uint8_t length;
    if (span.size() < sizeof(length)) {
        throw NotEnoughDataException();
    }
    std::memcpy(&length, span.data(), sizeof(length));
    span = span.subspan(sizeof(length));
    std::string result;
    if (span.size() < length) {
        throw NotEnoughDataException();
    }
    result.resize(length);
    memcpy(&result[0], span.data(), length);
    span = span.subspan(length);
    return result;
}
