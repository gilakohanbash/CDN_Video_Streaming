#include <cstdint>
#include <iostream>
#include <ranges>
#include <arpa/inet.h>

#include "DNSQuestion.h"
#include "DNSDomainName.h"
#include "Serialization/DNSSerializationBuffer.h"
#include "Serialization/DNSDeserializationBuffer.h"

DNSSerializationBuffer DNSQuestion::serialize(void) {
    DNSSerializationBuffer result;

    result.concat(QNAME.serialize());
    result.serializeUInt16(static_cast<uint16_t>(QTYPE));
    result.serializeUInt16(static_cast<uint16_t>(QCLASS));

    return result;
}

DNSQuestion DNSQuestion::deserialize(DNSDeserializationBuffer& buffer) {

    DNSQuestion question;

    question.QNAME = DNSDomainName::deserialize(buffer);
    question.QTYPE = static_cast<DNSQType>(buffer.deserializeUInt16());
    question.QCLASS = static_cast<DNSQClass>(buffer.deserializeUInt16());

    return question;
}
