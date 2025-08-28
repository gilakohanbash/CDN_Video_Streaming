#include <cstdint>
#include <arpa/inet.h>

#include "DNSResourceRecord.h"
#include "Serialization/DNSSerializationBuffer.h"
#include "Serialization/DNSDeserializationBuffer.h"

DNSSerializationBuffer DNSResourceRecord::serialize(void) {

    DNSSerializationBuffer buffer;

    buffer.concat(NAME.serialize());
    buffer.serializeUInt16(static_cast<uint16_t>(TYPE));
    buffer.serializeUInt16(static_cast<uint16_t>(CLASS));
    buffer.serializeUInt32(TTL);
    buffer.serializeUInt16(RDLENGTH);

    switch (TYPE) {
        case DNSRRType::A: {
            buffer.concat(std::get<DNSResourceRecord::RecordDataTypes::A>(RDATA).serialize());
            break;
        }
        case DNSRRType::AAAA:
            buffer.concat(std::get<DNSResourceRecord::RecordDataTypes::AAAA>(RDATA).serialize());
            break;
        default:
            throw std::runtime_error("Not implemented");
    }

    return buffer;
}

DNSResourceRecord DNSResourceRecord::deserialize(DNSDeserializationBuffer& buffer) {
    DNSResourceRecord record;

    record.NAME = DNSDomainName::deserialize(buffer);
    record.TYPE = static_cast<DNSRRType>(buffer.deserializeUInt16());
    record.CLASS = static_cast<DNSRRClass>(buffer.deserializeUInt16());
    record.TTL = buffer.deserializeUInt32();
    record.RDLENGTH = buffer.deserializeUInt16();
    switch (record.TYPE) {
        case DNSRRType::A:
            record.RDATA = DNSResourceRecord::RecordDataTypes::A::deserialize(buffer);
            break;
        case DNSRRType::AAAA:
            record.RDATA = DNSResourceRecord::RecordDataTypes::AAAA::deserialize(buffer);
            break;
        default:
            throw std::runtime_error("Not implemented");
    }

    return record;
}

DNSResourceRecord::RecordDataTypes::A::A(const std::string& ipv4Address) :
    ipv4Address(inet_network(ipv4Address.c_str())) { }

std::string DNSResourceRecord::RecordDataTypes::A::toString(void) {
    struct in_addr addr;
    addr.s_addr = htonl(ipv4Address);
    return inet_ntoa(addr);
}

DNSSerializationBuffer DNSResourceRecord::RecordDataTypes::A::serialize(void) {
    DNSSerializationBuffer buffer;
    buffer.serializeUInt32(ipv4Address);
    return buffer;
}

DNSResourceRecord::RecordDataTypes::A DNSResourceRecord::RecordDataTypes::A::deserialize(DNSDeserializationBuffer& buffer) {
    DNSResourceRecord::RecordDataTypes::A resourceRecord;
    resourceRecord.ipv4Address = buffer.deserializeUInt32();
    return resourceRecord;
}

DNSResourceRecord::RecordDataTypes::AAAA::AAAA(const std::string& ipv6Address) {
    struct in6_addr temp;
    if (inet_pton(AF_INET6, ipv6Address.c_str(), &temp) != 1) {
        throw std::runtime_error("Invalid IP address");
    }
    memcpy(&this->ipv6Address, temp.s6_addr, sizeof(temp.s6_addr));
}

std::string DNSResourceRecord::RecordDataTypes::AAAA::toString(void) {
    char ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6Address, ip, sizeof(ip));
    return std::string(ip);
}

DNSSerializationBuffer DNSResourceRecord::RecordDataTypes::AAAA::serialize(void) {
    DNSSerializationBuffer buffer;
    buffer.serializeUInt128(ipv6Address);
    return buffer;
}

DNSResourceRecord::RecordDataTypes::AAAA DNSResourceRecord::RecordDataTypes::AAAA::deserialize(DNSDeserializationBuffer& buffer) {
    DNSResourceRecord::RecordDataTypes::AAAA resourceRecord;
    resourceRecord.ipv6Address = buffer.deserializeUInt128();
    return resourceRecord;
}
