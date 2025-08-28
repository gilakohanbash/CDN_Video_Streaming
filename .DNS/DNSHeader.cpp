#include <iostream>
#include <cstdint>
#include <arpa/inet.h>

#include "DNSHeader.h"
#include "Serialization/DNSSerializationBuffer.h"
#include "Serialization/DNSDeserializationBuffer.h"

DNSSerializationBuffer DNSHeader::serialize(void) {

    DNSSerializationBuffer buffer;

    buffer.serializeUInt16(ID);
    uint8_t byte1 = (QR << 7) | (static_cast<uint8_t>(OPCODE) << 3) | (AA << 2) | (TC << 1) | RD;
    buffer.serializeUInt8(byte1);
    uint8_t byte2 = (RA << 7) | (Z << 4) | static_cast<uint8_t>(RCODE);
    buffer.serializeUInt8(byte2);
    buffer.serializeUInt16(QDCOUNT);
    buffer.serializeUInt16(ANCOUNT);
    buffer.serializeUInt16(NSCOUNT);
    buffer.serializeUInt16(ARCOUNT);

    return buffer;
}

DNSHeader DNSHeader::deserialize(DNSDeserializationBuffer& buffer) {

    DNSHeader header;

    header.ID = buffer.deserializeUInt16();
    uint8_t byte1 = buffer.deserializeUInt8();
    header.QR = (byte1 >> 7) & 0x01;
    header.OPCODE = static_cast<DNSOpcode>((byte1 >> 3) & 0x0F);
    header.AA = (byte1 >> 2) & 0x01;
    header.TC = (byte1 >> 1) & 0x01;
    header.RD = byte1 & 0x01;
    uint8_t byte2 = buffer.deserializeUInt8();
    header.RA = (byte2 >> 7) & 0x01;
    header.Z = (byte2 >> 6) & 0x1;
    header.AD = (byte2 >> 5) & 0x1;
    header.CD = (byte2 >> 4) & 0x1;
    header.RCODE = static_cast<DNSRcode>(byte2 & 0x0F);
    header.QDCOUNT = buffer.deserializeUInt16();
    header.ANCOUNT = buffer.deserializeUInt16();
    header.NSCOUNT = buffer.deserializeUInt16();
    header.ARCOUNT = buffer.deserializeUInt16();

    return header;
}
