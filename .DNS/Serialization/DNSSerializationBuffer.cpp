#include <arpa/inet.h>
#include <stdexcept>
#include <algorithm>
#include <cassert>

#include "DNSSerializationBuffer.h"

void DNSSerializationBuffer::serializeUInt8(uint8_t num) {
    m_Data.push_back(static_cast<std::byte>(num));
}

void DNSSerializationBuffer::serializeUInt16(uint16_t num) {
    num = htons(num);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[0]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[1]);
}

void DNSSerializationBuffer::serializeUInt32(uint32_t num) {
    num = htonl(num);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[0]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[1]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[2]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[3]);

}

void DNSSerializationBuffer::serializeUInt128(__uint128_t num) {
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[0]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[1]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[2]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[3]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[4]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[5]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[6]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[7]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[8]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[9]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[10]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[11]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[12]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[13]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[14]);
    m_Data.push_back(reinterpret_cast<std::byte*>(&num)[15]);
}

void DNSSerializationBuffer::serializeDNSLabel(std::string string) {
    assert (string.length() <= UINT8_MAX);
    m_Data.push_back(static_cast<std::byte>(string.length()));
    for (char character : string) {
        m_Data.push_back(static_cast<std::byte>(character));
    }
}

void DNSSerializationBuffer::concat(const DNSSerializationBuffer& buffer) {
    std::copy(buffer.m_Data.begin(), buffer.m_Data.end(), std::back_inserter(m_Data));
}

std::vector<std::byte> DNSSerializationBuffer::data(void) {
    return m_Data;
}
