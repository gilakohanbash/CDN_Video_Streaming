#ifndef CC7061B7_0353_4BB8_B075_027284DEF298
#define CC7061B7_0353_4BB8_B075_027284DEF298

#include <vector>
#include <cstdint>
#include <string>

class DNSSerializationBuffer {
private:
    std::vector<std::byte> m_Data;
public:
    void serializeUInt8(uint8_t num);
    void serializeUInt16(uint16_t num);
    void serializeUInt32(uint32_t num);
    void serializeUInt128(__uint128_t num);
    void serializeDNSLabel(std::string string);
    void concat(const DNSSerializationBuffer& buffer);
    std::vector<std::byte> data(void);
};

#endif /* CC7061B7_0353_4BB8_B075_027284DEF298 */
