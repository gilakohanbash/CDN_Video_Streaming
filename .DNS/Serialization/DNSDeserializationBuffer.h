#ifndef ED471E99_3908_47D2_8E46_5ADCB44A8062
#define ED471E99_3908_47D2_8E46_5ADCB44A8062

#include <cstdint>
#include <string>
#include <span>
#include <vector>

class NotEnoughDataException : public std::exception { };

class DNSDeserializationBuffer {
private:
    std::span<const std::byte> span;
public:
    DNSDeserializationBuffer(std::span<const std::byte> data);
    uint8_t deserializeUInt8(void);
    uint16_t deserializeUInt16(void);
    uint32_t deserializeUInt32(void);
    __uint128_t deserializeUInt128(void);
    std::string deserializeDNSLabel(void);
};

#endif /* ED471E99_3908_47D2_8E46_5ADCB44A8062 */
