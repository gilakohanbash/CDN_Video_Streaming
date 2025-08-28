#ifndef EA3AE37A_F279_42C0_8B95_03E763549912
#define EA3AE37A_F279_42C0_8B95_03E763549912

#include <span>
#include <stdexcept>

#include "DNSHeader.h"
#include "DNSQuestion.h"
#include "DNSResourceRecord.h"

struct DNSMessage {
    DNSHeader header;
    DNSQuestion question;
    std::vector<DNSResourceRecord> answers;

    std::vector<std::byte> serialize(void);
    static DNSMessage deserialize(std::span<const std::byte> data);
};

#endif /* EA3AE37A_F279_42C0_8B95_03E763549912 */
