#ifndef BE572AC7_3592_4408_A7A6_912DA333A733
#define BE572AC7_3592_4408_A7A6_912DA333A733

#include <cstdint>
#include <string>
#include <sstream>
#include <span>
#include <vector>

#include "Serialization/DNSSerializationBuffer.h"
#include "Serialization/DNSDeserializationBuffer.h"

class DNSDomainName {
private:
    DNSDomainName(std::string stringRepresentation);
    std::vector<std::string> components;

public:
    DNSDomainName() = default;
    static DNSDomainName fromString(std::string domainName);
    std::string toString(void) const;

    DNSSerializationBuffer serialize(void);
    static DNSDomainName deserialize(DNSDeserializationBuffer& buffer);

    bool operator==(const DNSDomainName& other) const;
};


#endif /* BE572AC7_3592_4408_A7A6_912DA333A733 */
