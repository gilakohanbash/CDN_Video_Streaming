#include <cstdint>
#include <ranges>
#include <iostream>

#include "DNSDomainName.h"
#include "Serialization/DNSSerializationBuffer.h"
#include "Serialization/DNSDeserializationBuffer.h"

// If using C++23, you can shorten this to:
//
//      DNSDomainName::DNSDomainName(std::string fullyQualifiedDomainName) {
//          for (const auto& component : std::ranges::views::split(fullyQualifiedDomainName, '.')) {
//              components.push_back(std::ranges::to<std::string>(component));
//          }
//      }

DNSDomainName::DNSDomainName(std::string fullyQualifiedDomainName) {
    std::stringstream ss(fullyQualifiedDomainName);
    std::string component;
    while (std::getline(ss, component, '.')) {
        components.push_back(component);
    }
    components.push_back(""); // root
}

DNSSerializationBuffer DNSDomainName::serialize(void) {
    DNSSerializationBuffer buffer;
    for (std::string component : components) {
        buffer.serializeDNSLabel(component);
    }
    return buffer;
}

DNSDomainName DNSDomainName::deserialize(DNSDeserializationBuffer& buffer) {
    DNSDomainName domainName;
    std::string label;
    do {
        label = buffer.deserializeDNSLabel();
        domainName.components.push_back(label);
    } while (label.length() > 0);
    return domainName;
}

DNSDomainName DNSDomainName::fromString(std::string domainName) {
    if (!domainName.ends_with(".")) {
        domainName.append("."); // Make it fully-qualified
    }
    return DNSDomainName(domainName);
}

std::string DNSDomainName::toString(void) const {
    std::string stringified;
    for (const auto& component : components | std::ranges::views::take(components.size() - 1)) {
        stringified += component + ".";
    }
    for (const auto& component : components | std::ranges::views::drop(components.size() - 1)) {
        stringified += component;
    }
    return stringified;
}

// If using C++23, you can shorten this to:
//
//      std::string DNSDomainName::toString(void) {
//          return std::ranges::views::join_with(components, '.') | std::ranges::to<std::string>();
//      }

bool DNSDomainName::operator==(const DNSDomainName& other) const {
    return this->components == other.components;
}
