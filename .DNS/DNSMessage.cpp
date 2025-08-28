#include <iostream>
#include <algorithm>
#include <ranges>

#include "DNSMessage.h"
#include "Serialization/DNSSerializationBuffer.h"
#include "Serialization/DNSDeserializationBuffer.h"

std::vector<std::byte> DNSMessage::serialize(void) {

    DNSSerializationBuffer buffer;

    buffer.concat(header.serialize());
    buffer.concat(question.serialize());
    for (DNSResourceRecord answer : answers) {
        buffer.concat(answer.serialize());
    }

    return buffer.data();
}

DNSMessage DNSMessage::deserialize(std::span<const std::byte> data) {

    DNSDeserializationBuffer buffer(data);
    DNSMessage message;
    message.header = DNSHeader::deserialize(buffer);
    message.question = DNSQuestion::deserialize(buffer);
    for (int i = 0; i < message.header.ANCOUNT; i++) {
        message.answers.push_back(DNSResourceRecord::deserialize(buffer));
    }

    return message;
}
