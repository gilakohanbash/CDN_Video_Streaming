CXXFLAGS = "-std=c++20"

INCLUDE_DIRS = DNS/ DNS/Serialization
INCLUDE_FILES = $(wildcard DNS/*.cpp DNS/Serialization/*.cpp)
INCLUDES = $(foreach dir,$(INCLUDE_DIRS),-I$(dir))

SRC_FILES = DNS/DNSMessage.cpp \
	DNS/DNSHeader.cpp \
	DNS/DNSQuestion.cpp \
	DNS/DNSResourceRecord.cpp \
	DNS/DNSDomainName.cpp \
	DNS/Serialization/DNSSerializationBuffer.cpp \
	DNS/Serialization/DNSDeserializationBuffer.cpp

OBJ_FILES = $(SRC_FILES:.cpp=.o)

.PHONY: all
all: nameserver

%.o: %.cpp
	g++ $(CXXFLAGS) $(INCLUDES) -c $< -o $@

miProxy: miProxy.o $(OBJ_FILES)
	g++ $(CXXFLAGS) $(INCLUDES) $^ -o $@

nameserver: nameserver.o $(OBJ_FILES)
	g++ $(CXXFLAGS) $(INCLUDES) $^ -o $@

clean:
	rm -f $(OBJ_FILES) *.o miProxy nameserver
