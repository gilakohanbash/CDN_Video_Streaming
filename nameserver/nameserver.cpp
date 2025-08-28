#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <ctime>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include "Serialization/DNSSerializationBuffer.h"
#include "Serialization/DNSDeserializationBuffer.h"
#include "DNSHeader.h"
#include "DNSQuestion.h"
#include "DNSResourceRecord.h"
#include "DNSMessage.h"
#include "DNSDomainName.h"
#include <climits>
#include <algorithm>
#include <set>
#include <iomanip>
#include <queue>
#include <cstring> // For strerror and errno

#define BUFFER_SIZE 1024

using namespace std;

// Global variable for log file name
string logFileName;
//int rrIndex = -1;  // Start at -1 so first increment gives 0

// Debug log file for troubleshooting
ofstream debugLog("/tmp/debug_log.txt", ios_base::app);

// Structures for geolocation mode
struct Node {
    int id;
    string type; // CLIENT, SERVER, SWITCH
    string ip;   // IP address or "NO_IP"
};

unordered_map<int, Node> nodes;
unordered_map<int, vector<pair<int, int>>> adjacencyList; // nodeId -> list of (neighborId, cost)
vector<int> serverNodeIds; // List of server node IDs

// Function to normalize domain names
string normalizeDomainName(const string& domainName) {
    string name = domainName;
    transform(name.begin(), name.end(), name.begin(), ::tolower);
    if (name.back() != '.') {
        name += '.';
    }
    return name;
}

// Function to read the round-robin IP list from a file
vector<string> readRoundRobinIPList(const string& filePath) {
    debugLog << "ROUND ROBIN" << endl;
    vector<string> ipList;
    ifstream file(filePath);
    string ip;
    while (file >> ip) {
        ipList.push_back(ip);
    }
    debugLog << "Read " << ipList.size() << " IPs from round-robin IP list:\n";
    for (const auto& ipAddr : ipList) {
        debugLog << ipAddr << endl;
    }
    return ipList;
}

// Add these debug functions at the top of your file
void debugPrintNodes() {
    debugLog << "\nAll Nodes in Topology:" << endl;
    for (const auto& [id, node] : nodes) {
        debugLog << "Node ID: " << id
                << ", Type: " << node.type
                << ", IP: " << (node.ip.empty() ? "NO_IP" : node.ip) << endl;
    }
}

void debugPrintAdjacencyList() {
    debugLog << "\nAdjacency List:" << endl;
    for (const auto& [nodeId, neighbors] : adjacencyList) {
        debugLog << "Node " << nodeId << " connects to: ";
        for (const auto& [neighborId, cost] : neighbors) {
            debugLog << "(" << neighborId << ", cost=" << cost << ") ";
        }
        debugLog << endl;
    }
}

// Function to read the network topology and build the graph
void readGeographicTopology(const string& filePath) {
    ifstream file(filePath);
    if (!file.is_open()) {
        debugLog << "Error opening topology file: " << filePath << endl;
        return;
    }

    // Clear existing data structures
    nodes.clear();
    adjacencyList.clear();
    serverNodeIds.clear();

    string line;
    int numNodes, numLinks;

    // Parse number of nodes
    file >> line >> numNodes;
    debugLog << "Number of nodes: " << numNodes << endl;

    // Read nodes
    for (int i = 0; i < numNodes; ++i) {
        int id;
        string type, ip;
        file >> id >> type >> ip;

        Node node;
        node.id = id;
        // Convert type to uppercase and trim whitespace
        transform(type.begin(), type.end(), type.begin(), ::toupper);
        node.type = type;
        node.ip = (ip == "NO_IP") ? "" : ip;

        if (node.type == "SERVER") {
            serverNodeIds.push_back(node.id);
            debugLog << "Added server node ID: " << node.id << " with IP: " << node.ip << endl;
        }

        nodes[id] = node;

        debugLog << "Parsed and added node: ID=" << id << ", Type=" << type << ", IP=" << (ip.empty() ? "NO_IP" : ip) << endl;

        if (node.type == "SERVER") {
            serverNodeIds.push_back(id);
            debugLog << "Added server node: " << id << " with IP: " << node.ip << endl;
        }

        debugLog << "Added node: ID=" << id
                << ", Type=" << type
                << ", IP=" << (ip == "NO_IP" ? "NO_IP" : ip) << endl;
    }

    // Parse number of links
    file >> line >> numLinks;
    debugLog << "Number of links: " << numLinks << endl;

    // Read links
    for (int i = 0; i < numLinks; ++i) {
        int origin, destination, cost;
        file >> origin >> destination >> cost;

        if (nodes.find(origin) == nodes.end() || nodes.find(destination) == nodes.end()) {
            debugLog << "Invalid link: node ID " << origin << " or " << destination << " not found." << endl;
            continue; // Skip this link if one of the nodes is not found
        }

        adjacencyList[origin].push_back({destination, cost});
        adjacencyList[destination].push_back({origin, cost});

        debugLog << "Added link: " << origin << " <-> " << destination << " (cost=" << cost << ")" << endl;
    }


    file.close();

    // Print debug information
    debugPrintNodes();
    debugPrintAdjacencyList();

    // Verify servers were found
    debugLog << "\nFound " << serverNodeIds.size() << " servers:" << endl;
    for (int serverId : serverNodeIds) {
        debugLog << "Server ID: " << serverId
                << ", IP: " << nodes[serverId].ip << endl;
    }
}

// Modified findClientNodeId function
int findClientNodeId(const string& clientIP) {
    debugLog << "\nLooking for client IP: " << clientIP << endl;
    debugLog << "Available nodes:" << endl;
    
    for (const auto& [id, node] : nodes) {
        debugLog << "Checking node " << id << ": type=" << node.type
                << ", ip=" << (node.ip.empty() ? "NO_IP" : node.ip) << endl;
        
        if (node.type == "CLIENT" && node.ip == clientIP) {
            debugLog << "Found matching client node: " << id << endl;
            return id;
        }
    }
    
    debugLog << "No matching client node found for IP " << clientIP << endl;
    return -1;
}

unordered_map<int, int> dijkstra(int startNodeId) {
    debugLog << "\nRunning Dijkstra's algorithm from node " << startNodeId << endl;
    
    unordered_map<int, int> distances;
    for (const auto& [id, _] : nodes) {
        distances[id] = INT_MAX;
    }
    distances[startNodeId] = 0;

    priority_queue<pair<int, int>, vector<pair<int, int>>, greater<pair<int, int>>> pq;
    pq.push({0, startNodeId});

    while (!pq.empty()) {
        auto [dist, nodeId] = pq.top();
        pq.pop();

        if (dist > distances[nodeId]) continue;

        debugLog << "Processing node " << nodeId << " at distance " << dist << endl;

        for (const auto& [neighborId, cost] : adjacencyList[nodeId]) {
            int newDist = dist + cost;
            if (newDist < distances[neighborId]) {
                distances[neighborId] = newDist;
                pq.push({newDist, neighborId});
                debugLog << "Updated distance to node " << neighborId
                        << " = " << newDist << endl;
            }
        }
    }

    return distances;
}


string selectClosestServer(int clientNodeId) {
    if (clientNodeId == -1) {
        debugLog << "Invalid client node ID" << endl;
        return "";
    }

    unordered_map<int, int> distances = dijkstra(clientNodeId);
    
    int minDistance = INT_MAX;
    int closestServerId = INT_MAX;

    for (int serverId : serverNodeIds) {
        int distance = distances[serverId];
        debugLog << "Distance to server " << serverId << " (IP: "
                 << nodes[serverId].ip << ") = "
                 << (distance == INT_MAX ? "INFINITY" : to_string(distance)) << endl;
        
        if (distance < minDistance ||
            (distance == minDistance && serverId < closestServerId)) {
            minDistance = distance;
            closestServerId = serverId;
        }
    }

    if (closestServerId == INT_MAX || distances[closestServerId] == INT_MAX) {
        debugLog << "No reachable server found. Sending NOERROR with no answers." << endl;
        return "";
    }

    debugLog << "Selected server " << closestServerId
             << " at distance " << minDistance << endl;
    return nodes[closestServerId].ip;
}



// Function to send a DNS response to the client
void sendDNSResponse(int sockfd, struct sockaddr_in& clientAddr, socklen_t clientAddrLen,
                     const DNSMessage& queryMessage,
                     const string& clientIP, const string& queryName, const string& responseIP) {
    DNSMessage responseMessage;
    
    // Preserve the ID and recursion desired flag from the query
    responseMessage.header = queryMessage.header;
    responseMessage.header.QR = 1;        // This is a response
    responseMessage.header.AA = 1;        // Authoritative answer
    responseMessage.header.QDCOUNT = 1;
    responseMessage.header.ANCOUNT = 1;
    responseMessage.header.NSCOUNT = 0;
    responseMessage.header.ARCOUNT = 0;
    responseMessage.header.RCODE = DNSRcode::NO_ERROR;

    // Copy the question section exactly as it was received
    responseMessage.question = queryMessage.question;

    // Create answer record
    DNSResourceRecord answer;
    answer.NAME = queryMessage.question.QNAME;
    answer.TYPE = DNSRRType::A;
    answer.CLASS = DNSRRClass::IN;
    answer.TTL = 300;
    answer.RDLENGTH = 4;

    answer.RDATA = DNSResourceRecord::RecordDataTypes::A(responseIP);
    responseMessage.answers.push_back(answer);

    // Serialize
    auto serializedResponse = responseMessage.serialize();
    ssize_t sentBytes = sendto(sockfd, serializedResponse.data(), serializedResponse.size(), 0,
                              (struct sockaddr*)&clientAddr, clientAddrLen);

    if (sentBytes < 0) {
        debugLog << "Failed to send DNS response: " << strerror(errno) << endl;
        return;
    }

    // Log only successful sends
    if (sentBytes == serializedResponse.size()) {
        ofstream logFile(logFileName, ios::app);  // Changed from trunc to app
        if (logFile.is_open()) {
            logFile << clientIP << " " << queryName << " " << responseIP << endl;
            logFile.flush();  // Added flush
            logFile.close();
        }
        debugLog << "Successfully sent response to " << clientIP
                << " with server IP " << responseIP << endl;
    } else {
        debugLog << "Partial send - sent " << sentBytes << " of "
                << serializedResponse.size() << " bytes" << endl;
    }
}
// Function to send a DNS error response (e.g., NXDOMAIN)
void sendDNSErrorResponse(int sockfd, struct sockaddr_in& clientAddr, socklen_t& clientAddrLen,
                          const DNSMessage& queryMessage,
                          const string& clientIP, const string& queryName, DNSRcode rcode, const string& errorMsg) {
    DNSMessage responseMessage;
    responseMessage.header = queryMessage.header;
    responseMessage.header.QR = 1; // Response
    responseMessage.header.AA = 1; // Authoritative Answer
    responseMessage.header.RCODE = rcode;

    // Set header counts
    responseMessage.header.QDCOUNT = 1; // One question
    responseMessage.header.ANCOUNT = 0; // No answers
    responseMessage.header.NSCOUNT = 0;
    responseMessage.header.ARCOUNT = 0;

    // Include the question section
    responseMessage.question = queryMessage.question;
    responseMessage.header.RCODE = rcode;

    // Serialize and send the response
    vector<byte> serializedResponse = responseMessage.serialize();
    ssize_t sentBytes = sendto(sockfd, serializedResponse.data(), serializedResponse.size(), 0,
                               (struct sockaddr*)&clientAddr, clientAddrLen);
    if (sentBytes < 0) {
        debugLog << "Error sending error response: " << strerror(errno) << endl;
    }

    debugLog << errorMsg << endl;
}

int main(int argc, char* argv[]) {
    string ip, domain;
    string rrIPListPath, netTopoPath;
    int port = 0;
    bool rrMode = false, geoMode = false;

    debugLog << "Received arguments:";
    for (int i = 0; i < argc; ++i) {
        debugLog << " " << argv[i];
    }
    debugLog << endl;

    // Parse command-line arguments
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "--ip" && i + 1 < argc)
            ip = argv[++i];
        else if (arg == "--port" && i + 1 < argc)
            port = stoi(argv[++i]);
        else if (arg == "--domain" && i + 1 < argc)
            domain = argv[++i];
        else if (arg == "--log-file-name" && i + 1 < argc)
            logFileName = argv[++i];
        else if (arg == "--round-robin-ip-list-file-path" && i + 1 < argc) {
            rrIPListPath = argv[++i];
            rrMode = true;
        } else if (arg == "--network-topology-file-path" && i + 1 < argc) {
            netTopoPath = argv[++i];
            geoMode = true;
        } else {
            cerr << "Unknown argument: " << arg << endl;
            return 1;
        }
    }

    // Default log file name as per assignment
    if (logFileName.empty()) {
        logFileName = "nameserver_log.txt";
    }

    // Clear the log file at the beginning of the program
    ofstream logFile(logFileName, ios::trunc);
    if (logFile.is_open()) {
        logFile.close();
    } else {
        cerr << "Error opening log file: " << logFileName << endl;
        return 1;
    }

    // Validate required arguments
    if (ip.empty() || port == 0 || domain.empty() || (rrMode && geoMode) || (!rrMode && !geoMode)) {
        debugLog << "Invalid arguments or both modes selected." << endl;
        return 1;
    }

    // Variables for round-robin mode
    vector<string> roundRobinIPs;
    int rrIndex = 0;

    // Initialize based on mode
    if (rrMode) {
        // Read round-robin IP list
        roundRobinIPs = readRoundRobinIPList(rrIPListPath);
        if (roundRobinIPs.empty()) {
            debugLog << "Round-robin IP list is empty." << endl;
            return 1;
        }
    } else if (geoMode) {
        // Read network topology
        readGeographicTopology(netTopoPath);
        if (serverNodeIds.empty()) {
            debugLog << "No servers found in the topology." << endl;
            return 1;
        }
    }

    // Create UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        debugLog << "Socket creation failed: " << strerror(errno) << endl;
        return 1;
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        debugLog << "Failed to set SO_REUSEADDR: " << strerror(errno) << endl;
        close(sockfd);
        return 1;
    }

struct sockaddr_in serverAddr {};
serverAddr.sin_family = AF_INET;
serverAddr.sin_port = htons(port);
//serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
//serverAddr.sin_addr.s_addr = INADDR_ANY;  // Changed from specific IP to INADDR_ANY

    
    // Convert IP address from string to binary form
    if (inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr) != 1) {
        debugLog << "Invalid IP address: " << ip << endl;
        close(sockfd);
        return 1;
    }

    // Bind socket
    if (bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        debugLog << "Bind failed: " << strerror(errno) << endl;
        close(sockfd);
        return 1;
    }

    debugLog << "DNS Server listening on " << ip << ":" << port << endl;

    // Main loop
    while (true) {
        struct sockaddr_in clientAddr {};
        socklen_t clientAddrLen = sizeof(clientAddr);
        byte buffer[BUFFER_SIZE];

        ssize_t msgLen = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                                 (struct sockaddr*)&clientAddr, &clientAddrLen);
        
        if (msgLen < 0) {
            debugLog << "Error receiving: " << strerror(errno) << endl;
            continue;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
        debugLog << "Received " << msgLen << " bytes from " << clientIP << endl;

        try {
            auto queryMessage = DNSMessage::deserialize(span(buffer, msgLen));
            string queryDomain = normalizeDomainName(queryMessage.question.QNAME.toString());
            string configuredDomain = normalizeDomainName(domain);

            debugLog << "Query domain: " << queryDomain << endl;

            if (queryDomain == configuredDomain) {
                string responseIP;
                debugLog << "Domain match found. Mode: " << (geoMode ? "Geo" : "RoundRobin") << endl;
                
            if (geoMode) {
                debugLog << "Looking for client: " << clientIP << endl;
                int clientNodeId = findClientNodeId(clientIP);
                 debugLog << "Client node ID: " << clientNodeId << endl;
                //string responseIP;
                
                if (clientNodeId != -1) {
                    responseIP = selectClosestServer(clientNodeId);
                     debugLog << "Selected server IP: " << (responseIP.empty() ? "NONE" : responseIP) << endl;
                    
                    if (responseIP.empty()) {
                        // NO_PATH case - need to log and send specific response
                        ofstream logFile(logFileName, ios::app); //changed to app?
                        if (logFile.is_open()) {
                            logFile << clientIP << " " << queryDomain << " NO_PATH" << endl;
                            logFile.close();
                        }
                        
                        // Send NOERROR response with no answers
                        DNSMessage responseMessage;
                        responseMessage.header = queryMessage.header;
                        responseMessage.header.QR = 1;
                        responseMessage.header.RCODE = DNSRcode::NO_ERROR;
                        responseMessage.header.QDCOUNT = 1;
                        responseMessage.header.ANCOUNT = 0;
                        responseMessage.header.NSCOUNT = 0;
                        responseMessage.header.ARCOUNT = 0;
                        responseMessage.question = queryMessage.question;
                        
                        auto serializedResponse = responseMessage.serialize();
                        sendto(sockfd, serializedResponse.data(), serializedResponse.size(), 0,
                            (struct sockaddr*)&clientAddr, clientAddrLen);
                        continue;
                    }
                } else {
                    // Client not found in topology - handle same as NO_PATH
                    ofstream logFile(logFileName, ios::trunc);
                    if (logFile.is_open()) {
                        logFile << clientIP << " " << queryDomain << " NO_PATH" << endl;
                        logFile.close();
                    }
                    
                    // Send NOERROR response with no answers
                    DNSMessage responseMessage;
                    responseMessage.header = queryMessage.header;
                    responseMessage.header.QR = 1;
                    responseMessage.header.RCODE = DNSRcode::NO_ERROR;
                    responseMessage.header.QDCOUNT = 1;
                    responseMessage.header.ANCOUNT = 0;
                    responseMessage.header.NSCOUNT = 0;
                    responseMessage.header.ARCOUNT = 0;
                    responseMessage.question = queryMessage.question;
                    
                    auto serializedResponse = responseMessage.serialize();
                    sendto(sockfd, serializedResponse.data(), serializedResponse.size(), 0,
                        (struct sockaddr*)&clientAddr, clientAddrLen);
                    continue;
                }
            } else {
                    responseIP = roundRobinIPs[rrIndex];
                    rrIndex = (rrIndex + 1) % roundRobinIPs.size();
                    debugLog << "Round Robin selected IP: " << responseIP << endl;
                    
                    // Make sure we're sending the response
                    sendDNSResponse(sockfd, clientAddr, clientAddrLen,
                                queryMessage, clientIP, queryDomain, responseIP);
                //responseIP = roundRobinIPs[rrIndex = (rrIndex + 1) % roundRobinIPs.size()];
                //debugLog << "Round Robin selected IP " << responseIP << " at index " << rrIndex << endl;
            }

                if (!responseIP.empty()) {
                    debugLog << "About to send DNS response with IP: " << responseIP << endl;
                    sendDNSResponse(sockfd, clientAddr, clientAddrLen,
                                queryMessage, clientIP, queryDomain, responseIP);
                    debugLog << "Sent response with IP " << responseIP << endl;
                } else {
                    debugLog << "No response IP available, sending error response" << endl;
                    sendDNSErrorResponse(sockfd, clientAddr, clientAddrLen,
                                        queryMessage, clientIP, queryDomain,
                                        DNSRcode::NO_ERROR, "No server available");
                }
            } else {
                sendDNSErrorResponse(sockfd, clientAddr, clientAddrLen,
                                   queryMessage, clientIP, queryDomain,
                                   DNSRcode::NAME_ERROR, "Domain not found");
            }
        } catch (const exception& e) {
            debugLog << "Error processing query: " << e.what() << endl;
        }
    }

    close(sockfd);
    return 0;
}



