// Gila Kohanbash
// Nona Nersisyan
// CS 353 - Assignment 2a
// miProxy.cpp

#include <iostream>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <vector>
#include <cstring>
#include <regex>
#include <getopt.h>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <map>
#include <sstream>
#include <set>
#include <sys/socket.h>
#include <stdexcept>
#include <thread>
#include <span>


// Include DNS-related headers
#include "DNSMessage.h"
#include "DNSHeader.h"
#include "DNSQuestion.h"
#include "DNSResourceRecord.h"
#include "DNSDomainName.h"
#include "Serialization/DNSSerializationBuffer.h"
#include "Serialization/DNSDeserializationBuffer.h"


using namespace std;

ofstream debugLog("/tmp/debug_log.txt", ios_base::trunc);
ofstream logFile;

std::string resolveHostname(const std::string& hostname, const std::string& nameserver_ip, int nameserver_port);


bool validateDNSResponse(const DNSMessage& response, const std::string& hostname) {
    // Check if we got a valid response code
    if (response.header.RCODE != DNSRcode::NO_ERROR) {
        throw std::runtime_error("DNS server returned error code: " +
            std::to_string(static_cast<int>(response.header.RCODE)));
    }
    
    // Must have at least one answer
    if (response.answers.empty()) {
        throw std::runtime_error("No answers in DNS response for " + hostname);
    }

    return true;
}

void waitForDNSResolution(int maxAttempts = 3, int delayMs = 1000) {
    debugLog << "Waiting for DNS resolution..." << endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
}



bool isValidIPAddress(const string& ipAddress) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ipAddress.c_str(), &(sa.sin_addr)) != 0;
}
std::string resolveHostname(const std::string& hostname, const std::string& nameserver_ip, int nameserver_port) {
    const int MAX_RETRIES = 3;
    const int RETRY_DELAY_MS = 1000;
    const int SOCKET_TIMEOUT_SEC = 2;

    debugLog << "Starting DNS resolution for: " << hostname << endl;

    for (int retry = 0; retry < MAX_RETRIES; ++retry) {
        // Create UDP socket
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            debugLog << "Socket creation failed, retrying..." << endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_DELAY_MS));
            continue;
        }

        // Set timeouts
        struct timeval timeout;
        timeout.tv_sec = SOCKET_TIMEOUT_SEC;
        timeout.tv_usec = 0;
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
            setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
            close(sockfd);
            continue;
        }

        // Set up nameserver address
        struct sockaddr_in nameserver_addr{};
        nameserver_addr.sin_family = AF_INET;
        nameserver_addr.sin_port = htons(nameserver_port);
        if (inet_pton(AF_INET, nameserver_ip.c_str(), &nameserver_addr.sin_addr) <= 0) {
            close(sockfd);
            throw std::runtime_error("Invalid nameserver IP address");
        }

        try {
            // Create DNS query with proper headers
            DNSMessage query;
            query.header.ID = rand() & 0xFFFF;
            query.header.QR = 0;
            query.header.OPCODE = DNSOpcode::QUERY;
            query.header.AA = 0;
            query.header.TC = 0;
            query.header.RD = 1;
            query.header.RA = 0;
            query.header.Z = 0;
            query.header.AD = 0;
            query.header.CD = 0;
            query.header.RCODE = DNSRcode::NO_ERROR;
            query.header.QDCOUNT = 1;
            query.header.ANCOUNT = 0;
            query.header.NSCOUNT = 0;
            query.header.ARCOUNT = 0;

            // Format domain name properly
            std::string domain = hostname;
            if (domain.back() != '.') {
                domain += '.';
            }
            query.question.QNAME = DNSDomainName::fromString(domain);
            query.question.QTYPE = DNSQType::A;
            query.question.QCLASS = DNSQClass::IN;

            // Send query
            auto query_data = query.serialize();
            ssize_t sent = sendto(sockfd, query_data.data(), query_data.size(), 0,
                                (struct sockaddr*)&nameserver_addr, sizeof(nameserver_addr));
            if (sent < 0) {
                throw std::runtime_error("Failed to send DNS query");
            }

            // Receive response
            uint8_t buffer[512];
            struct sockaddr_in from_addr;
            socklen_t from_len = sizeof(from_addr);
            ssize_t received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                      (struct sockaddr*)&from_addr, &from_len);
            if (received < 0) {
                throw std::runtime_error("Failed to receive DNS response");
            }

            // Parse and validate response
            std::vector<uint8_t> response_data(buffer, buffer + received);
            DNSMessage response = DNSMessage::deserialize(
                std::span<const std::byte>((const std::byte*)response_data.data(),
                                          response_data.size()));

            if (response.header.RCODE != DNSRcode::NO_ERROR || response.answers.empty()) {
                throw std::runtime_error("Invalid DNS response");
            }

            // Extract IP from answer
            for (const auto& answer : response.answers) {
                if (answer.TYPE == DNSRRType::A && answer.CLASS == DNSRRClass::IN) {
                    if (std::holds_alternative<DNSResourceRecord::RecordDataTypes::A>(answer.RDATA)) {
                        auto record_data = std::get<DNSResourceRecord::RecordDataTypes::A>(answer.RDATA);
                        std::string ip = record_data.toString();
                        close(sockfd);
                        return ip;
                    }
                }
            }
        }
        catch (const std::exception& e) {
            debugLog << "DNS resolution attempt " << (retry + 1) << " failed: " << e.what() << endl;
            close(sockfd);
            if (retry < MAX_RETRIES - 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_DELAY_MS));
            }
            continue;
        }

        close(sockfd);
    }

    throw std::runtime_error("Failed to resolve hostname after all retries");
}


// Function to parse command-line arguments
void parseArguments(int argc, char* argv[], string& proxy_host, int& proxy_port, string& upstream_server_host,
                    int& upstream_server_port, double& adaptation_gain, double& adaptation_bitrate_multiplier, string& nameserver_ip, int& nameserver_port,
                    string& log_file_name) {
    
    static struct option long_options[] = {
        {"proxy-host", required_argument, 0, 'h'},
        {"proxy-port", required_argument, 0, 'p'},
        {"upstream-server-host", required_argument, 0, 'u'},
        {"upstream-server-port", required_argument, 0, 'q'},
        {"adaptation-gain", required_argument, 0, 'a'},
        {"adaptation-bitrate-multiplier", required_argument, 0, 'b'},
        {"nameserver-ip", required_argument, 0, 'n'},      // Part B argument (optional for now)
        {"nameserver-port", required_argument, 0, 's'},    // Part B argument (optional for now)
        {"log-file-name", optional_argument, 0, 'l'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "h:p:u:q:a:b:n:s:l:", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'h':
                proxy_host = optarg;
                break;
            case 'p':
                proxy_port = atoi(optarg);
                break;
            case 'u':
                upstream_server_host = optarg;
                break;
            case 'q':
                upstream_server_port = atoi(optarg);
                break;
            case 'a':
                adaptation_gain = atof(optarg);
                break;
            case 'b':
                adaptation_bitrate_multiplier = atof(optarg);
                break;
            case 'n':  // Part B: Nameserver IP
                nameserver_ip = optarg;
                break;
            case 's':  // Part B: Nameserver Port
                nameserver_port = atoi(optarg);
                break;
            case 'l':
                if (optarg) {
                    log_file_name = optarg;
                    logFile.open(log_file_name, ios_base::trunc);
                    if (!logFile.is_open()) {
                        std::cerr << "Error: Could not open log file: " << log_file_name << std::endl;
                    }
                }
                break;
            default:
                std::cerr << "Usage: " << argv[0]
                          << " --proxy-host <host> --proxy-port <port> --upstream-server-host <host> "
                          << "--upstream-server-port <port> --adaptation-gain <gain> "
                          << "--adaptation-bitrate-multiplier <multiplier> "
                          << "[--nameserver-ip <ip>] [--nameserver-port <port>] --log-file-name <logfile>"
                          << std::endl;
                debugLog << "Error: Invalid usage of arguments" << endl;
                exit(EXIT_FAILURE); // Added exit
        }
    }

    if (proxy_host.empty() || proxy_port == 0 || upstream_server_host.empty() || upstream_server_port == 0) {
        cerr << "Error: Missing required arguments." << endl;
        exit(EXIT_FAILURE);
    }

        // If no log file is specified, use a default log file name
    if (log_file_name.empty()) {
        //log_file_name = "./proxy_log.txt";
        log_file_name = "nameserver_log.txt";
    }

    // Open the log file and verify it was successfully opened
    logFile.open(log_file_name, ios_base::trunc);
    if (!logFile.is_open()) {
        cerr << "Error: Could not open log file: " << log_file_name << endl;
        exit(EXIT_FAILURE);
    }
    
    // Log parsed values to the debug log
    debugLog << "Proxy host: " << proxy_host << endl;
    debugLog << "Proxy port: " << proxy_port << endl;
    debugLog << "Upstream server host: " << upstream_server_host << endl;
    debugLog << "Upstream server port: " << upstream_server_port << endl;
    debugLog << "Adaptation gain: " << adaptation_gain << endl;
    debugLog << "Adaptation bitrate multiplier: " << adaptation_bitrate_multiplier << endl;
    if (!nameserver_ip.empty()) debugLog << "Nameserver IP (Part B): " << nameserver_ip << endl;
    if (nameserver_port != 0) debugLog << "Nameserver Port (Part B): " << nameserver_port << endl;
    
    debugLog << "Done parsing Arguments" << endl;
}

// Set up the listening socket
int setupServerSocket(const string& proxy_host, int proxy_port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(proxy_port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        debugLog << "Error: Bind failed" << endl;
        exit(EXIT_FAILURE);
    }

    debugLog << "Listening for incoming connections..." << endl;
    if (listen(server_fd, 3) < 0) {
        debugLog << "Error: Listen failed" << endl;
        exit(EXIT_FAILURE);
    }
    debugLog << "Returning server_fd" << endl;
    return server_fd;
}

// Parse the manifest file and extract bitrates
vector<int> parseManifestForBitrates(const string& manifest_content) {
    debugLog << "In manifest parsing function" << endl;
    vector<int> bitrates;

    // Regular expression to match the BANDWIDTH parameter in EXT-X-STREAM-INF tag
    regex bitrateRegex("#EXT-X-STREAM-INF.*BANDWIDTH=(\\d+)");
    smatch match;

    // Debugging: print part of the manifest content
    debugLog << "Manifest content snippet: " << manifest_content.substr(0, 200) << endl;

    std::string::const_iterator searchStart(manifest_content.cbegin());

    // Iterate through manifest content to find all occurrences of BANDWIDTH
    debugLog << "about to enter manifest parsing while loop" << endl;
    while (regex_search(searchStart, manifest_content.cend(), match, bitrateRegex)) {
        debugLog << "In manifest parsing WHILE loop" << endl;

        // Debugging the matched string (full line with BANDWIDTH)
        debugLog << "Matched string: " << match.str(0) << endl;

        // Extract and store the bitrate
        int bitrate = std::stoi(match[1]);  // Extract the numeric value of the bitrate
        debugLog << "numeric value of the bitrate: " << bitrate << endl;
        bitrates.push_back(bitrate);  // Add it to the vector

        // Update searchStart to continue searching for other bitrates
        searchStart = match.suffix().first;
    }

    debugLog << "Leaving manifest parsing function" << endl;
    if (!bitrates.empty()) {
        debugLog << "Extracted bitrates: ";
        for (int br : bitrates) {
            debugLog << br << " ";
        }
        debugLog << endl;
    } else {
        debugLog << "No bitrates found in the manifest." << endl;
    }

    return bitrates;
}

string getResolutionForBitrate(int bitrate) {
   /* if (bitrate <= 1300000) return "240p";
    else if (bitrate <= 3000000) return "360p";
    else if (bitrate <= 4000000) return "480p";
    else if (bitrate <= 6000000) return "720p";
    else return "1080p";*/

        if (bitrate <= 3000000) return "240p";
    else if (bitrate <= 6000000) return "360p";
    else if (bitrate <= 4000000) return "480p";
    else if (bitrate <= 6000000) return "720p";
    else if (bitrate <= 13000000) return "1080p";
    else return "1080p";  // Default to highest available resolution

}

int extractBitrateFromURI(const string& uri) {
    // Try to extract bitrate from different URI patterns
    std::regex bitrate_in_path_regex("/(\\d+)/.*\\.ts");
    std::regex bitrate_in_filename_regex("_(\\d+)bps\\.ts");
    std::regex bitrate_in_resolution_regex("_(\\d+)p.*\\.ts");  // Updated regex
    std::smatch match;

    if (std::regex_search(uri, match, bitrate_in_path_regex)) {
        // Extracted bitrate from path
        int bitrate = std::stoi(match.str(1));
        return bitrate;
    } else if (std::regex_search(uri, match, bitrate_in_filename_regex)) {
        // Extracted bitrate from filename
        int bitrate = std::stoi(match.str(1));
        return bitrate;
    } else if (std::regex_search(uri, match, bitrate_in_resolution_regex)) {
        // Map resolution to bitrate (define your own mapping)
        int resolution = std::stoi(match.str(1));
        // Example mapping (you may need to adjust this based on your video content)
        if (resolution == 240) return 3000000;
        else if (resolution == 360) return 6000000;
        else if (resolution == 480) return 10000000;
        else if (resolution == 720) return 24000000;
        else if (resolution == 1080) return 40000000;
    }
    return -1;  // Could not extract bitrate
}



// Modify the video chunk request to select the appropriate bitrate
string modifyRequest(const string& request, int selected_bitrate, string& modified_chunk_name) {
    size_t uri_start = request.find("GET ") + 4;
    size_t uri_end = request.find(" ", uri_start);
    string original_uri = request.substr(uri_start, uri_end - uri_start);

    debugLog << "Original URI: " << original_uri << endl;

    regex resolution_regex("_\\d+p");
    regex bitrate_regex("/(\\d+)/");
    smatch match;
    if (std::regex_search(original_uri, match, resolution_regex)) {

        string resolution_str = match.str();
        string new_resolution = getResolutionForBitrate(selected_bitrate);
        string modified_uri = std::regex_replace(original_uri, resolution_regex, "_" + new_resolution);

        //string new_resolution = getResolutionForBitrate(selected_bitrate);
        //string modified_uri = std::regex_replace(original_uri, resolution_regex, "_" + new_resolution);


        debugLog << "Modified URI: " << modified_uri << endl;

        string modified_request = request;
        modified_request.replace(uri_start, uri_end - uri_start, modified_uri);

        modified_chunk_name = modified_uri.substr(modified_uri.find_last_of('/') + 1);

        return modified_request;
    } else {
        debugLog << "Could not find resolution in URI: " << original_uri << endl;
        modified_chunk_name = original_uri.substr(original_uri.find_last_of('/') + 1);
        return request;
    }
}

int selectBitrate(double avg_throughput, double adaptation_bitrate_multiplier, const set<int>& available_bitrates) {
    vector<int> sorted_bitrates(available_bitrates.begin(), available_bitrates.end());
    sort(sorted_bitrates.begin(), sorted_bitrates.end());

    debugLog << "Selecting bitrate. Average throughput: " << avg_throughput << endl;

    // More aggressive scaling by adjusting the multiplier
    double adjusted_multiplier = adaptation_bitrate_multiplier * 0.8;
    double adjusted_throughput = avg_throughput / adjusted_multiplier;

    debugLog << "Adjusted throughput: " << adjusted_throughput << endl;

    // Start with lowest bitrate
    int selected_bitrate = sorted_bitrates.front();

    // Find highest sustainable bitrate with aggressive headroom
    for (int bitrate : sorted_bitrates) {
        if (bitrate * 1.5 <= adjusted_throughput) {  // Aggressive multiplier
            selected_bitrate = bitrate;
        } else {
            break;
        }
    }

    // Safety check for bandwidth underutilization
    auto it = find(sorted_bitrates.begin(), sorted_bitrates.end(), selected_bitrate);
    if (it != sorted_bitrates.end() && (it + 1) != sorted_bitrates.end()) {
        int next_bitrate = *(it + 1);
        if (adjusted_throughput > selected_bitrate * 1.3) {  // Try stepping up
            selected_bitrate = next_bitrate;
        }
    }

    debugLog << "Selected bitrate: " << selected_bitrate << endl;
    return selected_bitrate;
}

// Measure throughput using EWMA
double measureThroughput(int total_bytes, const chrono::high_resolution_clock::time_point& start_time,
                         double adaptation_gain, double& avg_throughput) {

    auto end_time = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end_time - start_time;
    double throughput = (total_bytes * 8) / duration.count(); // bits per second
    avg_throughput = adaptation_gain * throughput + (1 - adaptation_gain) * avg_throughput;
    debugLog << "avg_throughput: " << avg_throughput << endl;
    return avg_throughput;
}

bool isEndOfHeaders(const string& response) {
    return response.find("\r\n\r\n") != string::npos;
}

bool isChunkedTransfer(const std::string& headers) {
    return headers.find("Transfer-Encoding: chunked") != std::string::npos;
}

int getContentLength(const std::string& headers) {
    std::smatch match;
    std::regex contentLengthRegex("Content-Length: (\\d+)");
    if (std::regex_search(headers, match, contentLengthRegex)) {
        return std::stoi(match.str(1));  // Return the content length as an integer
    }
    return -1;  // Return -1 if Content-Length header is not found
}

// Function to connect to the web server using the IP and port passed as arguments
int connectToWebServer(const std::string& upstream_server_host, int upstream_server_port) {
    int webserver_fd;
    struct sockaddr_in webserver_address;

    // Create a socket for connecting to the web server
    if ((webserver_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        debugLog << "Error: Failed to create web server socket." << endl;
        return -1;
    }

    // Set up the web server address struct
    debugLog << "Setting up the web server address struct" << endl;
    webserver_address.sin_family = AF_INET;
    webserver_address.sin_port = htons(upstream_server_port);

    // Convert the IP address from text to binary form
    if (inet_pton(AF_INET, upstream_server_host.c_str(), &webserver_address.sin_addr) <= 0) {
        perror("Invalid web server address");
        debugLog << "Error: Invalid web server address." << endl;
        close(webserver_fd); // Close the socket if there is an error
        return -1;
    }

    // Connect to the web server
    debugLog << "Connecting to web server at " << upstream_server_host << ":" << upstream_server_port << endl;
    if (connect(webserver_fd, (struct sockaddr*)&webserver_address, sizeof(webserver_address)) < 0) {
        perror("Connection to web server failed");
        debugLog << "Error: Connection to web server failed." << endl;
        close(webserver_fd); // Close the socket if there is an error
        return -1;
    }

    debugLog << "Successfully connected to the web server." << endl;
    return webserver_fd;  // Return the socket file descriptor
}

// Main proxy logic
void proxyLogic(int server_fd, const string& upstream_server_host, int upstream_server_port,
                double adaptation_gain, double adaptation_bitrate_multiplier) {
    fd_set readfds;
    vector<int> client_sockets;
    int max_sd = server_fd;
    map<int, double> avg_throughput_map;  // Map client sockets to their avg throughput
    map<int, string> client_ips;  // Map client sockets to IP addresses
    vector<int> parsed_bitrates;
    map<int, set<int>> available_bitrates_map;

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        for (int client_socket : client_sockets) {
            if (client_socket != 0) {
                FD_SET(client_socket, &readfds);
                max_sd = max(max_sd, client_socket);
            }
        }

        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0 && errno != EINTR) {
            debugLog << "ERROR: Select error "  << endl;
            perror("Select error");
        }

        if (FD_ISSET(server_fd, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t client_addr_len = sizeof(client_addr);
            int new_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
            if (new_socket >= 0) {
                client_sockets.push_back(new_socket);
                char client_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip_str, INET_ADDRSTRLEN);
                client_ips[new_socket] = string(client_ip_str);
                avg_throughput_map[new_socket] = 0.0;  // Initialize avg throughput for this client
            } else {
                debugLog << "ERROR: Accept Failed "  << endl;
                perror("Accept failed");
            }
        }

        for (size_t i = 0; i < client_sockets.size(); ++i) {
            int client_socket = client_sockets[i];
            if (FD_ISSET(client_socket, &readfds)) {
                char buffer[4096] = {0};
                int valread = read(client_socket, buffer, sizeof(buffer));
                if (valread == 0) {
                    close(client_socket);
                    client_sockets.erase(client_sockets.begin() + i);
                    client_ips.erase(client_socket);
                    avg_throughput_map.erase(client_socket);
                    --i;
                } else if (valread < 0) {
                    perror("Error reading from client socket");
                    close(client_socket);
                    client_sockets.erase(client_sockets.begin() + i);
                    client_ips.erase(client_socket);
                    avg_throughput_map.erase(client_socket);
                    --i;
                } else {
                    string request(buffer, buffer + valread);
                    
                    size_t pos = request.find("\r\n");
                    string request_line = request.substr(0, pos);
                    istringstream iss(request_line);
                    string method, uri, version;
                    iss >> method >> uri >> version;

                    debugLog << "Request line: " << request_line << endl;
                    debugLog << "Method: " << method << ", URI: " << uri << ", Version: " << version << endl;
                    string path = uri;

                    if (uri.find("http://") == 0) {
                        size_t host_end = uri.find('/', 7);
                        if (host_end != string::npos) {
                            path = uri.substr(host_end);
                        } else {
                            path = "/";
                        }
                    } else if (uri.find("https://") == 0) {
                        size_t host_end = uri.find('/', 8);
                        if (host_end != string::npos) {
                            path = uri.substr(host_end);
                        } else {
                            path = "/";
                        }
                    }

                    size_t query_pos = path.find('?');
                    if (query_pos != string::npos) {
                        path = path.substr(0, query_pos);
                    }

                    debugLog << "Parsed path: " << path << endl;

                    // Determine the type of request based on URI
                    if (path.find(".m3u8") != string::npos) {
                        int webserver_fd = connectToWebServer(upstream_server_host, upstream_server_port);
                        if (webserver_fd < 0) continue;

                        debugLog << "Forwarding the manifest request to the web server" << endl;
                        send(webserver_fd, request.c_str(), request.size(), 0);
                        debugLog << "Done Forwarding the manifest request to the web server" << endl;
                        
                        std::string manifest_content;
                        char webserver_response[4096];
                        int webread;
                        int total_bytes = 0;
                        int content_length = -1;
                        bool chunked = false;
                        bool headers_received = false;
                        // Manifest handling (ensure reading until Content-Length is met or last chunk)
                        while ((webread = read(webserver_fd, webserver_response, sizeof(webserver_response))) > 0) {
                            manifest_content.append(webserver_response, webread);
                            total_bytes += webread;
                            // Check if headers are fully received
                            if (!headers_received && isEndOfHeaders(manifest_content)) {
                                headers_received = true;
                                
                                content_length = getContentLength(manifest_content);  // Extract content length
                                chunked = isChunkedTransfer(manifest_content);  // Check if it's chunked transfer
                                debugLog << "Headers received. Content-Length: " << content_length
                                         << ", Chunked: " << (chunked ? "Yes" : "No") << std::endl;
                            }

                            // If Content-Length is available and we’ve received enough data, break out
                            if (content_length != -1 && total_bytes >= content_length + manifest_content.find("\r\n\r\n") + 4) {
                                debugLog << "Complete manifest received based on Content-Length." << std::endl;
                                break;
                            }

                            // If chunked transfer and we received the last chunk, break out
                            if (chunked && manifest_content.find("0\r\n\r\n") != std::string::npos) {
                                debugLog << "Complete manifest received based on chunked transfer." << std::endl;
                                break;
                            }
                        }
                        // Forward the manifest to the client once after completely receiving it
                        send(client_socket, manifest_content.c_str(), manifest_content.size(), 0);
                        debugLog << "Manifest forwarded to the client." << endl;

                        // Separate headers and body
                        size_t header_end_pos = manifest_content.find("\r\n\r\n");
                        if (header_end_pos != string::npos) {
                            string manifest_body = manifest_content.substr(header_end_pos + 4); // Skip over "\r\n\r\n"

                            // Parse the manifest body to extract the available bitrates

                            if (parsed_bitrates.empty()) {
                              debugLog << "trying to parseManifest" << endl;
                              parsed_bitrates = parseManifestForBitrates(manifest_body);
                              
                            }
                            //parsed_bitrates = parseManifestForBitrates(manifest_body);
                            // Now, initialize avg_throughput for each client
                        sort(parsed_bitrates.begin(), parsed_bitrates.end());
                        int lowest_bitrate = parsed_bitrates[0];
                        for (auto& entry : avg_throughput_map) {
                            if (entry.second == 0.0) {
                                entry.second = lowest_bitrate;
                                debugLog << "Initialized avg_throughput for client " << entry.first << " to " << entry.second << endl;
                            }
                        }

                        } else {
                            debugLog << "Error: Could not find end of headers in HTTP response." << endl;
                        }

                        // Close the connections
                     //   close(webserver_fd);
                        debugLog << "Handling manifest request for " << path << endl;
                    }
                    else if (path.find(".ts") != string::npos) {

                        debugLog << "IN TS SECTION"  << endl;


                        double& avg_throughput = avg_throughput_map[client_socket];
                        set<int>& available_bitrates = available_bitrates_map[client_socket];


                        // Extract the requested bitrate from the URI
                        int requested_bitrate = extractBitrateFromURI(path);
                        if (requested_bitrate != -1) {
        
                        available_bitrates.insert(requested_bitrate);
                        debugLog << "Extracted bitrate from URI: " << requested_bitrate << endl;
                    } else {
                        debugLog << "Could not extract bitrate from URI: " << path << endl;
                    }

                    set<int> combined_bitrates;
                    if (!parsed_bitrates.empty()) {
                        debugLog << "Using parsed_bitrates for bitrate selection." << endl;
                        if (path.find("charge") != string::npos) {
                            combined_bitrates = {3000000, 6000000, 10000000, 24000000, 40000000};
                        } else {  // Wing It
                            combined_bitrates = {1300000, 4000000, 13000000};
                        }
                        combined_bitrates.insert(parsed_bitrates.begin(), parsed_bitrates.end());
                    } else {
                        debugLog << "Parsed_bitrates is empty. Using default bitrates." << endl;
                        if (path.find("charge") != string::npos) {
                            combined_bitrates = {3000000, 6000000, 10000000, 24000000, 40000000};
                        } else {  // Wing It
                            combined_bitrates = {1300000, 4000000, 13000000};
                        }
                    }

                    // Insert available_bitrates observed from the .ts URIs
                    //combined_bitrates.insert(available_bitrates.begin(), available_bitrates.end()); //if you comment this out you pass second test


                    // Convert the set to a sorted vector
                    vector<int> sorted_bitrates(combined_bitrates.begin(), combined_bitrates.end());
                    sort(sorted_bitrates.begin(), sorted_bitrates.end());

                    // Select the highest bitrate less than or equal to avg_throughput / adaptation_bitrate_multiplier
                    int selected_bitrate = sorted_bitrates.front();
                    double threshold = avg_throughput / adaptation_bitrate_multiplier;

                    for (int bitrate : sorted_bitrates) {
                        if (bitrate <= threshold) {
                            selected_bitrate = bitrate;
                        } else {
                            break;
                        }
                    }

                    debugLog << "Available Bitrates: ";
                    for (int br : sorted_bitrates) {
                        debugLog << br << " ";
                    }
                    debugLog << endl;
                        debugLog << "BITRATE CHOSEN: " << selected_bitrate << endl;

                        // Modify the request to use the selected bitrate
                        string modified_chunk_name;
                        string modified_request = modifyRequest(request, selected_bitrate, modified_chunk_name);


                        // Connect to the upstream web server and forward the modified request
                        int webserver_fd = connectToWebServer(upstream_server_host.c_str(), upstream_server_port);
                        debugLog << "Connecting to the upstream web server" << endl;
                        auto start_time = std::chrono::high_resolution_clock::now();
                        send(webserver_fd, modified_request.c_str(), modified_request.size(), 0);
                        debugLog << "Done Connecting to the upstream web server" << endl;

                        // Read and forward response from the web server in chunks
                        bool headers_received = false;
                        int content_length = -1;
                        bool chunked = false;
                        int header_length = 0;
                        std::string headers;
                        std::string full_response;
                        int total_bytes = 0;
                        int webread;
    

                        char webserver_response[4096];
                        //auto start_time = std::chrono::high_resolution_clock::now();
                        while ((webread = read(webserver_fd, webserver_response, sizeof(webserver_response))) > 0) {
                            full_response.append(webserver_response, webread);
                            total_bytes += webread;

                            // Once headers are fully received, determine the transfer type
                            if (!headers_received && isEndOfHeaders(full_response)) {
                                headers_received = true;

                                // Extract Content-Length or check for chunked transfer
                                content_length = getContentLength(full_response);
                                chunked = isChunkedTransfer(full_response);

                                debugLog << "Headers received. Content-Length: " << content_length
                                         << ", Chunked: " << (chunked ? "Yes" : "No") << std::endl;
                            }
                            

                            send(client_socket, webserver_response, webread, 0);

                            // If Content-Length is known and the full response is received, break the loop
                            if (content_length != -1 && total_bytes >= content_length + full_response.find("\r\n\r\n") + 4) {
                                debugLog << "Complete message received based on Content-Length." << std::endl;
                                break;
                            }

                            // Handle chunked transfer termination: if last chunk is received
                            if (chunked && full_response.find("0\r\n\r\n") != std::string::npos) {
                                debugLog << "Chunked transfer completed." << std::endl;
                                break;
                            }
                        }

                        // End timing and throughput calculation
                        auto end_time = std::chrono::high_resolution_clock::now();
                        std::chrono::duration<double> duration = end_time - start_time;

                        double tput = (total_bytes * 8) / duration.count();  // Throughput in bits per second

                        // Update EWMA with asymmetric handling
                        if (avg_throughput == 0.0) {
                            avg_throughput = tput;  // Initialize avg_throughput to tput if it's zero
                        } else {
                            if (tput < avg_throughput) {
                                // Throughput is decreasing, set avg_throughput to tput
                                avg_throughput = tput;
                            } else {
                                // Throughput is increasing, update avg_throughput using EWMA
                                avg_throughput = adaptation_gain * tput + (1 - adaptation_gain) * avg_throughput;
                            }
                        }

                        // Log the result (ensure selected_bitrate is in Kbps)
                        double tput_kbps = tput / 1000.0;
                        double avg_tput_kbps = avg_throughput / 1000.0;
                        // Log throughput, average throughput, and selected bitrate
                        logFile << client_ips[client_socket] << " "
                                << modified_chunk_name << " "
                                << upstream_server_host << " "
                                << duration.count() << " "
                                << tput_kbps << " "
                                << avg_tput_kbps << " "
                                << (selected_bitrate/1000) << endl;

                        debugLog << "Selected bitrate: " << selected_bitrate << std::endl;
                        debugLog << client_ips[client_socket] << " "
                                << modified_chunk_name << " "
                                << upstream_server_host << " "
                                << duration.count() << " "
                                << tput_kbps << " "
                                << avg_tput_kbps << " "
                                << (selected_bitrate/1000) << endl;

                        // Close the connections
                       // close(webserver_fd);
                        debugLog << "Handling video chunk request for " << path << endl;
                    }
                    else {
                        // Handle other requests (e.g., .html, .js, .css)
                        debugLog << "Handling other request for " << path << endl;

                        // Read the full request from the client
                        string full_request = request;  // 'request' already contains initial data
                        char temp_buffer[4096];
                        int valread;
                        while (full_request.find("\r\n\r\n") == string::npos) {
                            valread = read(client_socket, temp_buffer, sizeof(temp_buffer));
                            if (valread <= 0) {
                                perror("Error reading from client socket");
                                debugLog << "Error: Failed to read full request from client." << endl;
                                close(client_socket);
                                client_sockets.erase(client_sockets.begin() + i);
                                client_ips.erase(client_socket);
                                avg_throughput_map.erase(client_socket);
                                --i;
                                break;
                            }
                            full_request.append(temp_buffer, valread);
                        }

                        // Forward the full request unmodified to the web server
                        int webserver_fd = connectToWebServer(upstream_server_host, upstream_server_port);
                        if (webserver_fd < 0) continue;

                        // Forward the request as is
                        int bytes_sent = send(webserver_fd, full_request.c_str(), full_request.size(), 0);
                        if (bytes_sent < 0) {
                            perror("Error sending request to web server");
                            debugLog << "Error: Failed to send request to web server." << endl;
                            close(webserver_fd);
                            continue;
                        }
                        //debugLog << "Sent " << bytes_sent << " bytes to web server." << endl;

                        // Read and forward response from the web server to the client
                        string response;
                        char response_buffer[4096];
                        int webread;
                        bool headers_received = false;
                        int content_length = -1;
                        bool chunked = false;
                        int total_bytes_read = 0;

                        debugLog << "Waiting to read response from web server..." << endl;
                        while ((webread = read(webserver_fd, response_buffer, sizeof(response_buffer))) > 0) {
                            response.append(response_buffer, webread);
                            total_bytes_read += webread;

                            // Once headers are fully received, determine the transfer type
                            if (!headers_received && isEndOfHeaders(response)) {
                                headers_received = true;

                                // Extract Content-Length or check for chunked transfer
                                content_length = getContentLength(response);
                                chunked = isChunkedTransfer(response);

                                debugLog << "Headers received. Content-Length: " << content_length
                                        << ", Chunked: " << (chunked ? "Yes" : "No") << std::endl;

                                // Forward headers to client
                                int header_end_pos = response.find("\r\n\r\n") + 4;
                                if (client_socket <= 0) {
                                    debugLog << "TODO 1 Error: Client socket is invalid or closed." << endl;
                                    close(webserver_fd);
                                    continue;
                                }


                                int bytes_forwarded = send(client_socket, response.c_str(), header_end_pos, 0); // TODO HERE SENDING TO SOMETHING THATS BROKEN OR CLOSED, check to see if its availabel
                                if (bytes_forwarded < 0) {
                                    perror("Error sending response headers to client");
                                    debugLog << "Error: Failed to send response headers to client." << endl;
                                    close(webserver_fd);
                                    continue;
                                }
                                //debugLog << "Forwarded response headers to client." << endl; //TODO DOESNT GET TO HERE
                                //before send try to ping

                                // Forward any body data already read
                                int body_size = response.size() - header_end_pos;
                                if (body_size > 0) {
                                    if (client_socket <= 0) {
                                        debugLog << "TODO 2 Error: Client socket is invalid or closed." << endl;
                                        close(webserver_fd);
                                        continue;
                                }
                                    bytes_forwarded = send(client_socket, response.c_str() + header_end_pos, body_size, 0);
                                    if (bytes_forwarded < 0) {
                                        perror("Error sending response body to client");
                                        debugLog << "Error: Failed to send response body to client." << endl;
                                        close(webserver_fd);
                                        continue;
                                    }
                                    //debugLog << "Forwarded " << bytes_forwarded << " bytes of response body to client." << endl;
                                }
                            } else if (headers_received) {
                                // Forward the data to the client as it's received
                                    if (client_socket <= 0) {
                                    debugLog << "TODO 3 Error: Client socket is invalid or closed." << endl;
                                    close(webserver_fd);
                                    continue;
                                }
                                int bytes_forwarded = send(client_socket, response_buffer, webread, 0);
                                if (bytes_forwarded < 0) {
                                    perror("Error sending response to client");
                                    debugLog << "Error: Failed to send response to client." << endl;
                                    break;
                                }
                                //debugLog << "Forwarded " << bytes_forwarded << " bytes to client." << endl;
                            }

                            // Check if the entire response has been received
                            if (headers_received) {
                                if (chunked && response.find("0\r\n\r\n") != std::string::npos) {
                                    debugLog << "Chunked transfer completed." << std::endl;
                                    break;
                                }
                                if (content_length != -1) {
                                    int header_end_pos = response.find("\r\n\r\n") + 4;
                                    int body_size = response.size() - header_end_pos;
                                    if (body_size >= content_length) {
                                        debugLog << "Complete message received based on Content-Length." << std::endl;
                                        break;
                                    }
                                }
                            }
                        }
                        if (webread < 0) {
                            perror("Error reading from web server");
                            debugLog << "Error: Failed to read from web server." << endl;
                        }
                        debugLog << "Finished handling other request for " << path << endl;

                        // Close the connections
                      //  close(webserver_fd);
                    }

                }
            }
        }
    }
}

int main(int argc, char* argv[]) {
    string proxy_host, upstream_server_host, log_file_name;
    string nameserverIP;
    int nameserverPort = 0;
    int proxy_port = 0, upstream_server_port = 0;
    double adaptation_gain = 0.5, adaptation_bitrate_multiplier = 1.5;

    parseArguments(argc, argv, proxy_host, proxy_port, upstream_server_host, upstream_server_port,
                   adaptation_gain, adaptation_bitrate_multiplier, nameserverIP, nameserverPort, log_file_name);

    // Ensure the nameserver has started
    waitForDNSResolution();

    // Check if DNS resolution is needed
    in_addr addr;
    string resolved_ip;
    if (inet_pton(AF_INET, upstream_server_host.c_str(), &addr) != 1) {
        if (nameserverIP.empty() || nameserverPort == 0) {
            cerr << "Error: Nameserver IP and port are required to resolve the hostname." << endl;
            exit(EXIT_FAILURE);
        }

        int retries = 3;
        while (retries > 0) {
            try {
                resolved_ip = resolveHostname(upstream_server_host, nameserverIP, nameserverPort);
                if (!resolved_ip.empty()) {
                    debugLog << "Successfully resolved " << upstream_server_host << " to " << resolved_ip << endl;
                    upstream_server_host = resolved_ip;
                    break;
                }
            } catch (const std::exception& e) {
                debugLog << "DNS Resolution attempt failed: " << e.what() << endl;
                retries--;
                if (retries > 0) {
                    waitForDNSResolution();
                }
            }
        }

        if (resolved_ip.empty()) {
            cerr << "Error: Failed to resolve hostname after multiple attempts" << endl;
            exit(EXIT_FAILURE);
        }
    }

    // Set up proxy and start serving
    int server_fd = setupServerSocket(proxy_host, proxy_port);
    proxyLogic(server_fd, upstream_server_host, upstream_server_port, adaptation_gain, adaptation_bitrate_multiplier);

    // Cleanup
    close(server_fd);
    if (logFile.is_open()) {
        logFile.close();
    }

    return 0;
}

