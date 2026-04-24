#include <iostream>
#include <string>
#include <vector>
#include <zmq.hpp>
#include <curl/curl.h>
#include <ndpi/ndpi_main.h>
#include <ndpi/ndpi_typedefs.h>
#include <ndpi/ndpi_api.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <openssl/md5.h>
#include <signal.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <ctime>

// --- Configuration Constants ---
constexpr u_int32_t SNAPLEN = 1600;
constexpr u_int32_t PCAP_GLOBAL_HEADER_LEN = 24;
constexpr u_int32_t PCAP_PACKET_HEADER_LEN = 16;
constexpr u_int32_t IPV4_SCAN_DEPTH = 32;
constexpr u_int32_t MIN_IPV4_HLEN = 20;
constexpr u_int32_t HEARTBEAT_INTERVAL_SEC = 5; // Time-based interval in seconds
constexpr u_int32_t DEBUG_INTERVAL = 1000;
constexpr int CURL_TIMEOUT_SEC = 5;
constexpr const char* ZMQ_TOPIC = "flow";

/**
 * Structure: zmq_msg_hdr_v4
 * Purpose: Binary header structure required by ntopng for ZMQ messages.
 * This layout ensures compatibility with ntopng's ZMQ collector.
 */
struct zmq_msg_hdr_v4 {
    char topic[16];
    u_int8_t version;
    u_int8_t msg_type;
    u_int16_t source_id;
    u_int32_t msg_id;
    u_int32_t uncompressed_len;
    u_int32_t compressed_len;
    u_int32_t probe_id;
} __attribute__((packed));

/**
 * Structure: pcap_pkthdr_std
 * Purpose: Standard PCAP packet header format as provided by the Fritz!Box stream.
 */
struct pcap_pkthdr_std {
    u_int32_t ts_sec;
    u_int32_t ts_usec;
    u_int32_t incl_len;
    u_int32_t orig_len;
};

// Global pointers and state variables
zmq::socket_t* global_socket = nullptr;
ndpi_serializer* global_serializer = nullptr;
u_int32_t global_msg_id = 1;
u_int64_t total_flows_sent = 0;
time_t last_heartbeat_time = 0;
volatile sig_atomic_t is_running = 1;
bool debug_enabled = false;

/**
 * Function: get_env
 * Purpose: Safely retrieve an environment variable with a fallback default.
 */
std::string get_env(const std::string& key, const std::string& def) {
    char* val = getenv(key.c_str());
    return val ? std::string(val) : def;
}

/**
 * Function: md5_hex
 * Purpose: Calculate MD5 hash and return as hexadecimal string.
 */
std::string md5_hex(const std::string& input) {
    unsigned char digest[MD5_DIGEST_LENGTH];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    MD5((unsigned char*)input.c_str(), input.length(), digest);
#pragma GCC diagnostic pop
    char buf[33];
    for(int i = 0; i < 16; i++) sprintf(&buf[i*2], "%02x", digest[i]);
    return std::string(buf);
}

/**
 * Function: stop_fb_capture
 * Purpose: Notify the Fritz!Box to explicitly terminate the packet capture stream.
 */
void stop_fb_capture(const std::string& sid, const std::string& ip, const std::string& iface) {
    if (sid == "0000000000000000") return;

    CURL *curl = curl_easy_init();
    if (curl) {
        std::string stop_url = "http://" + ip + "/cgi-bin/capture_notimeout?sid=" + sid +
                               "&capture=Stop&ifaceorminor=" + iface;

        std::cout << "[INFO] Sending stop command to Fritz!Box..." << std::endl;
        curl_easy_setopt(curl, CURLOPT_URL, stop_url.c_str());
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)CURL_TIMEOUT_SEC);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        std::cout << "[INFO] Stop command sequence finished." << std::endl;
    }
}

/**
 * Function: get_fb_sid
 * Purpose: Perform the Fritz!Box login handshake to obtain a valid Session ID (SID).
 */
std::string get_fb_sid() {
    CURL *curl = curl_easy_init();
    std::string res_str;
    if(!curl) return "0000000000000000";

    std::string ip = get_env("FRITZBOX_IP", "192.168.178.1");
    std::string base_url = "http://" + ip + "/login_sid.lua";

    curl_easy_setopt(curl, CURLOPT_URL, base_url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](void* ptr, size_t size, size_t nmemb, std::string* s) {
        s->append((char*)ptr, size * nmemb); return size * nmemb;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res_str);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)CURL_TIMEOUT_SEC);
    curl_easy_perform(curl);

    size_t start = res_str.find("<Challenge>") + 11;
    size_t end = res_str.find("</Challenge>");
    if(start == std::string::npos || end == std::string::npos) return "0000000000000000";

    std::string challenge = res_str.substr(start, end - start);
    std::string utf16_input;
    std::string pass = get_env("FRITZBOX_PASSWORD", "");

    for(char c : challenge + "-" + pass) { utf16_input += c; utf16_input += '\0'; }
    std::string response = challenge + "-" + md5_hex(utf16_input);

    res_str.clear();
    std::string user = get_env("FRITZBOX_USERNAME", "admin");
    std::string login_url = base_url + "?username=" + user + "&response=" + response;
    curl_easy_setopt(curl, CURLOPT_URL, login_url.c_str());
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    start = res_str.find("<SID>") + 5;
    end = res_str.find("</SID>");
    return (start != std::string::npos) ? res_str.substr(start, end - start) : "0000000000000000";
}

/**
 * Function: curl_write_cb
 * Purpose: Libcurl callback processing the raw binary PCAP stream.
 * It identifies IPv4 packets and serializes them into nDPI TLV format for ZMQ transmission.
 */
size_t curl_write_cb(void* ptr, size_t size, size_t nmemb, void* userdata) {
    static std::vector<uint8_t> buffer;
    size_t total_size = size * nmemb;
    buffer.insert(buffer.end(), (uint8_t*)ptr, (uint8_t*)ptr + total_size);

    static bool global_hdr_skipped = false;
    size_t offset = 0;

    if(!global_hdr_skipped && buffer.size() >= PCAP_GLOBAL_HEADER_LEN) {
        offset = PCAP_GLOBAL_HEADER_LEN;
        global_hdr_skipped = true;
    }

    while(buffer.size() - offset >= PCAP_PACKET_HEADER_LEN) {
        pcap_pkthdr_std* h = reinterpret_cast<pcap_pkthdr_std*>(&buffer[offset]);

        if(h->incl_len > SNAPLEN || h->incl_len == 0) {
            offset++;
            continue;
        }

        if(buffer.size() - offset < PCAP_PACKET_HEADER_LEN + h->incl_len) break;

        uint8_t* packet = &buffer[offset + PCAP_PACKET_HEADER_LEN];
        struct iphdr* iph = nullptr;

        if (h->incl_len >= MIN_IPV4_HLEN) {
            u_int32_t scan_limit = std::min(IPV4_SCAN_DEPTH, h->incl_len - MIN_IPV4_HLEN);
            for(u_int32_t i=0; i <= scan_limit; ++i) {
                if((packet[i] == 0x45) && (packet[i+9] == 6 || packet[i+9] == 17 || packet[i+9] == 1)) {
                    iph = reinterpret_cast<struct iphdr*>(&packet[i]);
                    break;
                }
            }
        }

        if(iph && global_serializer && global_socket) {
            ndpi_reset_serializer(global_serializer);

            ndpi_serialize_uint32_uint32(global_serializer, 8, ntohl(iph->saddr));
            ndpi_serialize_uint32_uint32(global_serializer, 12, ntohl(iph->daddr));
            ndpi_serialize_uint32_uint32(global_serializer, 4, static_cast<u_int32_t>(iph->protocol));
            ndpi_serialize_uint32_uint32(global_serializer, 1, static_cast<u_int32_t>(h->incl_len));
            ndpi_serialize_uint32_uint32(global_serializer, 2, 1);

            uint16_t sport = 0, dport = 0;
            if(iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
                u_int16_t* ports = reinterpret_cast<u_int16_t*>(reinterpret_cast<uint8_t*>(iph) + (iph->ihl * 4));
                sport = ntohs(ports[0]);
                dport = ntohs(ports[1]);
                ndpi_serialize_uint32_uint32(global_serializer, 7, sport);
                ndpi_serialize_uint32_uint32(global_serializer, 11, dport);
            }

            u_int32_t tlv_len;
            char* tlv_buf = ndpi_serializer_get_buffer(global_serializer, &tlv_len);

            if(tlv_buf && tlv_len > 0) {
                zmq_msg_hdr_v4 z_hdr = {};
                memset(z_hdr.topic, 0, 16);
                memcpy(z_hdr.topic, ZMQ_TOPIC, strlen(ZMQ_TOPIC));

                z_hdr.version = 4;
                z_hdr.msg_type = 2;
                z_hdr.source_id = htons(0);
                z_hdr.msg_id = htonl(global_msg_id++);
                z_hdr.uncompressed_len = htonl(tlv_len);
                z_hdr.compressed_len = htonl(tlv_len);
                z_hdr.probe_id = htonl(0);

                zmq::message_t m_hdr(&z_hdr, sizeof(z_hdr));
                zmq::message_t m_body(tlv_buf, tlv_len);
                global_socket->send(m_hdr, zmq::send_flags::sndmore);
                global_socket->send(m_body, zmq::send_flags::none);

                total_flows_sent++;

                // Logging for verification (triggered by environment variable)
                if(debug_enabled && (total_flows_sent % DEBUG_INTERVAL == 0)) {
                    struct in_addr sa, da;
                    sa.s_addr = iph->saddr; da.s_addr = iph->daddr;
                    std::cout << "[DEBUG] " << inet_ntoa(sa) << ":" << sport
                              << " -> " << inet_ntoa(da) << ":" << dport
                              << " (Proto: " << (int)iph->protocol << ")" << std::endl;
                }

                // Time-based heartbeat
                time_t now = time(NULL);
                if (now - last_heartbeat_time >= HEARTBEAT_INTERVAL_SEC) {
                    std::cout << "[HEARTBEAT] " << total_flows_sent << " flows sent to ntopng." << std::endl;
                    last_heartbeat_time = now;
                }
            }
        }
        offset += PCAP_PACKET_HEADER_LEN + h->incl_len;
    }

    if (offset > 0) {
        buffer.erase(buffer.begin(), buffer.begin() + offset);
    }

    return total_size;
}

/**
 * Function: curl_progress_cb
 * Purpose: Signal-safe abortion of the HTTP stream when termination is requested.
 */
int curl_progress_cb(void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
    return is_running ? 0 : 1;
}

/**
 * Function: main
 * Purpose: Main entry point for the capture tool.
 */
int main() {
    setvbuf(stdout, NULL, _IOLBF, 0);
    std::cout << "Fritz!Box ZMQ Capture Tool v1.0.2" << std::endl;

    if(get_env("DEBUG_FLOWS", "false") == "true") {
        debug_enabled = true;
        std::cout << "[CONFIG] Debugging mode enabled." << std::endl;
    }

    auto sig_handler = [](int s) { is_running = 0; };
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    zmq::context_t z_ctx(1);
    zmq::socket_t z_sock(z_ctx, ZMQ_PUB);
    try {
        z_sock.bind("tcp://0.0.0.0:5556");
    } catch (std::exception &e) {
        std::cerr << "[ERROR] ZMQ bind failed: " << e.what() << std::endl;
        return 1;
    }
    global_socket = &z_sock;

    ndpi_serializer ser;
    if (ndpi_init_serializer(&ser, ndpi_serialization_format_tlv) != 0) {
        std::cerr << "[ERROR] nDPI initialization failed." << std::endl;
        return 1;
    }
    global_serializer = &ser;

    std::string ip = get_env("FRITZBOX_IP", "192.168.178.1");
    std::string iface = get_env("FRITZBOX_INTERFACE", "3-0");
    std::string sid = get_fb_sid();

    if(sid == "0000000000000000") {
        std::cerr << "[ERROR] SID login failed. Check credentials and IP." << std::endl;
        return 1;
    }

    // Initialize timer
    last_heartbeat_time = time(NULL);

    stop_fb_capture(sid, ip, iface);
    sleep(2);

    CURL *curl = curl_easy_init();
    if (curl) {
        std::string url = "http://" + ip + "/cgi-bin/capture_notimeout?sid=" + sid +
                          "&capture=Start&snaplen=" + std::to_string(SNAPLEN) + "&ifaceorminor=" + iface;

        std::cout << "[INFO] Opening capture stream on interface " << iface << "..." << std::endl;

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, curl_progress_cb);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK && is_running) {
            std::cerr << "[ERROR] Network stream error: " << curl_easy_strerror(res) << std::endl;
        }
        curl_easy_cleanup(curl);
    }

    std::cout << "[STOP] Terminating and notifying Fritz!Box..." << std::endl;
    stop_fb_capture(sid, ip, iface);
    ndpi_term_serializer(&ser);

    return 0;
}
