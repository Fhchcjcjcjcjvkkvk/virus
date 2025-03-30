#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <pcap.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <zlib.h>
#include <getopt.h>
#include <cstring>
#include <iomanip>
#include <map>

// Function prototypes
void print_usage();
void analyze_handshake(const std::string &filename);
void crack_password(const std::string &handshake_file, const std::vector<std::string> &password_list);
std::vector<std::string> read_wordlist(const std::string &filename);
void handle_packet(const u_char *packet, struct pcap_pkthdr packet_header);
void derive_keys(const std::string &password, const std::string &ssid, u_char *pmk, u_char *ptk, const u_char *eapol_frame, size_t eapol_frame_len, u_char *mic);

// Global variables
std::vector<std::vector<u_char>> eapol_packets;
size_t total_packets = 0;
std::string ssid;
u_char ap_mac[6], client_mac[6];

int main(int argc, char *argv[]) {
    if (argc < 4) {
        print_usage();
        return 1;
    }

    int opt;
    std::string password_list_file;
    std::string handshake_file;

    while ((opt = getopt(argc, argv, "P:")) != -1) {
        switch (opt) {
            case 'P':
                password_list_file = optarg;
                break;
            default:
                print_usage();
                return 1;
        }
    }

    if (optind < argc) {
        handshake_file = argv[optind];
    } else {
        print_usage();
        return 1;
    }

    std::cout << "Opening " << handshake_file << "..." << std::endl;
    analyze_handshake(handshake_file);

    if (eapol_packets.empty()) {
        std::cout << "No EAPOL found :(" << std::endl;
        return 1;
    }

    std::vector<std::string> password_list = read_wordlist(password_list_file);
    crack_password(handshake_file, password_list);

    return 0;
}

void print_usage() {
    std::cerr << "Usage: amx.exe -P <passwordlist> <handshake.cap>" << std::endl;
}

void analyze_handshake(const std::string &filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename.c_str(), errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening file: " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    struct pcap_pkthdr header;
    const u_char *packet;
    while ((packet = pcap_next(handle, &header)) != nullptr) {
        handle_packet(packet, header);
        total_packets++;
    }

    pcap_close(handle);
    std::cout << "Analyzing " << total_packets << " packet(s)..." << std::endl;
}

void handle_packet(const u_char *packet, struct pcap_pkthdr packet_header) {
    const u_char *ptr = packet + 24; // Adjust the offset based on the actual radiotap header length
    if (packet[0] == 0x88 && packet[1] == 0x8e) { // EAPOL packet
        std::vector<u_char> eapol_frame(ptr, ptr + packet_header.len - 24);
        eapol_packets.push_back(eapol_frame);
        // Extract MAC addresses
        memcpy(ap_mac, packet + 10, 6);
        memcpy(client_mac, packet + 4, 6);
    }
}

std::vector<std::string> read_wordlist(const std::string &filename) {
    std::vector<std::string> wordlist;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error opening wordlist file: " << filename << std::endl;
        exit(EXIT_FAILURE);
    }

    std::string line;
    while (std::getline(file, line)) {
        wordlist.push_back(line);
    }

    file.close();
    return wordlist;
}

void derive_keys(const std::string &password, const std::string &ssid, u_char *pmk, u_char *ptk, const u_char *eapol_frame, size_t eapol_frame_len, u_char *mic) {
    // Derive the Pairwise Master Key (PMK)
    PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(), (const unsigned char*)ssid.c_str(), ssid.length(), 4096, 32, pmk);

    // Derive the Pairwise Transient Key (PTK)
    u_char pke[100];
    memcpy(pke, "Pairwise key expansion", 23);
    if (memcmp(ap_mac, client_mac, 6) < 0) {
        memcpy(pke + 23, ap_mac, 6);
        memcpy(pke + 29, client_mac, 6);
    } else {
        memcpy(pke + 23, client_mac, 6);
        memcpy(pke + 29, ap_mac, 6);
    }
    if (memcmp(eapol_frame + 19, eapol_frame + 13, 32) < 0) {
        memcpy(pke + 35, eapol_frame + 19, 32);
        memcpy(pke + 67, eapol_frame + 13, 32);
    } else {
        memcpy(pke + 35, eapol_frame + 13, 32);
        memcpy(pke + 67, eapol_frame + 19, 32);
    }
    HMAC(EVP_sha1(), pmk, 32, pke, 99, ptk, nullptr);

    // Calculate the MIC
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(hmac);
    char *digest_name = (char *)"SHA1";
    OSSL_PARAM params[2] = { OSSL_PARAM_construct_utf8_string("digest", digest_name, 0), OSSL_PARAM_construct_end() };
    EVP_MAC_init(ctx, ptk, 16, params);
    EVP_MAC_update(ctx, eapol_frame, eapol_frame_len);
    size_t mic_len;
    EVP_MAC_final(ctx, mic, &mic_len, 16);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(hmac);
}

void crack_password(const std::string &handshake_file, const std::vector<std::string> &password_list) {
    for (const auto &password : password_list) {
        std::cout << "Comparing: " << password << std::endl;

        u_char pmk[32], ptk[48], mic[16];
        for (const auto &eapol_frame : eapol_packets) {
            derive_keys(password, ssid, pmk, ptk, eapol_frame.data(), eapol_frame.size(), mic);

            // Compare derived MIC with the captured MIC
            if (memcmp(mic, eapol_frame.data() + eapol_frame.size() - 16, 16) == 0) {
                std::cout << "KEY FOUND! [" << password << "]" << std::endl;
                std::cout << "Master Key      : " << std::hex << std::setw(32) << std::setfill('0') << pmk << std::endl;
                std::cout << "Transient Key   : " << std::hex << std::setw(48) << std::setfill('0') << ptk << std::endl;
                std::cout << "EAPOL HMAC      : " << std::hex << std::setw(16) << std::setfill('0') << mic << std::endl;
                std::cout << "Tryied          : " << password_list.size() << std::endl;
                return;
            }
        }
    }

    std::cout << "Key Not Found" << std::endl;
}
