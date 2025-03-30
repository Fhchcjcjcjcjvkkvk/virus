#include <iostream>
#include <pcap.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <iomanip>
#include <map>
#include <mutex>

// Define structures for network and station information
struct Network {
    std::string bssid;
    int pwr;
    int beacons;
    int packetsPerSecond;
    int channel;
    std::string encryption;
    std::string auth;
    std::string essid;
};

struct Station {
    std::string mac;
    int pwr;
    std::string notes;
    std::string probes;
};

// Vectors to store network and station information
std::vector<Network> networks;
std::vector<Station> stations;
std::map<std::string, int> packetCount;

// Mutex to protect shared resources
std::mutex networkMutex;
std::mutex stationMutex;

// Function to check if promiscuous mode is active
bool isPromiscuousModeActive(pcap_t* handle) {
    pcap_stat stats;
    if (pcap_stats(handle, &stats) == 0) {
        return true;
    }
    return false;
}

// Function to identify WPA, WPA2, WEP, or Open encryption/authentication
void identifyEncryption(const u_char* packet, std::string& encryption, std::string& auth) {
    // Check for WPA2 or WPA (RSN or WPA info)
    if (packet[37] == 0x30) {
        encryption = "WPA2";
        auth = "PSK";
    }
    else if (packet[37] == 0x00) {
        encryption = "WPA";
        auth = "PSK";
    }
    // Check for WEP encryption
    else if (packet[22] & 0x40) {
        encryption = "WEP";
        auth = "Shared Key";
    }
    // Otherwise, it's an open network
    else {
        encryption = "OPN";
        auth = "None";
    }
}

// Function to capture network information
void captureNetworks(pcap_t* handle) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue; // Timeout elapsed

        // Check if it's a beacon frame or data frame
        if (packet[0] == 0x80 || packet[0] == 0x40) {
            // Extract BSSID
            char bssid[18];
            sprintf(bssid, "%02x:%02x:%02x:%02x:%02x:%02x", packet[10], packet[11], packet[12], packet[13], packet[14], packet[15]);

            // Extract ESSID length and ESSID
            int essid_len = packet[37];
            std::string essid(reinterpret_cast<const char*>(packet + 38), essid_len);

            // Extract other details
            int pwr = (int8_t)packet[22];
            int channel = packet[64];

            // Identify encryption and authentication
            std::string encryption;
            std::string auth;
            identifyEncryption(packet, encryption, auth);

            // Lock the network data for thread-safe access
            std::lock_guard<std::mutex> guard(networkMutex);
            bool found = false;
            for (auto& network : networks) {
                if (network.bssid == bssid) {
                    network.pwr = pwr;
                    network.beacons++;
                    network.channel = channel;
                    network.encryption = encryption;
                    network.auth = auth;
                    network.essid = essid;
                    packetCount[bssid]++;
                    network.packetsPerSecond = packetCount[bssid] / 10; // Average over 10 seconds
                    found = true;
                    break;
                }
            }

            if (!found) {
                Network newNetwork = {bssid, pwr, 1, 0, channel, encryption, auth, essid};
                networks.push_back(newNetwork);
                packetCount[bssid] = 1;
            }
        }
    }
}

// Function to display network information
void displayNetworks() {
    system("CLS"); // Clear the console on Windows
    std::cout << "BSSID              PWR   Beacons    #/s  CH ENC  AUTH ESSID" << std::endl;

    // Lock the network data for thread-safe access
    std::lock_guard<std::mutex> guard(networkMutex);
    for (const auto& network : networks) {
        std::cout << std::setw(17) << network.bssid
                  << std::setw(6) << network.pwr
                  << std::setw(10) << network.beacons
                  << std::setw(6) << network.packetsPerSecond
                  << std::setw(4) << network.channel
                  << std::setw(5) << network.encryption
                  << std::setw(5) << network.auth
                  << " " << network.essid << std::endl;
    }

    std::cout << std::endl;
    std::cout << "STATION            PWR   Notes  Probes" << std::endl;

    // Lock the station data for thread-safe access
    std::lock_guard<std::mutex> stationGuard(stationMutex);
    for (const auto& station : stations) {
        std::cout << std::setw(17) << station.mac
                  << std::setw(6) << station.pwr
                  << std::setw(6) << station.notes
                  << " " << station.probes << std::endl;
    }
}

// Function to start capturing network information
void startCapture(const std::string& interface, const std::string& outputFile) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << interface << ": " << errbuf << std::endl;
        return;
    }

    if (!isPromiscuousModeActive(handle)) {
        std::cerr << "Promiscuous Mode is not activated." << std::endl;
        pcap_close(handle);
        return;
    }

    std::thread captureThread(captureNetworks, handle);

    while (true) {
        displayNetworks();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    captureThread.join();
    pcap_close(handle);
}

// Main function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface> [-o <output_file>]" << std::endl;
        return 1;
    }

    std::string interface = argv[1];
    std::string outputFile;

    if (argc == 4 && std::string(argv[2]) == "-o") {
        outputFile = argv[3];
    }

    startCapture(interface, outputFile);

    return 0;
}
