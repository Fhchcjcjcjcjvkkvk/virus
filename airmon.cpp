#include <iostream>
#include <pcap.h>
#include <string>
#include <cstdlib>

void startPromiscuousMode(const std::string &interfaceName) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the network interface for live capture
    handle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return;
    }

    // Set promiscuous mode
    if (pcap_set_promisc(handle, 1) != 0) {
        std::cerr << "Error enabling promiscuous mode on " << interfaceName << std::endl;
        pcap_close(handle);
        return;
    }

    std::cout << "Promiscuous mode enabled on " << interfaceName << std::endl;
    pcap_close(handle);
}

void stopPromiscuousMode(const std::string &interfaceName) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the network interface for live capture
    handle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return;
    }

    // Set promiscuous mode off
    if (pcap_set_promisc(handle, 0) != 0) {
        std::cerr << "Error disabling promiscuous mode on " << interfaceName << std::endl;
        pcap_close(handle);
        return;
    }

    std::cout << "Promiscuous mode disabled on " << interfaceName << std::endl;
    pcap_close(handle);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <start|off>" << std::endl;
        return 1;
    }

    std::string interfaceName = argv[1];
    std::string command = argv[2];

    if (command == "start") {
        startPromiscuousMode(interfaceName);
    } else if (command == "off") {
        stopPromiscuousMode(interfaceName);
    } else {
        std::cerr << "Invalid command. Use 'start' or 'off'." << std::endl;
        return 1;
    }

    return 0;
}
