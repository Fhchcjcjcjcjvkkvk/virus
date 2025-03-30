#include <pcap.h>       // Include pcap.h first
#include <iostream>
#include <string>        // Include string for std::string
#include <windows.h>     // Include windows.h after C++ headers

#define NOMINMAX         // Avoid min/max macro conflicts

// Function to start promiscuous mode on the interface
void startPromiscuousMode(const std::string& interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open the device for packet capture in promiscuous mode
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << interface << ": " << errbuf << std::endl;
        return;
    }

    std::cout << "Promiscuous mode enabled on " << interface << std::endl;
    pcap_close(handle);
}

// Function to stop promiscuous mode on the interface
void stopPromiscuousMode(const std::string& interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open the device for packet capture in non-promiscuous mode
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 0, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << interface << ": " << errbuf << std::endl;
        return;
    }

    std::cout << "Promiscuous mode disabled on " << interface << std::endl;
    pcap_close(handle);
}

// Main function to process commands
int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: airmon.exe <interface> start|off" << std::endl;
        return 1;
    }

    std::string interface = argv[1];
    std::string command = argv[2];

    if (command == "start") {
        startPromiscuousMode(interface);
    }
    else if (command == "off") {
        stopPromiscuousMode(interface);
    }
    else {
        std::cerr << "Invalid command. Use 'start' or 'off'." << std::endl;
        return 1;
    }

    return 0;
}
