#include <iostream>
#include <pcap.h>
#include <string>
#include <thread>
#include <windows.h>

// Function to start promiscuous mode on the interface
void startPromiscuousMode(const std::string& interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open the device for packet capture in promiscuous mode
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << interface << ": " << errbuf << std::endl;
        return;
    }

    // Set the interface into promiscuous mode
    if (pcap_set_rfmon(handle, 1) != 0) {
        std::cerr << "Failed to set promiscuous mode." << std::endl;
        pcap_close(handle);
        return;
    }

    std::cout << "Promiscuous mode enabled on " << interface << std::endl;
    pcap_close(handle);
}

// Function to stop promiscuous mode on the interface
void stopPromiscuousMode(const std::string& interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open the device for packet capture
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << interface << ": " << errbuf << std::endl;
        return;
    }

    // Set the interface into normal mode (disable promiscuous mode)
    if (pcap_set_rfmon(handle, 0) != 0) {
        std::cerr << "Failed to disable promiscuous mode." << std::endl;
        pcap_close(handle);
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
