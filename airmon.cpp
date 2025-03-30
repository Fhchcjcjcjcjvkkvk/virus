#include <iostream>
#include <pcap.h>
#include <string>
#include <vector>

void listInterfaces() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Get the list of all network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return;
    }

    std::cout << "Available interfaces:" << std::endl;
    int i = 1;
    for (d = alldevs; d != NULL; d = d->next) {
        std::cout << i++ << ". " << d->name << std::endl;
    }

    // Free the device list
    pcap_freealldevs(alldevs);
}

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

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Get the list of all network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    // List available interfaces
    listInterfaces();

    // Prompt the user to select an interface
    int choice;
    std::cout << "Enter the number of the interface you want to use: ";
    std::cin >> choice;

    pcap_if_t *selectedDev = alldevs;
    int i = 1;
    while (selectedDev != NULL && i < choice) {
        selectedDev = selectedDev->next;
        i++;
    }

    if (selectedDev == NULL) {
        std::cerr << "Invalid choice, exiting." << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    std::string interfaceName = selectedDev->name;
    pcap_freealldevs(alldevs);

    // Ask the user if they want to start or stop promiscuous mode
    std::string action;
    std::cout << "Do you want to enable or disable promiscuous mode on " << interfaceName << "? (start/stop): ";
    std::cin >> action;

    if (action == "start") {
        startPromiscuousMode(interfaceName);
    } else if (action == "stop") {
        stopPromiscuousMode(interfaceName);
    } else {
        std::cerr << "Invalid command. Use 'start' or 'stop'." << std::endl;
        return 1;
    }

    return 0;
}
