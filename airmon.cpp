#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <Windows.h>
#include <Urlmon.h>

#pragma comment(lib, "urlmon.lib")

// Function to check if monitor mode is supported on any adapters
std::vector<std::string> checkMonitorModeSupport() {
    std::vector<std::string> adapters;
    std::string line;
    std::ifstream driverOutput("drivers.txt");

    if (driverOutput.is_open()) {
        while (getline(driverOutput, line)) {
            if (line.find("Name") != std::string::npos) {
                adapters.push_back(line.substr(line.find(":") + 1));
            }
        }
        driverOutput.close();
    }

    return adapters;
}

// Function to download and install Npcap
void downloadNpcap() {
    const std::string url = "https://nmap.org/npcap/dist/npcap-1.79.exe";
    const std::string filename = "npcap.exe";

    std::cout << "[+] Downloading Npcap from " << url << std::endl;
    HRESULT result = URLDownloadToFileA(NULL, url.c_str(), filename.c_str(), 0, NULL);
    if (result == S_OK) {
        std::cout << "[+] Download complete. Installing Npcap..." << std::endl;
        system("npcap.exe /S"); // Silent install
        std::cout << "[+] Npcap installed successfully!" << std::endl;
    } else {
        std::cout << "[-] Error downloading Npcap." << std::endl;
    }
}

// Function to enable monitor mode for a specific adapter
void enableMonitorMode(const std::string& adapterName) {
    std::cout << "[+] Enabling monitor mode for adapter: " << adapterName << std::endl;
    std::string command = "wlanhelper.exe " + adapterName + " mode monitor";
    system(command.c_str());
    std::cout << "[+] Monitor Mode enabled!" << std::endl;
}

// Function to disable monitor mode for a specific adapter
void disableMonitorMode(const std::string& adapterName) {
    std::cout << "[+] Disabling monitor mode for adapter: " << adapterName << std::endl;
    std::string command = "wlanhelper.exe " + adapterName + " mode managed";
    system(command.c_str());
    std::cout << "[+] Monitor Mode disabled!" << std::endl;
}

// Function to list adapters in monitor mode
std::vector<std::string> listMonitorModeAdapters() {
    std::vector<std::string> monitorAdapters;
    std::string line;
    std::ifstream monitorOutput("monitor_mode.txt");

    if (monitorOutput.is_open()) {
        while (getline(monitorOutput, line)) {
            if (line.find("Mode") != std::string::npos && line.find("Monitor") != std::string::npos) {
                std::string adapterName = line.substr(line.find(":") + 1);
                monitorAdapters.push_back(adapterName);
            }
        }
        monitorOutput.close();
    }

    return monitorAdapters;
}

// Function to prompt user for an adapter choice
int getAdapterChoice(const std::vector<std::string>& adapters) {
    std::cout << "[+] Available adapters:" << std::endl;
    for (int i = 0; i < adapters.size(); ++i) {
        std::cout << i + 1 << ". " << adapters[i] << std::endl;
    }

    int choice;
    std::cout << "[+] Choose an adapter by number: ";
    std::cin >> choice;

    if (choice >= 1 && choice <= adapters.size()) {
        return choice - 1;
    } else {
        std::cout << "[-] Invalid choice." << std::endl;
        return -1;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: %s start|kill" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "start") {
        std::cout << "[+] Checking compatible adapters for monitor mode..." << std::endl;
        std::vector<std::string> adapters = checkMonitorModeSupport();

        if (adapters.empty()) {
            std::cout << "[-] No compatible adapters found that support monitor mode." << std::endl;
            return 1;
        }

        int adapterChoice = getAdapterChoice(adapters);
        if (adapterChoice == -1) return 1;

        std::string adapterName = adapters[adapterChoice];
        std::cout << "[+] Selected adapter: " << adapterName << std::endl;

        char installNpcap;
        std::cout << "[+] Do you want to install Npcap? (y/n): ";
        std::cin >> installNpcap;

        if (installNpcap == 'y' || installNpcap == 'Y') {
            downloadNpcap();
        }

        enableMonitorMode(adapterName);

    } else if (command == "kill") {
        std::cout << "[+] Listing adapters in monitor mode..." << std::endl;
        std::vector<std::string> monitorAdapters = listMonitorModeAdapters();

        if (monitorAdapters.empty()) {
            std::cout << "[-] No adapters are in monitor mode." << std::endl;
            return 1;
        }

        int adapterChoice = getAdapterChoice(monitorAdapters);
        if (adapterChoice == -1) return 1;

        std::string adapterName = monitorAdapters[adapterChoice];
        std::cout << "[+] Selected adapter: " << adapterName << std::endl;

        disableMonitorMode(adapterName);

    } else {
        std::cout << "Usage: %s start|kill" << std::endl;
        return 1;
    }

    return 0;
}
