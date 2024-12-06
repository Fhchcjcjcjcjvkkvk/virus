#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

void list_networks() {
    // Run netsh command to list WiFi networks
    printf("Listing available Wi-Fi networks...\n");
    system("netsh wlan show networks mode=bssid");
}

void capture_packets(const char *file_name, const char *bssid, const char *interface_name) {
    // Construct tshark command to capture packets for the specified BSSID
    char command[256];
    sprintf(command, "tshark -i \"%s\" -w %s -f \"ether host %s and eapol\"", interface_name, file_name, bssid);
    
    printf("Capturing packets from BSSID: %s\n", bssid);
    
    // Execute the tshark command to capture packets
    int result = system(command);

    // Check if the capture was successful
    if (result == 0) {
        printf("Capture started. Looking for EAPOL handshake...\n");
        // Wait until the capture completes or user presses Ctrl+C
    } else {
        printf("Failed to start packet capture.\n");
    }
}

void show_clients(const char *bssid, const char *interface_name) {
    // Use tshark to list the clients connected to the specified BSSID
    // This command will look for any packets associated with the BSSID and extract the MAC addresses of clients
    char command[256];
    sprintf(command, "tshark -i \"%s\" -Y \"wlan.addr == %s\" -T fields -e wlan.sa -e wlan.da", interface_name, bssid);

    printf("Clients connected to BSSID: %s\n", bssid);
    printf("Displaying MAC addresses of clients:\n");

    // Execute the tshark command to show client MAC addresses
    int result = system(command);

    // Check if the command was successful
    if (result != 0) {
        printf("Failed to retrieve clients. Ensure tshark is running and capturing traffic.\n");
    }
}

int main(int argc, char *argv[]) {
    const char *default_interface = "Wi-Fi";  // Default Wi-Fi interface name on Windows

    if (argc == 1) {
        // If no arguments are provided, list available networks
        list_networks();
    } else if (argc == 5 && strcmp(argv[1], "-w") == 0 && strcmp(argv[3], "-b") == 0) {
        // If the command is in the form of airhunter -w capture.pcap -b <BSSID>
        const char *file_name = argv[2];
        const char *bssid = argv[4];

        // Capture packets with EAPOL filter for the given BSSID
        capture_packets(file_name, bssid, default_interface);
    } else if (argc == 3 && strcmp(argv[1], "-b") == 0) {
        // If the command is in the form of airhunter -b <BSSID>, show connected clients
        const char *bssid = argv[2];
        
        // Show the clients connected to the given BSSID
        show_clients(bssid, default_interface);
    } else if (argc == 5 && strcmp(argv[1], "-w") == 0 && strcmp(argv[3], "-b") == 0 && strcmp(argv[4], "-i") == 0) {
        // If the command is in the form of airhunter -w capture.pcap -b <BSSID> -i <interface>
        const char *file_name = argv[2];
        const char *bssid = argv[4];
        const char *interface_name = argv[5];

        // Capture packets with EAPOL filter for the given BSSID and interface
        capture_packets(file_name, bssid, interface_name);
    } else if (argc == 4 && strcmp(argv[1], "-b") == 0 && strcmp(argv[3], "-i") == 0) {
        // If the command is in the form of airhunter -b <BSSID> -i <interface>, show clients connected
        const char *bssid = argv[2];
        const char *interface_name = argv[3];

        // Show the clients connected to the given BSSID and interface
        show_clients(bssid, interface_name);
    } else {
        printf("Invalid arguments. Usage:\n");
        printf("airhunter               : List available networks\n");
        printf("airhunter -w <file> -b <BSSID> : Capture EAPOL packets for the specified BSSID\n");
        printf("airhunter -b <BSSID> : Show clients connected to the specified BSSID\n");
        printf("airhunter -w <file> -b <BSSID> -i <interface> : Capture packets for BSSID using specified interface\n");
        printf("airhunter -b <BSSID> -i <interface> : Show clients connected using specified interface\n");
    }
    
    return 0;
}
