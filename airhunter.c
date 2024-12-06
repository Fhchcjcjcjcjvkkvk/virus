#include <windows.h>
#include <wlanapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

void usage() {
    printf("Usage: ./code -b <BSSID>\n");
    printf("Example: ./code -b 00:11:22:33:44:55\n");
}

void print_mac_address(PBYTE mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02X", mac[i]);
        if (i < 5) printf(":");
    }
    printf("\n");
}

int get_connected_clients_by_bssid(const char *bssid) {
    HANDLE hClient = NULL;
    DWORD dwResult = 0;
    WLAN_INTERFACE_INFO_LIST *pIfList = NULL;
    WLAN_INTERFACE_INFO *pIfInfo = NULL;
    PWLAN_BSS_LIST pBssList = NULL;

    // Initialize WLAN API
    dwResult = WlanOpenHandle(2, NULL, &dwResult, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        printf("Error opening WLAN handle: %u\n", dwResult);
        return 1;
    }

    // Enumerate wireless interfaces
    dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
    if (dwResult != ERROR_SUCCESS) {
        printf("Error enumerating WLAN interfaces: %u\n", dwResult);
        WlanCloseHandle(hClient, NULL);
        return 1;
    }

    // Iterate through interfaces
    for (int i = 0; i < (int)pIfList->dwNumberOfItems; i++) {
        pIfInfo = &pIfList->InterfaceInfo[i];

        // Get the BSS list for the interface
        dwResult = WlanGetNetworkBssList(hClient, &pIfInfo->InterfaceGuid, NULL, dot11_BSS_type_infrastructure, FALSE, NULL, &pBssList);
        if (dwResult != ERROR_SUCCESS) {
            printf("Error getting BSS list for interface %s: %u\n", pIfInfo->strInterfaceDescription, dwResult);
            continue;
        }

        // Loop through BSS list and find matching BSSID
        for (int j = 0; j < (int)pBssList->dwNumberOfItems; j++) {
            if (memcmp(pBssList->wlanBssEntries[j].dot11Bssid, bssid, 6) == 0) {
                printf("Found BSSID: ");
                print_mac_address(pBssList->wlanBssEntries[j].dot11Bssid);

                // Print clients connected to the BSSID
                printf("Clients connected to BSSID %s:\n", bssid);
                // Note: Here, you would typically have to further query the network to find connected clients.
                // For example, this might require using other management APIs or monitoring the network traffic.
            }
        }

        if (pBssList) {
            WlanFreeMemory(pBssList);
            pBssList = NULL;
        }
    }

    // Clean up
    if (pIfList) {
        WlanFreeMemory(pIfList);
    }
    WlanCloseHandle(hClient, NULL);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3 || strcmp(argv[1], "-b") != 0) {
        usage();
        return 1;
    }

    const char *bssid = argv[2];

    // Validate BSSID format (simple check for MAC address format)
    if (strlen(bssid) != 17) {
        printf("Invalid BSSID format. It should be in the format XX:XX:XX:XX:XX:XX\n");
        return 1;
    }

    // Call function to get connected clients by BSSID
    return get_connected_clients_by_bssid(bssid);
}
