#include <windows.h>
#include <wlanapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

void PrintNetworkInfo(WLAN_AVAILABLE_NETWORK* network) {
    // Convert the BSSID to a readable format
    char bssid[18];
    snprintf(bssid, sizeof(bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
             network->bssid[0], network->bssid[1], network->bssid[2],
             network->bssid[3], network->bssid[4], network->bssid[5]);

    // Convert the ESSID to a string
    char essid[33];
    snprintf(essid, sizeof(essid), "%.*s", network->ssidLength, network->ssid);

    // Display the network information
    printf("ESSID: %s\n", essid);
    printf("BSSID: %s\n", bssid);
    printf("RSSI: %d dBm\n", network->rssi);
    printf("Signal Quality: %d%%\n", network->signalQuality);
    printf("----------------------------------------------------\n");
}

int main() {
    HANDLE hClient = NULL;
    DWORD dwVersion = 0;

    // Initialize WLAN API
    if (WlanOpenHandle(2, NULL, &dwVersion, &hClient) != ERROR_SUCCESS) {
        printf("Error: Unable to open WLAN handle\n");
        return 1;
    }

    // Enumerate wireless interfaces
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    if (WlanEnumInterfaces(hClient, NULL, &pIfList) != ERROR_SUCCESS) {
        printf("Error: Unable to enumerate interfaces\n");
        WlanCloseHandle(hClient, NULL);
        return 1;
    }

    if (pIfList->dwNumberOfItems == 0) {
        printf("No wireless interfaces found.\n");
        WlanFreeMemory(pIfList);
        WlanCloseHandle(hClient, NULL);
        return 1;
    }

    // Scan for networks
    PWLAN_AVAILABLE_NETWORK_LIST pNetworkList = NULL;
    for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
        WLAN_INTERFACE_INFO interfaceInfo = pIfList->InterfaceInfo[i];
        printf("Scanning on interface: %ws\n", interfaceInfo.strInterfaceDescription);

        if (WlanScan(hClient, &interfaceInfo.InterfaceGuid, NULL, NULL, NULL) != ERROR_SUCCESS) {
            printf("Error: Unable to scan on interface %ws\n", interfaceInfo.strInterfaceDescription);
            continue;
        }

        // Wait for the scan to complete
        Sleep(2000);

        // Get scan results
        if (WlanGetAvailableNetworkList(hClient, &interfaceInfo.InterfaceGuid, 0, NULL, &pNetworkList) != ERROR_SUCCESS) {
            printf("Error: Unable to get network list\n");
            continue;
        }

        // Print available networks information
        for (DWORD j = 0; j < pNetworkList->dwNumberOfItems; j++) {
            PrintNetworkInfo(&pNetworkList->Network[j]);
        }

        WlanFreeMemory(pNetworkList);
    }

    WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);

    return 0;
}
