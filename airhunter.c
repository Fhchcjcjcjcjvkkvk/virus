#include <stdio.h>
#include <windows.h>
#include <wlanapi.h>
#include <objbase.h>
#include <iphlpapi.h>
#include <wtypes.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")

void PrintBssid(const BYTE* bssid) {
    for (int i = 0; i < 6; i++) {
        printf("%02X", bssid[i]);
        if (i < 5) printf(":");
    }
}

void PrintNetworkList(PWLAN_BSS_LIST pBssList) {
    for (int i = 0; i < pBssList->dwNumberOfItems; i++) {
        WLAN_BSS_ENTRY bssEntry = pBssList->wlanBssEntries[i];

        // Print SSID
        printf("SSID: ");
        for (int j = 0; j < bssEntry.dot11Ssid.uSSIDLength; j++) {
            printf("%c", bssEntry.dot11Ssid.ucSSID[j]);
        }
        printf("\n");

        // Print BSSID (MAC address)
        printf("BSSID: ");
        PrintBssid(bssEntry.dot11Bssid);
        printf("\n");

        // Print RSSI
        printf("RSSI: %d dBm\n", bssEntry.ilRssi);

        // Print Beacon Period (this is a measure of how often beacons are sent)
        printf("Beacon Period: %d (time units)\n", bssEntry.usBeaconPeriod);
        printf("---------------------------------\n");
    }
}

int main() {
    HANDLE hClient = NULL;
    DWORD dwMaxClient = 2; // max client version
    DWORD dwCurVersion = 0;
    DWORD dwResult = 0;

    // Initialize COM
    if (CoInitializeEx(NULL, COINIT_MULTITHREADED) != S_OK) {
        printf("COM initialization failed!\n");
        return -1;
    }

    // Initialize WLAN client
    dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        printf("WlanOpenHandle failed with error: %u\n", dwResult);
        CoUninitialize();
        return -1;
    }

    // Enumerate WLAN interfaces
    PWLAN_INTERFACE_INFO_LIST pInterfaceList = NULL;
    dwResult = WlanEnumInterfaces(hClient, NULL, &pInterfaceList);
    if (dwResult != ERROR_SUCCESS) {
        printf("WlanEnumInterfaces failed with error: %u\n", dwResult);
        WlanCloseHandle(hClient, NULL);
        CoUninitialize();
        return -1;
    }

    // Iterate through interfaces
    for (int i = 0; i < (int)pInterfaceList->dwNumberOfItems; i++) {
        printf("Interface %d: %ws\n", i + 1, pInterfaceList->InterfaceInfo[i].strInterfaceDescription);

        // Get network BSS list
        PWLAN_BSS_LIST pBssList = NULL;
        dwResult = WlanGetNetworkBssList(hClient, &pInterfaceList->InterfaceInfo[i].InterfaceGuid, NULL, dot11BssTypeAny, FALSE, NULL, &pBssList);
        if (dwResult == ERROR_SUCCESS) {
            PrintNetworkList(pBssList);
            WlanFreeMemory(pBssList);
        } else {
            printf("WlanGetNetworkBssList failed with error: %u\n", dwResult);
        }
    }

    // Cleanup
    WlanFreeMemory(pInterfaceList);
    WlanCloseHandle(hClient, NULL);
    CoUninitialize();

    return 0;
}
