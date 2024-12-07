#include <windows.h>
#include <wlanapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

void PrintErrorMessage(DWORD dwError) {
    LPVOID lpMsgBuf;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                  NULL, dwError, 0, (LPTSTR)&lpMsgBuf, 0, NULL);
    printf("Error: %s\n", (char*)lpMsgBuf);
    LocalFree(lpMsgBuf);
}

void PrintBssid(BYTE *bssid) {
    for (int i = 0; i < 6; i++) {
        printf("%02X", bssid[i]);
        if (i < 5) printf(":");
    }
}

void ListAvailableNetworks() {
    HANDLE hClient = NULL;
    DWORD dwVersion = 0;
    WLAN_INTERFACE_INFO_LIST *pIfList = NULL;
    WLAN_INTERFACE_INFO *pIfInfo = NULL;
    DWORD dwResult = 0;

    // Initialize WLAN API
    dwResult = WlanOpenHandle(2, NULL, &dwVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        PrintErrorMessage(dwResult);
        return;
    }

    // Enumerate wireless interfaces
    dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
    if (dwResult != ERROR_SUCCESS) {
        PrintErrorMessage(dwResult);
        return;
    }

    // Check if there are available interfaces
    if (pIfList->dwNumberOfItems == 0) {
        printf("No wireless interfaces found.\n");
        return;
    }

    pIfInfo = &pIfList->InterfaceInfo[0]; // Assuming we only work with the first interface

    // Scan for available networks
    dwResult = WlanScan(hClient, &pIfInfo->InterfaceGuid, NULL, NULL, NULL);
    if (dwResult != ERROR_SUCCESS) {
        PrintErrorMessage(dwResult);
        return;
    }

    // Wait a few seconds for the scan to complete
    printf("Scanning for networks...\n");
    Sleep(5000);

    // Get scan results
    PWLAN_BSS_LIST pBssList = NULL;
    dwResult = WlanGetNetworkBssList(hClient, &pIfInfo->InterfaceGuid, NULL, dot11_BSS_type_any, FALSE, NULL, &pBssList);
    if (dwResult != ERROR_SUCCESS) {
        PrintErrorMessage(dwResult);
        return;
    }

    // Display the list of available networks
    printf("Available Networks:\n");
    for (DWORD i = 0; i < pBssList->dwNumberOfItems; i++) {
        WLAN_BSS_ENTRY bssEntry = pBssList->wlanBssEntries[i];
        printf("%d. SSID: %.*s, BSSID: ", i + 1, bssEntry.dot11Ssid.uSSIDLength, bssEntry.dot11Ssid.ucSSID);
        PrintBssid(bssEntry.dot11Bssid);
        printf(", Signal Strength: %d dBm\n", bssEntry.rssi);
    }

    // Clean up
    if (pBssList != NULL) {
        WlanFreeMemory(pBssList);
    }
    if (pIfList != NULL) {
        WlanFreeMemory(pIfList);
    }
    WlanCloseHandle(hClient, NULL);
}

int main() {
    ListAvailableNetworks();
    return 0;
}
