@echo off
cls

:: Enable ANSI escape codes (Works on Windows 10 and later)
echo.

:: Display colored antenna and wave banner
echo.   ^[[31m.;'                     `;,   ^[[0m
echo.   ^[[31m.;'  ^[[32m,;'             `;,  `;,   ^[[0m
echo.   ^[[31m.;'  ^[[32m,;'  ^[[32m,;'     `;,  `;,  `;,   ^[[0m
echo.   ^[[31m::   ^[[32m::   ^[[32m:   ( )   :   ^[[32m::   ::   ^[[0m
echo.   ^[[31m':   ^[[32m':   ^[[32m':  /_\ ,:'  ^[[32m,:'  ,:'  ^[[0m
echo.   ^[[31m ':   ^[[32m':     /___\    ,:'  ,:'   ^[[0m
echo.    ^[[31m ':        /_____\      ,:'     ^[[0m
echo.              ^[[31m/       \         ^[[0m
echo.

:: Wait for 2 seconds to display the banner
timeout /t 2 >nul

:: Request user to enter the network interface (e.g., wlan0)
set /p INTERFACE=ENTER INTERFACE (e.g., wlan0): 
echo.

:: Start the network scan and display information in columns
echo Scanning for networks...
echo.

:: Start the scan and capture the network details
netsh wlan show networks mode=bssid > temp_networks.txt

:: Parse output and display it in a formatted table
echo Elapsed: 0 min
echo ----------------------------------------------
echo BSSID              ESSID        CH   ENCR   CIPHER   RSSI   Beacons
echo ----------------------------------------------

for /f "tokens=1,* delims=:" %%a in ('findstr /i "SSID BSSID Channel Encryption RSSI" temp_networks.txt') do (
    set line=%%b
    set line=!line: =!
    if not "!line!"=="" (
        echo !line!
    )
)

:: Request user to enter the BSSID for packet capture
set /p BSSID=ENTER BSSID to capture packets: 
echo.
echo Capturing packets for BSSID %BSSID% on interface %INTERFACE%...

:: Run tshark to capture packets on the selected interface and BSSID
tshark -i %INTERFACE% -f "ether host %BSSID%" -w capture.pcap

pause
