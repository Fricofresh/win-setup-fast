# Check if winget is installed
if (Test-Path $env:userprofile\AppData\Local\Microsoft\WindowsApps\winget.exe) {
    #Checks if winget executable exists and if the Windows Version is 1809 or higher
    Write-Logs -Level INFO -Message "WinGet was detected" -LogPath $sync.logfile
}
else {

    if (($sync.ComputerInfo.WindowsVersion) -lt "1809") {
        #Checks if Windows Version is too old for winget
        Write-Logs -Level Warning -Message "Winget is not supported on this version of Windows (Pre-1809). Stopping installs" -LogPath $sync.logfile
        return
    }

    Write-Logs -Level INFO -Message "WinGet was not detected" -LogPath $sync.logfile

    if (((($sync.ComputerInfo.OSName.IndexOf("LTSC")) -ne -1) -or ($sync.ComputerInfo.OSName.IndexOf("Server") -ne -1)) -and (($sync.ComputerInfo.WindowsVersion) -ge "1809")) {
        Try{
            #Checks if Windows edition is LTSC/Server 2019+
            #Manually Installing Winget
            Write-Logs -Level INFO -Message "LTSC/Server Edition detected. Running Alternative Installer" -LogPath $sync.logfile

            #Download Needed Files
            $step = "Downloading the required files"
            Write-Logs -Level INFO -Message $step -LogPath $sync.logfile
            Start-BitsTransfer -Source "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -Destination "$ENV:TEMP\Microsoft.VCLibs.x64.14.00.Desktop.appx" -ErrorAction Stop
            Start-BitsTransfer -Source "https://github.com/microsoft/winget-cli/releases/download/v1.2.10271/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Destination "$ENV:TEMP/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -ErrorAction Stop
            Start-BitsTransfer -Source "https://github.com/microsoft/winget-cli/releases/download/v1.2.10271/b0a0692da1034339b76dce1c298a1e42_License1.xml" -Destination "$ENV:TEMP/b0a0692da1034339b76dce1c298a1e42_License1.xml" -ErrorAction Stop

            #Installing Packages
            $step = "Installing Packages"
            Write-Logs -Level INFO -Message $step -LogPath $sync.logfile
            Add-AppxProvisionedPackage -Online -PackagePath "$ENV:TEMP\Microsoft.VCLibs.x64.14.00.Desktop.appx" -SkipLicense -ErrorAction Stop
            Add-AppxProvisionedPackage -Online -PackagePath "$ENV:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -LicensePath "$ENV:TEMP\b0a0692da1034339b76dce1c298a1e42_License1.xml" -ErrorAction Stop
            
            #Sleep for 5 seconds to maximize chance that winget will work without reboot
            Start-Sleep -s 5

            #Removing no longer needed Files
            $step = "Removing Files"
            Write-Logs -Level INFO -Message $step -LogPath $sync.logfile
            Remove-Item -Path "$ENV:TEMP\Microsoft.VCLibs.x64.14.00.Desktop.appx" -Force
            Remove-Item -Path "$ENV:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Force
            Remove-Item -Path "$ENV:TEMP\b0a0692da1034339b76dce1c298a1e42_License1.xml" -Force

            $step = "WinGet Sucessfully installed"
            Write-Logs -Level INFO -Message $step -LogPath $sync.logfile

        }Catch{Write-Logs -Level FAILURE -Message "WinGet Install failed at $step" -LogPath $sync.logfile}
    }
    else {
        Try{
            #Installing Winget from the Microsoft Store                       
            $step = "Installing WinGet"
            Write-Logs -Level INFO -Message $step -LogPath $sync.logfile
            Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
            $nid = (Get-Process AppInstaller).Id
            Wait-Process -Id $nid

            $step = "Winget Installed"
            Write-Logs -Level INFO -Message $step -LogPath $sync.logfile
        }Catch{Write-Logs -Level FAILURE -Message "WinGet Install failed at $step" -LogPath $sync.logfile}
    }
    Write-Logs -Level INFO -Message "WinGet has been installed" -LogPath $sync.logfile
    Start-Sleep -Seconds 15
}

winget import -i winget.json --ignore-unavailable --accept-package-agreements --accept-source-agreements
