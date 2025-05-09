# Proxmox/VirtualBox Windows VM Essential Optimization Script
# Run this as Administrator to optimize a Windows VM for virtualization platforms

function Show-Menu {
    param (
        [string]$Title,
        [string[]]$Options
    )

    $choices = @{}
    for ($i = 0; $i -lt $Options.Length; $i++) {
        $choices[$i] = $true  # All checked by default
    }

    while ($true) {
        Clear-Host
        Write-Host "=== $Title ===`n"
        for ($i = 0; $i -lt $Options.Length; $i++) {
            $check = if ($choices[$i]) { "[X]" } else { "[ ]" }
            Write-Host "$($i+1). $check $($Options[$i])"
        }
        Write-Host "`nPress number to toggle, ENTER to continue..."

        $input = Read-Host
        if ($input -eq "") { break }
        $index = [int]$input - 1
        if ($choices.ContainsKey($index)) {
            $choices[$index] = -not $choices[$index]
        }
    }

    return $choices
}

# Menu Options - Only Essential VM Optimizations
$steps = @(
    "Install/Enable QEMU Guest Agent", 
    "Install/Enable VirtualBox Guest Additions",
    "Disable Hibernation",
    "Disable Sleep and Display Timeout",
    "Disable Fast Startup",
    "Optimize Virtual Memory Settings",
    "Disable Windows Search Service",
    "Disable Background Apps",
    "Set High Performance Power Plan",
    "Disable Scheduled Tasks",
    "Optimize Network Settings",
    "Clean Disk Space"
)

$selected = Show-Menu -Title "Essential Proxmox VM Optimizations" -Options $steps

# === Step Execution ===

if ($selected[0]) {
    Write-Host ">> Installing/Enabling QEMU Guest Agent..." -ForegroundColor Green
    # Check if QEMU Guest Agent is installed
    $qemuAgentService = Get-Service -Name "QEMU-GA" -ErrorAction SilentlyContinue
    if (-not $qemuAgentService) {
        # Create a temporary directory
        $tempDir = "$env:TEMP\qemu-ga-install"
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        
        # Download URL for QEMU Guest Agent
        $qemuGaUrl = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-qemu-ga/qemu-ga-x86_64.msi"
        $qemuGaInstaller = "$tempDir\qemu-ga-x86_64.msi"
        
        try {
            # Download the installer
            Write-Host "   Downloading QEMU Guest Agent..." -ForegroundColor Gray
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($qemuGaUrl, $qemuGaInstaller)
            
            # Install silently
            Write-Host "   Installing QEMU Guest Agent..." -ForegroundColor Gray
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$qemuGaInstaller`" /qn" -Wait
            
            # Start the service
            Start-Service -Name "QEMU-GA" -ErrorAction SilentlyContinue
            Set-Service -Name "QEMU-GA" -StartupType Automatic -ErrorAction SilentlyContinue
            
            Write-Host "   QEMU Guest Agent installed successfully" -ForegroundColor Green
        }
        catch {
            Write-Host "   Failed to install QEMU Guest Agent: $_" -ForegroundColor Red
            Write-Host "   Please manually install the QEMU Guest Agent from: $qemuGaUrl" -ForegroundColor Yellow
        }
        finally {
            # Clean up
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        Write-Host "   QEMU Guest Agent is already installed" -ForegroundColor Green
        # Ensure the service is running and set to automatic
        Set-Service -Name "QEMU-GA" -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name "QEMU-GA" -ErrorAction SilentlyContinue
    }
    
    # Check for VirtIO drivers
    $virtioDriversInstalled = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceName -like "*virtio*" }
    if (-not $virtioDriversInstalled) {
        Write-Host "   VirtIO drivers not detected. For best performance, install them from:" -ForegroundColor Yellow
        Write-Host "   https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso" -ForegroundColor Yellow
    }
    else {
        Write-Host "   VirtIO drivers detected" -ForegroundColor Green
    }
}

if ($selected[1]) {
    Write-Host ">> Installing/Enabling VirtualBox Guest Additions..." -ForegroundColor Green
    
    # Check if VirtualBox Guest Additions are already installed
    $vboxService = Get-Service -Name "VBoxService" -ErrorAction SilentlyContinue
    $vboxTrayApp = Get-Process -Name "VBoxTray" -ErrorAction SilentlyContinue
    
    if ($vboxService -or $vboxTrayApp) {
        Write-Host "   VirtualBox Guest Additions are already installed" -ForegroundColor Green
        
        # Ensure the service is running and set to automatic
        if ($vboxService) {
            Set-Service -Name "VBoxService" -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name "VBoxService" -ErrorAction SilentlyContinue
        }
    } else {
        # Check if we're running in VirtualBox
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $isVirtualBox = $computerSystem.Model -like "*VirtualBox*"
        
        if ($isVirtualBox) {
            Write-Host "   Detected VirtualBox VM. Checking for Guest Additions ISO..." -ForegroundColor Gray
            
            # Check for mounted Guest Additions ISO
            $guestAdditionsDrive = Get-WmiObject Win32_LogicalDisk | Where-Object { 
                (Test-Path "$($_.DeviceID)\VBoxWindowsAdditions.exe") -or 
                (Test-Path "$($_.DeviceID)\VBoxWindowsAdditions-x86.exe") -or 
                (Test-Path "$($_.DeviceID)\VBoxWindowsAdditions-amd64.exe") 
            } | Select-Object -First 1
            
            if ($guestAdditionsDrive) {
                Write-Host "   Found Guest Additions ISO mounted at $($guestAdditionsDrive.DeviceID)" -ForegroundColor Green
                
                # Determine installer path
                $installer = ""
                if (Test-Path "$($guestAdditionsDrive.DeviceID)\VBoxWindowsAdditions-amd64.exe") {
                    $installer = "$($guestAdditionsDrive.DeviceID)\VBoxWindowsAdditions-amd64.exe"
                } elseif (Test-Path "$($guestAdditionsDrive.DeviceID)\VBoxWindowsAdditions-x86.exe") {
                    $installer = "$($guestAdditionsDrive.DeviceID)\VBoxWindowsAdditions-x86.exe"
                } elseif (Test-Path "$($guestAdditionsDrive.DeviceID)\VBoxWindowsAdditions.exe") {
                    $installer = "$($guestAdditionsDrive.DeviceID)\VBoxWindowsAdditions.exe"
                }
                
                if ($installer) {
                    Write-Host "   Installing VirtualBox Guest Additions..." -ForegroundColor Gray
                    # Run installer silently
                    Start-Process -FilePath $installer -ArgumentList "/S" -Wait
                    Write-Host "   VirtualBox Guest Additions installed successfully" -ForegroundColor Green
                } else {
                    Write-Host "   Error: Couldn't find VirtualBox Guest Additions installer" -ForegroundColor Red
                }
            } else {
                Write-Host "   VirtualBox Guest Additions ISO not mounted" -ForegroundColor Yellow
                Write-Host "   Please insert Guest Additions CD from VirtualBox menu: Devices > Insert Guest Additions CD..." -ForegroundColor Yellow
            }
        } else {
            Write-Host "   Not running in VirtualBox. Skipping Guest Additions installation." -ForegroundColor Gray
        }
    }
    
    # Check for VirtualBox video driver
    $vboxVideo = Get-WmiObject Win32_VideoController | Where-Object { $_.Description -like "*VirtualBox*" }
    if ($vboxVideo) {
        Write-Host "   VirtualBox video driver detected" -ForegroundColor Green
    } else {
        Write-Host "   VirtualBox video driver not detected" -ForegroundColor Yellow
    }
    
    # Check for VirtualBox audio driver
    $vboxAudio = Get-WmiObject Win32_SoundDevice | Where-Object { $_.Name -like "*VirtualBox*" }
    if ($vboxAudio) {
        Write-Host "   VirtualBox audio driver detected" -ForegroundColor Green
    } else {
        Write-Host "   VirtualBox audio driver not detected" -ForegroundColor Yellow
    }
}

if ($selected[2]) {
    Write-Host ">> Disabling Hibernation..." -ForegroundColor Green
    powercfg -h off
}

if ($selected[3]) {
    Write-Host ">> Disabling Sleep and Display Timeout..." -ForegroundColor Green
    powercfg -change -standby-timeout-ac 0
    powercfg -change -monitor-timeout-ac 0
    powercfg -change -disk-timeout-ac 0
}

if ($selected[4]) {
    Write-Host ">> Disabling Fast Startup..." -ForegroundColor Green
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "HiberbootEnabled" -Value 0 -Type DWord -Force
}

if ($selected[5]) {
    Write-Host ">> Optimizing Virtual Memory Settings..." -ForegroundColor Green
    # Calculate optimal page file size based on VM RAM
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $totalRam = [Math]::Round($computerSystem.TotalPhysicalMemory / 1GB)
    $pageFileSize = [Math]::Min($totalRam, 4) * 1024  # Cap at 4GB or total RAM, whichever is smaller

    # Update page file settings
    $computerSystem.AutomaticManagedPagefile = $false
    $computerSystem.Put() | Out-Null
    
    # Configure the page file
    $pagefile = Get-WmiObject -Query "SELECT * FROM Win32_PageFileSetting WHERE Name='C:\\pagefile.sys'"
    if ($pagefile) {
        $pagefile.InitialSize = $pageFileSize
        $pagefile.MaximumSize = $pageFileSize
        $pagefile.Put() | Out-Null
    } else {
        $pagefileSetting = Get-WmiObject -List | Where-Object { $_.Name -eq "Win32_PageFileSetting" }
        $newPagefile = $pagefileSetting.CreateInstance()
        $newPagefile.Name = "C:\pagefile.sys"
        $newPagefile.InitialSize = $pageFileSize
        $newPagefile.MaximumSize = $pageFileSize
        $newPagefile.Put() | Out-Null
    }
    
    Write-Host "   Page file set to $pageFileSize MB" -ForegroundColor Gray
}

if ($selected[6]) {
    Write-Host ">> Disabling Windows Search Service..." -ForegroundColor Green
    Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WSearch" -StartupType Disabled
}

if ($selected[7]) {
    Write-Host ">> Disabling Background Apps..." -ForegroundColor Green
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "GlobalUserDisabled" -Value 1 -Type DWord
    
    # Disable all background apps except critical Windows ones
    Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*", "Microsoft.Windows.ShellExperienceHost*" | ForEach-Object {
        Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Value 1 -Type DWord -Force
    }
}

if ($selected[8]) {
    Write-Host ">> Setting Power Plan to High Performance..." -ForegroundColor Green
    powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    
    # Disable CPU throttling
    powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 100
    powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
}

if ($selected[9]) {
    Write-Host ">> Disabling Unnecessary Scheduled Tasks..." -ForegroundColor Green
    $tasksToDisable = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\Maintenance\WinSAT",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting",
        "\Microsoft\Windows\Defrag\ScheduledDefrag"
    )
    
    foreach ($task in $tasksToDisable) {
        Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
        Write-Host "   Disabled task: $task" -ForegroundColor Gray
    }
}

if ($selected[10]) {
    Write-Host ">> Optimizing Network Settings for VM..." -ForegroundColor Green
    # Disable IPv6 (often unnecessary in VMs)
    Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6" -ErrorAction SilentlyContinue
    
    # Network adapter optimization
    Get-NetAdapter | ForEach-Object {
        # Disable TCP/IP offloading features (more reliable in VMs)
        Disable-NetAdapterChecksumOffload -Name $_.Name -ErrorAction SilentlyContinue
        Disable-NetAdapterLso -Name $_.Name -ErrorAction SilentlyContinue
        
        Write-Host "   Optimized network adapter: $($_.Name)" -ForegroundColor Gray
    }
    
    # Optimize TCP settings
    netsh int tcp set global autotuninglevel=disabled
    netsh int tcp set global ecncapability=disabled
    
    # Disable Network Location Awareness service (improves boot time)
    Set-Service -Name "NlaSvc" -StartupType Manual -ErrorAction SilentlyContinue
}

if ($selected[11]) {
    Write-Host ">> Cleaning Disk Space..." -ForegroundColor Green
    # Set up disk cleanup settings
    $cleanMgrKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
    
    # Target all disk cleanup options
    $cleanupOptions = @(
        "Active Setup Temp Folders"
        "BranchCache"
        "Downloaded Program Files"
        "Internet Cache Files"
        "Old ChkDsk Files"
        "Previous Installations"
        "Recycle Bin"
        "Setup Log Files"
        "System error memory dump files"
        "System error minidump files"
        "Temporary Files"
        "Temporary Setup Files"
        "Thumbnail Cache"
        "Update Cleanup"
        "Upgrade Discarded Files"
        "Windows Defender"
        "Windows Error Reporting Files"
        "Windows ESD installation files"
    )
    
    # Enable all cleanup options
    foreach ($option in $cleanupOptions) {
        $optionKey = "$cleanMgrKey\$option"
        if (Test-Path $optionKey) {
            New-ItemProperty -Path $optionKey -Name "StateFlags0001" -Value 2 -PropertyType DWORD -Force | Out-Null
        }
    }
    
    # Run Disk Cleanup silently
    Start-Process -FilePath cleanmgr.exe -ArgumentList "/sagerun:1" -Wait -WindowStyle Hidden
    
    # Clean temp folders
    Remove-Item -Path "C:\Windows\Temp\*" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:TEMP\*" -Force -Recurse -ErrorAction SilentlyContinue
}



# Additional critical VM optimizations (always run)
Write-Host "`n>> Performing critical VM optimizations..." -ForegroundColor Green

# Detect virtualization platform
$computerSystem = Get-WmiObject -Class Win32_ComputerSystem
$isVirtualBox = $computerSystem.Model -like "*VirtualBox*"
$isVMware = $computerSystem.Manufacturer -like "*VMware*"
$isHyperV = $computerSystem.Model -like "*Virtual Machine*" -and $computerSystem.Manufacturer -like "*Microsoft*"
$isKVM = (Get-WmiObject Win32_PnPEntity | Where-Object { $_.DeviceID -like "*QEMU*" -or $_.DeviceID -like "*VEN_1AF4*" }) -ne $null

if ($isVirtualBox) {
    Write-Host "   Detected VirtualBox virtualization" -ForegroundColor Cyan
} elseif ($isVMware) {
    Write-Host "   Detected VMware virtualization" -ForegroundColor Cyan
} elseif ($isHyperV) {
    Write-Host "   Detected Hyper-V virtualization" -ForegroundColor Cyan
} elseif ($isKVM) {
    Write-Host "   Detected KVM/Proxmox virtualization" -ForegroundColor Cyan
} else {
    Write-Host "   Unknown virtualization platform" -ForegroundColor Yellow
}

# Disable Spectre and Meltdown mitigations (increases performance in VMs)
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
Set-ItemProperty -Path $regPath -Name "FeatureSettingsOverride" -Value 3 -Type DWORD -ErrorAction SilentlyContinue
Set-ItemProperty -Path $regPath -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWORD -ErrorAction SilentlyContinue
Write-Host "   Disabled Spectre/Meltdown mitigations for VM performance" -ForegroundColor Gray

# Disable Superfetch/SysMain (unnecessary in VMs)
Stop-Service -Name "SysMain" -Force -ErrorAction SilentlyContinue
Set-Service -Name "SysMain" -StartupType Disabled -ErrorAction SilentlyContinue
Write-Host "   Disabled Superfetch/SysMain service" -ForegroundColor Gray

# Optimize NTFS
fsutil behavior set disablelastaccess 1
Write-Host "   Optimized NTFS settings" -ForegroundColor Gray

# Configure audio for VM
if ($isVirtualBox -or $isKVM) {
    # Check for audio issues
    $audioDevices = Get-WmiObject Win32_SoundDevice | Where-Object { $_.Status -eq "OK" }
    if (-not $audioDevices) {
        Write-Host "   Warning: No functioning audio devices detected" -ForegroundColor Yellow
        Write-Host "   If audio is needed, ensure guest additions are properly installed" -ForegroundColor Yellow
    } else {
        Write-Host "   Audio devices configured correctly" -ForegroundColor Gray
    }
}

# Set services that are unnecessary in VMs to manual start
$vmUnnecessaryServices = @(
    "DiagTrack",           # Connected User Experiences and Telemetry
    "dmwappushservice",    # WAP Push Message Routing Service
    "MapsBroker",          # Downloaded Maps Manager
    "lfsvc",               # Geolocation Service
    "SharedAccess",        # Internet Connection Sharing
    "lltdsvc",             # Link-Layer Topology Discovery Mapper
    "workfolderssvc",      # Work Folders
    "WbioSrvc",            # Windows Biometric Service
    "WerSvc",              # Windows Error Reporting Service
    "WSearch"              # Windows Search
)

foreach ($service in $vmUnnecessaryServices) {
    Set-Service -Name $service -StartupType Manual -ErrorAction SilentlyContinue
}
Write-Host "   Set unnecessary services to manual start" -ForegroundColor Gray

# Ensure RDP is enabled for VM management
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
Write-Host "   Enabled Remote Desktop for VM management" -ForegroundColor Gray

Write-Host "`n✅ VM optimization completed! Your Windows VM is now optimized for virtual environments." -ForegroundColor Cyan" -ErrorAction SilentlyContinue
Write-Host "   Enabled Remote Desktop for VM management" -ForegroundColor Gray

Write-Host "`n✅ VM optimization completed! Your Windows VM is now optimized for virtual environments." -ForegroundColor Cyan" -ErrorAction SilentlyContinue
Write-Host "   Enabled Remote Desktop for VM management" -ForegroundColor Gray

Write-Host "`n✅ VM optimization completed! Your Windows VM is now optimized for virtual environments." -ForegroundColor Cyan

