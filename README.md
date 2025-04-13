# Windows VM Optimizer

## PowerShell script to optimize Windows VMs in Proxmox, VirtualBox, and other virtualization platforms.

### Features

- Auto-detects virtualization platform (Proxmox/KVM, VirtualBox, VMware, Hyper-V)  
- Optimizes performance, storage, memory, and network settings  
- Installs/configures guest agents and additions  
- Disables unnecessary services and scheduled tasks  

### Usage

1. Run as Administrator:  
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File vm-optimization.ps1
