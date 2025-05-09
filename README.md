# Windows VM Optimizer
![wmoptim](https://github.com/user-attachments/assets/496aec6d-2b62-4703-bb57-3fba30d31bfb)

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
