New-Item -ItemType Directory -Force -Path "C:\Program Files\UsbGuard\Driver" | Out-Null
Copy-Item "C:\KMDF Driver1\x64\Debug\UsbGuardMiniFilter.sys" "C:\Program Files\UsbGuard\Driver\UsbGuardMiniFilter.sys" -Force
Copy-Item "C:\KMDF Driver1\x64\Debug\KMDFDriver1.inf" "C:\Program Files\UsbGuard\Driver\UsbGuardMiniFilter.inf" -Force
Copy-Item "C:\KMDF Driver1\x64\Debug\KMDF Driver1\usbguardminifilter.cat" "C:\Program Files\UsbGuard\Driver\UsbGuardMiniFilter.cat" -Force
pnputil /add-driver "C:\Program Files\UsbGuard\Driver\UsbGuardMiniFilter.inf" /install
Start-Service UsbGuardAgent
