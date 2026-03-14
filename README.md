# Native Hardware Monitor 🖥️⚡

The **Native Hardware Monitor** is an advanced, ultra-lightweight telemetry dashboard written in PowerShell. It provides real-time data about your system's core without the need to install third-party bloatware. 

The architecture is designed to have a near-zero CPU footprint, utilizing asynchronous C# code injections (PInvoke) to extract data directly from the Windows Kernel and hardware drivers.

⚠️ **IMPORTANT: GPU LIMITATION**
This monitor uses the native NVIDIA library (`nvml.dll`) to read video sensors. Therefore, graphics card data collection **works exclusively with NVIDIA GPUs**. AMD (Radeon) or Intel graphics cards will not display graphical telemetry data.

---

## ⚙️ Under the Hood: Data Sources

This script doesn't "guess" data. It features a split Dual-Polling architecture that talks directly to the hardware using three distinct data sources:

1. **Win32 PInvoke (Absolute Real-Time):**
   * Uses native libraries like `kernel32.dll`, `pdh.dll` (Performance Data Helper), and `psapi.dll`.
   * **Why:** Allows reading CPU, RAM, and Kernel calls in milliseconds with zero delay or processing overhead.
2. **NVML API (Graphics Hardware):**
   * Uses `nvml.dll` (NVIDIA Management Library).
   * **Why:** Reads vital GPU info directly at the driver level, bypassing Windows limitations.
3. **WMI / CIM (Identity & Protection):**
   * Uses native PowerShell commands (`Get-CimInstance`).
   * **Why:** Used only at startup to read the PC's "Physical Identity" (Serials, BIOS, Motherboard). It is restricted to a hard lock of `>= 1000ms` when reading Motherboard thermal sensors to prevent physical I2C bus overloads.

---

## 📊 Extracted Data (Telemetry)

The monitor extracts dozens of metrics divided into 3 main pillars:

### 1. CPU, Kernel & Motherboard
* **Basics:** Load (%), Frequency (Base and Turbo clocks), Power state status.
* **Topology:** Physical/Logical Core count, Cache distribution (L1/L2/L3), Architecture.
* **Kernel Pulse:** Memory Hard Faults, System Calls (SysCalls/sec), User Mode vs Kernel Mode Time, DPC (Deferred Procedure Calls), and Interrupts.
* **ACPI Sensors:** Real-time temperatures of physical motherboard sensors.

### 2. RAM Memory
* **Real Usage:** Used, Free, Total RAM, Hardware Reserved, and Precision Load.
* **Paging:** Windows Pagefile usage.
* **Identity (DNA):** BIOS configured profile (Speed and Voltage), Serial Numbers, Manufacturer, and Stick Location (Slots).
* **System Pools:** System Cache, Paged Pool, Non-Paged Pool, and Commit Peaks.

### 3. NVIDIA Graphics Card (GPU)
* **Performance:** Chip Load (%), Core Clock, Memory Clock, Power Draw (W) vs Power Limit.
* **PCIe Communication:** Link Generation and Width (e.g., Gen4 x16) and Bandwidth Traffic (TX/RX in MB/s).
* **VRAM & BAR:** Video Memory usage and BAR1 Memory (Resizable BAR) exposure to the CPU.
* **Health:** Die Temperature, Fan Speeds, and Thermal/Power Throttle Reasons.

---

## 🛡️ Privacy Engine (Streamer Mode)

If you need to share your screen on Discord, Reddit, or live streams, exposing physical serial numbers (Hardware HWIDs) is a security risk. The dashboard includes a built-in privacy engine.

You can configure the "SETTINGS" tab to:
* **Level 0 (Disabled):** Shows all data.
* **Level 1 (Standard):** Hides all physical Serials for the CPU, Motherboard, GPU, and RAM sticks with a `[ CONFIDENTIAL ]` tag.
* **Level 2 (Maximum):** Hides physical serials plus OS, Microcode, and BIOS versions to prevent system vulnerability reconnaissance.

Your speed setting (Refresh Rate) and privacy level are automatically saved in a `Config.ini` file located in the same folder as the script.

---

## 🚀 How to Run

1. Download the `Native-Hardware-Monitor.ps1` file.
2. Right-click the file and choose **"Run with PowerShell"**.
3. *(Optional but Recommended)* To read Motherboard temperatures (ACPI) and TPM security chip data, run the script as Administrator. Without Admin privileges, the script will still work perfectly, but these two metrics will display `N/A`.
