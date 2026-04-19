<#
    NATIVE HARDWARE MONITOR
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# =========================================================================================
# 0. CONFIG FILE INITIALIZATION (Persistência)
# =========================================================================================
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$configFile = Join-Path -Path $scriptDir -ChildPath "Config.ini"
$defaultRate = 100
$defaultPriv = 0

if (Test-Path $configFile) {
    $fileContent = Get-Content $configFile -Raw
    if ($fileContent -match "RefreshRate=(\d+)") {
        $parsedRate = [int]$matches[1]
        if ($parsedRate -ge 1 -and $parsedRate -le 99999) { $defaultRate = $parsedRate }
    }
    if ($fileContent -match "PrivacyLevel=(\d)") {
        $parsedPriv = [int]$matches[1]
        if ($parsedPriv -ge 0 -and $parsedPriv -le 2) { $defaultPriv = $parsedPriv }
    }
} else {
    Set-Content -Path $configFile -Value "RefreshRate=$defaultRate`nPrivacyLevel=$defaultPriv"
}

# =========================================================================================
# 1. SHARED MEMORY & GLOBAL CONFIG
# =========================================================================================
$syncHash = [hashtable]::Synchronized(@{})
$syncHash.Run = $true
$syncHash.StartTrigger = $false

$syncHash.RefreshRate = $defaultRate
$syncHash.PrivacyLevel = $defaultPriv

$syncHash.System_CIM_Text = "Loading System Data (WMI)..."
$syncHash.System_TPM_Text = "Loading TPM Security Data..."
$syncHash.System_TPM_Color = "Gray"
$syncHash.RAM_DNA_Text = "Loading Memory DNA..."
$syncHash.RAM_WMI_Live = ""
$syncHash.GPU_DNA_Text = "Loading Driver Identity..."
$syncHash.CPU_DNA_Text = "Loading CPU Architecture..."

# =========================================================================================
# 2. WORKER THREAD (Assíncrona - Operação Independente)
# =========================================================================================
$workerScript = {
    param($sync)

    $engineSource = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Text;
using System.Collections.Generic;

public class UltimateEngine {

    [StructLayout(LayoutKind.Sequential)] public struct MEMORYSTATUSEX {
        public uint dwLength; public uint dwMemoryLoad; public ulong ullTotalPhys; public ulong ullAvailPhys;
        public ulong ullTotalPageFile; public ulong ullAvailPageFile; public ulong ullTotalVirtual;
        public ulong ullAvailVirtual; public ulong ullAvailExtendedVirtual;
    }
    [DllImport("kernel32.dll", EntryPoint="GlobalMemoryStatusEx")] public static extern bool GetMemStruct(ref MEMORYSTATUSEX lpBuffer);

    [DllImport("pdh.dll", CharSet = CharSet.Unicode)] public static extern uint PdhOpenQuery(IntPtr dataSource, IntPtr userData, out IntPtr query);
    [DllImport("pdh.dll", CharSet = CharSet.Unicode)] public static extern uint PdhAddEnglishCounter(IntPtr query, string counterPath, IntPtr userData, out IntPtr counter);
    [DllImport("pdh.dll")] public static extern uint PdhCollectQueryData(IntPtr query);
    [DllImport("pdh.dll")] public static extern uint PdhGetFormattedCounterValue(IntPtr counter, uint format, out uint type, out PDH_FMT_COUNTERVALUE value);
    
    // Correção de Memory Leak (Unmanaged Code)
    [DllImport("pdh.dll")] public static extern uint PdhCloseQuery(IntPtr query);
    [DllImport("nvml.dll")] public static extern int nvmlShutdown();

    [StructLayout(LayoutKind.Explicit)] public struct PDH_FMT_COUNTERVALUE { [FieldOffset(0)] public uint CStatus; [FieldOffset(8)] public double doubleValue; }
    
    private static IntPtr hQueryCpu = IntPtr.Zero, hCounterCpu = IntPtr.Zero, hCounterPerf = IntPtr.Zero;
    private static IntPtr hQueryHf = IntPtr.Zero, hCounterHf = IntPtr.Zero;
    private static IntPtr hCounterQueue = IntPtr.Zero, hCounterTemp = IntPtr.Zero;
    private static IntPtr hCounterPageFile = IntPtr.Zero;
    
    private static IntPtr hCounterSysCalls = IntPtr.Zero;
    private static IntPtr hCounterPriv = IntPtr.Zero;
    private static IntPtr hCounterUser = IntPtr.Zero;
    private static IntPtr hCounterDpc = IntPtr.Zero;
    private static IntPtr hCounterInt = IntPtr.Zero;
    private static IntPtr hCounterMod = IntPtr.Zero;

    private static IntPtr[] hCounterCores;
    private static int coreCount;

    [StructLayout(LayoutKind.Sequential)] public struct PERFORMANCE_INFORMATION {
        public int cb; public UIntPtr CommitTotal; public UIntPtr CommitLimit; public UIntPtr CommitPeak;
        public UIntPtr PhysicalTotal; public UIntPtr PhysicalAvailable; public UIntPtr SystemCache;
        public UIntPtr KernelTotal; public UIntPtr KernelPaged; public UIntPtr KernelNonpaged;
        public UIntPtr PageSize; public uint HandleCount; public uint ProcessCount; public uint ThreadCount;
    }
    [DllImport("psapi.dll")] public static extern bool GetPerformanceInfo(ref PERFORMANCE_INFORMATION pPerformanceInformation, int cb);

    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetLogicalProcessorInformation(IntPtr buffer, ref uint returnLength);
    [DllImport("user32.dll")] public static extern bool EnumDisplayDevices(string lpDevice, uint iDevNum, ref DISPLAY_DEVICE lpDisplayDevice, uint dwFlags);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)] public struct DISPLAY_DEVICE {
        public int cb; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DeviceName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceString;
        public int StateFlags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceID;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceKey;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] public static extern int RegOpenKeyEx(IntPtr hKey, string subKey, int ulOptions, int samDesired, out IntPtr phkResult);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint="RegQueryValueExW")] public static extern int RegQueryValueExDword(IntPtr hKey, string lpValueName, int lpReserved, out uint lpType, ref uint lpData, ref uint lpcbData);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint="RegQueryValueExW")] public static extern int RegQueryValueExBinary(IntPtr hKey, string lpValueName, int lpReserved, out uint lpType, byte[] lpData, ref uint lpcbData);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] public static extern int RegQueryValueEx(IntPtr hKey, string lpValueName, int lpReserved, out uint lpType, StringBuilder lpData, ref uint lpcbData);
    [DllImport("advapi32.dll")] public static extern int RegCloseKey(IntPtr hKey);

    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool GetPhysicallyInstalledSystemMemory(out ulong TotalMemoryInKilobytes);

    [DllImport("kernel32.dll")] public static extern bool GetNumaHighestNodeNumber(out uint HighestNodeNumber);
    [DllImport("kernel32.dll")] public static extern UIntPtr GetLargePageMinimum();

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO {
        public ushort wProcessorArchitecture; public ushort wReserved; public uint dwPageSize;
        public IntPtr lpMinimumApplicationAddress; public IntPtr lpMaximumApplicationAddress;
        public IntPtr dwActiveProcessorMask; public uint dwNumberOfProcessors; public uint dwProcessorType;
        public uint dwAllocationGranularity; public ushort wProcessorLevel; public ushort wProcessorRevision;
    }
    [DllImport("kernel32.dll")] public static extern void GetNativeSystemInfo(out SYSTEM_INFO lpSystemInfo);

    public static string GetRegString(string key, string val) {
        IntPtr hklm = new IntPtr(unchecked((int)0x80000002)); IntPtr hKey;
        if (RegOpenKeyEx(hklm, key, 0, 0x20019, out hKey) == 0) {
            uint type; uint size = 1024; StringBuilder data = new StringBuilder((int)size);
            if (RegQueryValueEx(hKey, val, 0, out type, data, ref size) == 0) { 
                RegCloseKey(hKey); return data.ToString(); 
            }
            RegCloseKey(hKey);
        }
        return "N/A";
    }

    public static ulong GetBiosRamMB() {
        ulong kb = 0;
        if (GetPhysicallyInstalledSystemMemory(out kb)) { return kb / 1024; }
        return 0;
    }

    public static uint GetBaseClock() {
        IntPtr hklm = new IntPtr(unchecked((int)0x80000002)); IntPtr hKey;
        if (RegOpenKeyEx(hklm, @"HARDWARE\DESCRIPTION\System\CentralProcessor\0", 0, 0x20019, out hKey) == 0) {
            uint type; uint size = 4; uint data = 0;
            if (RegQueryValueExDword(hKey, "~MHz", 0, out type, ref data, ref size) == 0) { RegCloseKey(hKey); return data; }
            RegCloseKey(hKey);
        }
        return 0;
    }

    [DllImport("nvml.dll")] public static extern int nvmlInit_v2();
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetHandleByIndex_v2(uint index, out IntPtr device);
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetUtilizationRates(IntPtr device, out nvmlUtilization_t utilization);
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetMemoryInfo(IntPtr device, out nvmlMemory_t memory);
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetTemperature(IntPtr device, int sensorType, out uint temp);
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetClockInfo(IntPtr device, int type, out uint clock);
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetPowerUsage(IntPtr device, out uint power);
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetUUID(IntPtr device, StringBuilder uuid, uint length);
    [DllImport("nvml.dll")] public static extern int nvmlSystemGetDriverVersion(StringBuilder version, uint length);
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetVbiosVersion(IntPtr device, StringBuilder version, uint length);
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetPowerManagementLimit(IntPtr device, out uint limit);
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetFanSpeed(IntPtr device, out uint speed);
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetCurrPcieLinkGeneration(IntPtr device, out uint gen);
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetCurrPcieLinkWidth(IntPtr device, out uint width);
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetPcieThroughput(IntPtr device, int counter, out uint throughput);
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetCurrentClocksEventReasons(IntPtr device, out ulong reasons);
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetPerformanceState(IntPtr device, out int pState);
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetArchitecture(IntPtr device, out uint arch); 
    
    [StructLayout(LayoutKind.Sequential)] public struct nvmlUtilization_t { public uint gpu; public uint memory; }
    [StructLayout(LayoutKind.Sequential)] public struct nvmlMemory_t { public ulong total; public ulong free; public ulong used; }
    [StructLayout(LayoutKind.Sequential)] public struct nvmlBAR1Memory_t { public ulong bar1Total; public ulong bar1Free; public ulong bar1Used; }
    [DllImport("nvml.dll")] public static extern int nvmlDeviceGetBAR1MemoryInfo(IntPtr device, ref nvmlBAR1Memory_t bar1Memory);

    private static IntPtr nvmlDevice = IntPtr.Zero;
    private static bool nvmlReady = false;
    
    private static string gpuUuid = null;
    private static string gpuDriver = null;
    private static string gpuVbios = null;
    private static string gpuArchStr = null;

    public static string GetThrottleReasons(IntPtr device) {
        ulong reasons;
        if (nvmlDeviceGetCurrentClocksEventReasons(device, out reasons) == 0) {
            if (reasons == 0x0000000000000000UL) return "Active (Unthrottled)";
            List<string> list = new List<string>();
            if ((reasons & 0x0000000000000001UL) != 0) list.Add("Idle");
            if ((reasons & 0x0000000000000004UL) != 0) list.Add("Power Cap");
            if ((reasons & 0x0000000000000008UL) != 0) list.Add("Thermal (HW)");
            if ((reasons & 0x0000000000000020UL) != 0) list.Add("Thermal (SW)");
            if ((reasons & 0x0000000000000100UL) != 0) list.Add("Display Limit");
            if ((reasons & 0x0000000000000200UL) != 0) list.Add("Volt Limit");
            if (list.Count > 0) return string.Join(", ", list);
            return "Unknown (" + reasons + ")";
        }
        return "N/A";
    }

    public static string InitAll(int cores) {
        try {
            PdhOpenQuery(IntPtr.Zero, IntPtr.Zero, out hQueryCpu);
            PdhAddEnglishCounter(hQueryCpu, "\\Processor Information(_Total)\\% Processor Utility", IntPtr.Zero, out hCounterCpu);
            PdhAddEnglishCounter(hQueryCpu, "\\Processor Information(_Total)\\% Processor Performance", IntPtr.Zero, out hCounterPerf);
            PdhAddEnglishCounter(hQueryCpu, "\\System\\Processor Queue Length", IntPtr.Zero, out hCounterQueue);
            PdhAddEnglishCounter(hQueryCpu, "\\Thermal Zone Information(*)\\Temperature", IntPtr.Zero, out hCounterTemp);
            PdhOpenQuery(IntPtr.Zero, IntPtr.Zero, out hQueryHf);
            PdhAddEnglishCounter(hQueryHf, "\\Memory\\Pages/sec", IntPtr.Zero, out hCounterHf);
            
            PdhAddEnglishCounter(hQueryCpu, "\\Paging File(_Total)\\% Usage", IntPtr.Zero, out hCounterPageFile);
            
            PdhAddEnglishCounter(hQueryCpu, "\\System\\System Calls/sec", IntPtr.Zero, out hCounterSysCalls);
            PdhAddEnglishCounter(hQueryCpu, "\\Processor Information(_Total)\\% Privileged Time", IntPtr.Zero, out hCounterPriv);
            PdhAddEnglishCounter(hQueryCpu, "\\Processor Information(_Total)\\% User Time", IntPtr.Zero, out hCounterUser);
            PdhAddEnglishCounter(hQueryCpu, "\\Processor Information(_Total)\\% DPC Time", IntPtr.Zero, out hCounterDpc);
            PdhAddEnglishCounter(hQueryCpu, "\\Processor Information(_Total)\\% Interrupt Time", IntPtr.Zero, out hCounterInt);
            PdhAddEnglishCounter(hQueryCpu, "\\Memory\\Modified Page List Bytes", IntPtr.Zero, out hCounterMod);

            coreCount = cores;
            hCounterCores = new IntPtr[cores];
            for (int i = 0; i < cores; i++) {
                PdhAddEnglishCounter(hQueryCpu, "\\Processor(" + i + ")\\% Processor Time", IntPtr.Zero, out hCounterCores[i]);
            }
            
            PdhCollectQueryData(hQueryCpu); PdhCollectQueryData(hQueryHf);

            try { if (nvmlInit_v2() == 0 && nvmlDeviceGetHandleByIndex_v2(0, out nvmlDevice) == 0) nvmlReady = true; } catch {}
            return "READY";
        } catch (Exception ex) { return "ERROR: " + ex.Message; }
    }

    // Função que encerra os Handles não-gerenciados do Windows
    public static void CloseAll() {
        if (hQueryCpu != IntPtr.Zero) { PdhCloseQuery(hQueryCpu); hQueryCpu = IntPtr.Zero; }
        if (hQueryHf != IntPtr.Zero) { PdhCloseQuery(hQueryHf); hQueryHf = IntPtr.Zero; }
        if (nvmlReady) { try { nvmlShutdown(); } catch {} }
    }

    public static string GetCpuName() {
        try { return (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString", "Unknown"); }
        catch { return "Unknown"; }
    }

    public static string GetGpuName() {
        try {
            DISPLAY_DEVICE d = new DISPLAY_DEVICE(); d.cb = Marshal.SizeOf(d);
            EnumDisplayDevices(null, 0, ref d, 0);
            return d.DeviceString;
        } catch { return "Unknown"; }
    }

    public static string FormatCache(int bytes) {
        int kb = bytes / 1024;
        if (kb >= 1024) {
            if (kb % 1024 == 0) {
                return kb + " KB (" + (kb / 1024) + " MB)";
            } else {
                return kb + " KB (" + Math.Round(kb / 1024.0, 1).ToString().Replace(",", ".") + " MB)";
            }
        }
        return kb + " KB";
    }

    public static string GetCoreTopology() {
        uint len = 0; GetLogicalProcessorInformation(IntPtr.Zero, ref len);
        if (len == 0) return "N/A;N/A";
        IntPtr ptr = Marshal.AllocHGlobal((int)len);
        try {
            if (GetLogicalProcessorInformation(ptr, ref len)) {
                int l1 = 0; int l2 = 0; int l3 = 0; int physCores = 0; 
                int structSize = Marshal.SizeOf(typeof(IntPtr)) == 8 ? 32 : 24; 
                int cacheOffset = Marshal.SizeOf(typeof(IntPtr)) == 8 ? 16 : 12;

                int count = (int)len / structSize; IntPtr current = ptr;
                for (int i = 0; i < count; i++) {
                    int relationship = Marshal.ReadInt32(current, Marshal.SizeOf(typeof(IntPtr))); 
                    if (relationship == 0) physCores++; 
                    if (relationship == 2) { 
                        IntPtr cachePtr = IntPtr.Add(current, cacheOffset);
                        byte level = Marshal.ReadByte(cachePtr, 0);
                        int size = Marshal.ReadInt32(cachePtr, 4);
                        if (level == 1) l1 += size;
                        if (level == 2) l2 += size;
                        if (level == 3) l3 += size;
                    }
                    current = IntPtr.Add(current, structSize);
                }
                
                string cacheLines = "L1 Cache        : " + FormatCache(l1) + "\nL2 Cache        : " + FormatCache(l2) + "\nL3 Cache        : " + FormatCache(l3);
                return string.Format("{0} Cores / {1} Threads;{2}", physCores, Environment.ProcessorCount, cacheLines);
            }
            return "N/A;N/A";
        } finally { Marshal.FreeHGlobal(ptr); }
    }

    public static string GetMicrocodeRev() {
        IntPtr hklm = new IntPtr(unchecked((int)0x80000002)); IntPtr hKey;
        if (RegOpenKeyEx(hklm, @"HARDWARE\DESCRIPTION\System\CentralProcessor\0", 0, 0x20019, out hKey) == 0) {
            uint type; uint size = 8; byte[] data = new byte[size];
            if (RegQueryValueExBinary(hKey, "Update Revision", 0, out type, data, ref size) == 0) { 
                RegCloseKey(hKey);
                try {
                    uint low = BitConverter.ToUInt32(data, 0);
                    uint high = BitConverter.ToUInt32(data, 4);
                    if (high != 0 && low == 0) return high.ToString("X");
                    if (low != 0 && high == 0) return low.ToString("X");
                    if (high == 0 && low == 0) return "0";
                    return high.ToString("X") + low.ToString("X8");
                } catch { return "Error"; }
            }
            RegCloseKey(hKey);
        }
        return "N/A";
    }

    public static string GetSystemInfoStr() {
        SYSTEM_INFO sysInfo; GetNativeSystemInfo(out sysInfo);
        string arq = sysInfo.wProcessorArchitecture == 9 ? "AMD64(x64)" : (sysInfo.wProcessorArchitecture == 12 ? "ARM64" : (sysInfo.wProcessorArchitecture == 0 ? "x86" : "Unknown"));
        return string.Format("Architecture    : {0}\nCPU Level       : {1}\nCPU Revision    : {2}\nPage Size       : {3} Bytes", arq, sysInfo.wProcessorLevel, sysInfo.wProcessorRevision, sysInfo.dwPageSize);
    }

    public static string GetKernelHardwareData(int privacy) {
        string uRev = (privacy == 2) ? "[ CONFIDENTIAL ]" : GetMicrocodeRev();
        uint numaNode = 0; GetNumaHighestNodeNumber(out numaNode);
        uint numaCount = numaNode + 1;
        UIntPtr largePageBytes = GetLargePageMinimum();
        string largePageMB = (ulong)largePageBytes > 0 ? Math.Round((ulong)largePageBytes / 1048576.0, 1) + " MB" : "Unsupported";
        string sysInfoStr = GetSystemInfoStr(); 
        return string.Format("Microcode Rev   : {0}\nNUMA Nodes      : {1}\nLarge Pages     : {2}\n{3}", uRev, numaCount, largePageMB, sysInfoStr);
    }

    public static double GetPageFileUsage() {
        uint type; PDH_FMT_COUNTERVALUE val;
        if (PdhGetFormattedCounterValue(hCounterPageFile, 0x200, out type, out val) == 0) return val.doubleValue;
        return 0;
    }

    public static string GetKernelPulseData() {
        uint type; PDH_FMT_COUNTERVALUE val;
        
        PdhGetFormattedCounterValue(hCounterSysCalls, 0x200, out type, out val); double sysCalls = val.doubleValue;
        PdhGetFormattedCounterValue(hCounterUser, 0x200, out type, out val); double user = val.doubleValue;
        PdhGetFormattedCounterValue(hCounterPriv, 0x200, out type, out val); double priv = val.doubleValue;
        PdhGetFormattedCounterValue(hCounterDpc, 0x200, out type, out val); double dpc = val.doubleValue;
        PdhGetFormattedCounterValue(hCounterInt, 0x200, out type, out val); double inter = val.doubleValue;
        PdhGetFormattedCounterValue(hCounterMod, 0x200, out type, out val); double mod = val.doubleValue;

        return Math.Round(sysCalls, 0) + ";" + 
               Math.Round(user, 1).ToString("0.0").Replace(",",".") + ";" + 
               Math.Round(priv, 1).ToString("0.0").Replace(",",".") + ";" + 
               Math.Round(dpc, 2).ToString("0.00").Replace(",",".") + ";" + 
               Math.Round(inter, 2).ToString("0.00").Replace(",",".") + ";" + 
               Math.Round(mod / 1048576.0, 0); 
    }

    public static string GetSmtCoresData() {
        if (coreCount <= 0) return "";
        string smtStr = "--- CORE LOADS ---\n";
        uint type; PDH_FMT_COUNTERVALUE val;
        
        if (coreCount % 2 == 0) {
            int physCore = 0;
            for (int i = 0; i < coreCount; i += 2) {
                PdhGetFormattedCounterValue(hCounterCores[i], 0x200, out type, out val);
                double t0 = val.doubleValue;
                
                PdhGetFormattedCounterValue(hCounterCores[i + 1], 0x200, out type, out val);
                double t1 = val.doubleValue;
                
                double cLoad = (t0 + t1) / 2.0;
                smtStr += string.Format("Core {0:00}: {1,6:0.0} %  [T{2,-2}: {3,5:0.0} % | T{4,-2}: {5,5:0.0} %]\n", physCore, cLoad, i, t0, (i + 1), t1);
                physCore++;
            }
        } else {
            for (int i = 0; i < coreCount; i++) {
                PdhGetFormattedCounterValue(hCounterCores[i], 0x200, out type, out val);
                smtStr += string.Format("Core {0:00}: {1,6:0.0} %\n", i, val.doubleValue);
            }
        }
        return smtStr;
    }

    public static string GetCpuSystemData() {
        uint type; PDH_FMT_COUNTERVALUE valCpu, valPerf, valHf, valQueue, valTemp;
        PdhCollectQueryData(hQueryCpu); PdhCollectQueryData(hQueryHf);
        PdhGetFormattedCounterValue(hCounterCpu, 0x200, out type, out valCpu);
        PdhGetFormattedCounterValue(hCounterPerf, 0x200, out type, out valPerf);
        PdhGetFormattedCounterValue(hCounterHf, 0x200, out type, out valHf);
        PdhGetFormattedCounterValue(hCounterQueue, 0x200, out type, out valQueue);
        PdhGetFormattedCounterValue(hCounterTemp, 0x200, out type, out valTemp);
        
        PERFORMANCE_INFORMATION pi = new PERFORMANCE_INFORMATION(); 
        pi.cb = Marshal.SizeOf(typeof(PERFORMANCE_INFORMATION));
        GetPerformanceInfo(ref pi, pi.cb);
        
        string coresStr = GetSmtCoresData();
        
        ulong commitTotMB = ((ulong)pi.CommitTotal * (ulong)pi.PageSize) >> 20;
        ulong commitLimMB = ((ulong)pi.CommitLimit * (ulong)pi.PageSize) >> 20;
        
        double rawTemp = valTemp.doubleValue;
        string sysTempStr = "N/A";
        if (rawTemp > 1000) { sysTempStr = ((rawTemp / 10.0) - 273.15).ToString("0.0").Replace(",", "."); }
        else if (rawTemp > 0) { sysTempStr = (rawTemp - 273.15).ToString("0.0").Replace(",", "."); }
        
        return valCpu.doubleValue.ToString("0.0").Replace(",",".") + ";" + 
               valHf.doubleValue.ToString("0").Replace(",",".") + ";" + 
               pi.ProcessCount + ";" + 
               pi.ThreadCount + ";" + 
               commitTotMB + ";" + 
               commitLimMB + ";" + 
               valPerf.doubleValue.ToString("0.0").Replace(",",".") + ";" + 
               valQueue.doubleValue.ToString("0").Replace(",",".") + ";" + 
               sysTempStr + ";" + 
               pi.HandleCount + ";" + 
               pi.PageSize + ";" + 
               (((ulong)pi.SystemCache * (ulong)pi.PageSize) >> 20) + ";" + 
               (((ulong)pi.KernelTotal * (ulong)pi.PageSize) >> 20) + ";" + 
               (((ulong)pi.KernelPaged * (ulong)pi.PageSize) >> 20) + ";" + 
               (((ulong)pi.KernelNonpaged * (ulong)pi.PageSize) >> 20) + ";" + 
               (((ulong)pi.CommitPeak * (ulong)pi.PageSize) >> 20) + ";" + 
               coresStr;
    }

    public static string GetRamData() {
        MEMORYSTATUSEX mem = new MEMORYSTATUSEX(); mem.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
        GetMemStruct(ref mem);
        ulong osTotalMB = mem.ullTotalPhys >> 20;
        ulong usedMB = (mem.ullTotalPhys - mem.ullAvailPhys) >> 20;
        ulong freeMB = mem.ullAvailPhys >> 20;
        double precLoad = ((double)usedMB / osTotalMB) * 100.0;
        ulong pfTotal = mem.ullTotalPageFile >> 20;
        ulong pfAvail = mem.ullAvailPageFile >> 20;
        ulong pfUsed = pfTotal - pfAvail;
        return mem.dwMemoryLoad + ";" + precLoad.ToString("0.00").Replace(",",".") + ";" + osTotalMB + ";" + usedMB + ";" + freeMB + ";" + pfTotal + ";" + pfUsed;
    }

    public static string GetGpuData(int privacy) {
        if (!nvmlReady) return "N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A;N/A";
        
        if (gpuUuid == null) {
            StringBuilder sb = new StringBuilder(128);
            if (nvmlDeviceGetUUID(nvmlDevice, sb, 128) == 0) gpuUuid = sb.ToString(); else gpuUuid = "N/A";
            sb.Clear();
            if (nvmlSystemGetDriverVersion(sb, 128) == 0) gpuDriver = sb.ToString(); else gpuDriver = "N/A";
            sb.Clear();
            if (nvmlDeviceGetVbiosVersion(nvmlDevice, sb, 128) == 0) gpuVbios = sb.ToString(); else gpuVbios = "N/A";
            
            try {
                uint arch = 0;
                if (nvmlDeviceGetArchitecture(nvmlDevice, out arch) == 0) {
                    switch (arch) {
                        case 2: gpuArchStr = "Kepler"; break;
                        case 3: gpuArchStr = "Maxwell"; break;
                        case 4: gpuArchStr = "Pascal"; break;
                        case 5: gpuArchStr = "Volta"; break;
                        case 6: gpuArchStr = "Turing"; break;
                        case 7: gpuArchStr = "Ampere"; break;
                        case 8: gpuArchStr = "Ada Lovelace"; break;
                        case 9: gpuArchStr = "Hopper"; break;
                        case 10: gpuArchStr = "Blackwell"; break;
                        default: gpuArchStr = "Unknown (" + arch + ")"; break;
                    }
                } else { gpuArchStr = "N/A"; }
            } catch { gpuArchStr = "N/A (Update Driver)"; }
        }

        nvmlUtilization_t ut = new nvmlUtilization_t();
        nvmlMemory_t mi = new nvmlMemory_t();
        uint temp = 0; uint gClk = 0; uint mClk = 0; uint powerMw = 0;
        
        nvmlDeviceGetUtilizationRates(nvmlDevice, out ut);
        nvmlDeviceGetMemoryInfo(nvmlDevice, out mi);
        nvmlDeviceGetTemperature(nvmlDevice, 0, out temp);
        nvmlDeviceGetClockInfo(nvmlDevice, 1, out gClk);
        nvmlDeviceGetClockInfo(nvmlDevice, 2, out mClk);
        nvmlDeviceGetPowerUsage(nvmlDevice, out powerMw);
        
        int pState = 0; nvmlDeviceGetPerformanceState(nvmlDevice, out pState);
        uint limitMw = 0; nvmlDeviceGetPowerManagementLimit(nvmlDevice, out limitMw);
        uint pcieGen = 0; nvmlDeviceGetCurrPcieLinkGeneration(nvmlDevice, out pcieGen);
        uint pcieWdt = 0; nvmlDeviceGetCurrPcieLinkWidth(nvmlDevice, out pcieWdt);
        uint txKb = 0; nvmlDeviceGetPcieThroughput(nvmlDevice, 0, out txKb);
        uint rxKb = 0; nvmlDeviceGetPcieThroughput(nvmlDevice, 1, out rxKb);
        uint fan = 0; int fanStatus = nvmlDeviceGetFanSpeed(nvmlDevice, out fan);
        
        nvmlBAR1Memory_t bar1 = new nvmlBAR1Memory_t();
        nvmlDeviceGetBAR1MemoryInfo(nvmlDevice, ref bar1);
        
        string throttle = GetThrottleReasons(nvmlDevice);
        
        ulong vTotal = mi.total >> 20; ulong vUsed = mi.used >> 20; ulong vFree = mi.free >> 20;
        double vLoad = vTotal > 0 ? ((double)vUsed / vTotal) * 100.0 : 0;
        double powerW = powerMw / 1000.0; double limitW = limitMw / 1000.0;
        double txMb = txKb / 1024.0; double rxMb = rxKb / 1024.0;
        ulong bTot = bar1.bar1Total >> 20; ulong bUsed = bar1.bar1Used >> 20;
        
        string fanStr = fanStatus == 0 ? fan.ToString() + " %" : "N/A";
        
        string displayUuid = (privacy >= 1) ? "[ CONFIDENTIAL ]" : gpuUuid;

        return string.Format("{0};{1};{2};{3};{4};{5};{6};{7:0.0};{8:0};{9};{10};{11};{12:0.0};{13};{14};{15};{16};{17};{18:0.0};{19:0.0};{20};{21};{22}",
            displayUuid, gpuDriver, gpuVbios, ut.gpu, gClk, mClk, pState, powerW, limitW, throttle, pcieGen, pcieWdt,
            vLoad, vTotal, vUsed, vFree, bTot, bUsed, txMb, rxMb, temp, fanStr, gpuArchStr).Replace(",",".");
    }
}
"@
    Add-Type -TypeDefinition $engineSource -Language CSharp
    
    # =========================================================================================
    # FASE 1: IGNIÇÃO ESTÁTICA - CAPTURA DE DADOS BRUTOS (WMI/CIM)
    # =========================================================================================
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $sync.IsAdmin = $isAdmin

    # OS Data
    $rawOsName = "N/A"; $rawOsBuild = "N/A"
    $osCim = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($osCim) {
        $rawOsName = $osCim.Caption -replace "Microsoft ", ""
        $rawOsBuild = $osCim.BuildNumber
        if ([int]$rawOsBuild -ge 22000 -and $rawOsName -match "Windows 10") { $rawOsName = ($rawOsName -replace "Windows 10", "Windows 11") + " (Fixed)" }
    }

    # Motherboard Data
    $rawMoboMfg = "N/A"; $rawMoboMod = "N/A"; $rawMoboVer = "N/A"; $rawMoboSer = "N/A"
    $board = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
    if ($board) {
        $rawMoboMfg = $board.Manufacturer; $rawMoboMod = $board.Product; $rawMoboVer = $board.Version; $rawMoboSer = $board.SerialNumber
    }

    # BIOS Data
    $rawBiosMfg = "N/A"; $rawBiosVer = "N/A"; $rawBiosCore = "N/A"; $rawBiosDate = "N/A"; $rawBiosLang = "N/A"; $rawBiosSer = "N/A"
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
    if ($bios) {
        $rawBiosMfg = $bios.Manufacturer; $rawBiosVer = $bios.SMBIOSBIOSVersion
        $rawBiosCore = "v$($bios.SMBIOSMajorVersion).$($bios.SMBIOSMinorVersion)"
        $rawBiosDate = [UltimateEngine]::GetRegString("HARDWARE\DESCRIPTION\System\BIOS", "BIOSReleaseDate")
        if ($rawBiosDate -match "^(\d{2})/(\d{2})/(\d{4})$") { $rawBiosDate = "$($matches[2])/$($matches[1])/$($matches[3])" }
        $rawBiosLang = if ($bios.CurrentLanguage) { $bios.CurrentLanguage } else { "N/A" }
        $rawBiosSer = $bios.SerialNumber
    }

    # Security Data
    $rawSbCim = "Unsupported (Legacy)"
    try {
        $cimReg = Invoke-CimMethod -Namespace root/default -ClassName StdRegProv -MethodName GetDWORDValue -Arguments @{hDefKey=[uint32]2147483650; sSubKeyName="SYSTEM\CurrentControlSet\Control\SecureBoot\State"; sValueName="UEFISecureBootEnabled"} -ErrorAction SilentlyContinue
        if ($cimReg.ReturnValue -eq 0) { $rawSbCim = if ($cimReg.uValue -eq 1) { "Enabled" } else { "Disabled" } }
    } catch {}

    # TPM
    if (-not $isAdmin) {
        $sync.System_TPM_Text = "TPM Module      : N/A (Admin Required)"; $sync.System_TPM_Color = "Red"
    } else {
        $tpm = Get-CimInstance -Namespace "Root\CIMV2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
        if ($tpm) {
            $fabID = switch ($tpm.ManufacturerId) {
                1229870147 { "$_ (INTC - Intel)" }; 1095582752 { "$_ (AMD - Adv Micro Devices)" }; 1229346816 { "$_ (IFX - Infineon)" }; 1314145024 { "$_ (NTC - Nuvoton)" }
                1398033696 { "$_ (STM - STMicroelectronics)" }; 1129467731 { "$_ (ATML - Atmel)" }; 1464156928 { "$_ (WEC - Winbond)" }; default { $_ }
            }
            $sync.System_TPM_Text = "TPM Module      : Present`nTPM Specificat. : $($tpm.SpecVersion)`nManufacturer    : $fabID`nManufact. Vers. : $($tpm.ManufacturerVersion)"
            $sync.System_TPM_Color = "White"
        } else {
            $sync.System_TPM_Text = "TPM Module      : Not Found / Unsupported"; $sync.System_TPM_Color = "White"
        }
    }

    # RAM DNA Raw Struct
    $ramSticks = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue)
    $rawRamGroups = @()
    $groupedRams = $ramSticks | Group-Object -Property { "$($_.PartNumber.Trim())|$($_.Capacity)|$($_.Speed)|$($_.Manufacturer)" }
    $groupIndex = 1
    $primaryRamName = "Unknown Memory Module"
    foreach ($group in $groupedRams) {
        $qtd = $group.Count; $sticks = $group.Group; $stickBase = $sticks[0]
        if ($groupIndex -eq 1) { $primaryRamName = if ([string]::IsNullOrWhiteSpace($stickBase.PartNumber)) { "Unknown" } else { $stickBase.PartNumber.Trim() } }
        $tipoMemoria = switch ($stickBase.SMBIOSMemoryType) { 20 { "DDR" }; 21 { "DDR2" }; 24 { "DDR3" }; 26 { "DDR4" }; 34 { "DDR5" }; default { "Unknown ($($stickBase.SMBIOSMemoryType))" } }
        $formato = switch ($stickBase.FormFactor) { 8 { "DIMM" }; 12 { "SODIMM" }; default { "Unknown ($($stickBase.FormFactor))" } }
        $capPorPenteGB = [math]::Round($stickBase.Capacity / 1073741824, 0); $capTotalGB = $capPorPenteGB * $qtd
        if ($null -ne $stickBase.ConfiguredVoltage) { $volts = "{0:N2} V" -f ($stickBase.ConfiguredVoltage / 1000.0); $volts = $volts.Replace(",", ".") } else { $volts = "N/A" }
        $velocidade = if ($null -ne $stickBase.Speed) { "$($stickBase.Speed) MHz" } else { "N/A" }
        
        $rawRamGroups += [PSCustomObject]@{
            GrpIdx = $groupIndex; Part = $stickBase.PartNumber.Trim(); Mfg = $stickBase.Manufacturer; Hw = "$tipoMemoria | $formato"
            Cap = "$capTotalGB GB (${qtd}x $capPorPenteGB GB)"; Sticks = $sticks; Speed = $velocidade; Volts = $volts
        }
        $groupIndex++
    }
    $sync.RAM_Name = $primaryRamName

    # GPU DNA Raw Struct
    $cimGpus = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)
    $rawGpuList = @()
    foreach ($gpu in $cimGpus) {
        $driverDateRaw = $gpu.DriverDate
        $dDate = if ($null -ne $driverDateRaw) { $driverDateRaw.ToString("dd/MM/yyyy") } else { "N/A" }
        $dStatus = switch ($gpu.Status) { "OK" { "OK (Working)" }; "Error" { "Error" }; "Degraded" { "Degraded" }; "Unknown" { "Unknown" }; "Pred Fail" { "Pred Fail" }; "Starting" { "Starting" }; "Stopping" { "Stopping" }; "Service" { "Service" }; default { if ($gpu.Status) { $gpu.Status } else { "N/A" } } }
        $hw = if ($gpu.PNPDeviceID) { $gpu.PNPDeviceID } else { "N/A" }
        $rawGpuList += [PSCustomObject]@{ Date = $dDate; Status = $dStatus; HWID = $hw }
    }

    # CPU DNA Raw Struct
    $cimCpus = @(Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue)
    $rawCpuList = @()
    foreach ($cpu in $cimCpus) {
        $arq = switch ($cpu.Architecture) { 0 { "x86 (32-bits)" }; 1 { "MIPS" }; 2 { "Alpha" }; 3 { "PowerPC" }; 5 { "ARM" }; 6 { "ia64 (Itanium)" }; 9 { "x64 (64-bits)" }; 12 { "ARM64" }; default { "Unknown ($($cpu.Architecture))" } }
        $status = switch ($cpu.Status) { "OK" { "OK (Working)" }; "Error" { "Error" }; "Degraded" { "Degraded" }; "Unknown" { "Unknown" }; default { if ($cpu.Status) { $cpu.Status } else { "N/A" } } }
        $virt = if ($cpu.VirtualizationFirmwareEnabled) { "Enabled (BIOS)" } else { "Disabled" }
        $rawCpuList += [PSCustomObject]@{ Mfg = $cpu.Manufacturer; Arch = $arq; Socket = $cpu.SocketDesignation; Virt = $virt; Status = $status; HWID = $cpu.ProcessorId }
    }

    # Inicialização PInvoke
    $sync.CPU_Name = [UltimateEngine]::GetCpuName()
    $sync.GPU_Name = [UltimateEngine]::GetGpuName()
    $topoParts = [UltimateEngine]::GetCoreTopology().Split(';')
    $sync.CPU_Topo = $topoParts[0]; $sync.CPU_Cache = $topoParts[1]
    $sync.CPU_BaseClock = [UltimateEngine]::GetBaseClock()
    $sync.RAM_BiosTotalMB = [UltimateEngine]::GetBiosRamMB()
    $coreCount = [Environment]::ProcessorCount
    $sync.Status = [UltimateEngine]::InitAll($coreCount)


    # =========================================================================================
    # FASE 2: MOTOR DE ALTA ROTAÇÃO (O LOOP PURO COM PRIVACY ENGINE)
    # =========================================================================================
    $sync.StartTrigger = $true
    
    while ($sync.Run) {
        $pLvl = $sync.PrivacyLevel

        # --- APLICAÇÃO DO FILTRO DE PRIVACIDADE NOS DADOS ESTÁTICOS ---
        
        # 1. OS & MOBO & BIOS
        $dOs = if ($pLvl -ge 2) { "[ CONFIDENTIAL ]" } else { "$rawOsName (Build $rawOsBuild)" }
        $dMoboSer = if ($pLvl -ge 1) { "[ CONFIDENTIAL ]" } else { $rawMoboSer }
        $dBiosVer = if ($pLvl -ge 2) { "[ CONFIDENTIAL ]" } else { $rawBiosVer }
        $dBiosSer = if ($pLvl -ge 1) { "[ CONFIDENTIAL ]" } else { $rawBiosSer }
        
        $sync.System_CIM_Text = "[ OPERATING SYSTEM ]`nOperating System: $dOs`n`n[ MOTHERBOARD ]`nManufacturer    : $rawMoboMfg`nModel           : $rawMoboMod`nVersion         : $rawMoboVer`nSerial          : $dMoboSer`n`n[ BIOS FIRMWARE ]`nManufacturer    : $rawBiosMfg`nVersion         : $dBiosVer`nCore SMBIOS     : $rawBiosCore`nBIOS Release Dt : $rawBiosDate`nLanguage        : $rawBiosLang`nSerial ROM      : $dBiosSer`n`n[ SECURITY ]`nSecure Boot     : $rawSbCim`n"

        # 2. RAM DNA
        $dnaOutput = ""; $liveOutput = ""
        foreach ($g in $rawRamGroups) {
            $dadosPorPente = ""
            foreach ($s in $g.Sticks) {
                $dSn = if ($pLvl -ge 1) { "[ CONFIDENTIAL ]" } else { $s.SerialNumber }
                $dadosPorPente += "$($s.DeviceLocator) ($($s.BankLabel))  [S/N: $dSn]`n"
            }
            $dnaOutput += "====== MODEL $($g.GrpIdx) ======`nModel (SKU)     : $($g.Part)`nManufacturer    : $($g.Mfg)`nHardware        : $($g.Hw)`nCapacity        : $($g.Cap)`nLocation        :`n$dadosPorPente`n"
            $liveOutput += "M$($g.GrpIdx) Clock  : $($g.Speed)`n"
        }
        $sync.RAM_DNA_Text = $dnaOutput
        $sync.RAM_WMI_Live = $liveOutput

        # 3. GPU DNA
        $gpuDnaOutput = ""
        foreach ($g in $rawGpuList) {
            $gpuDnaOutput += "Date            : $($g.Date)`nStatus          : $($g.Status)`nHW ID           :`n"
            $hw = $g.HWID
            if ($hw.Length -gt 42) {
                $gpuDnaOutput += "$($hw.Substring(0,42))`n"
                if ($hw.Length -gt 84) { $gpuDnaOutput += "$($hw.Substring(42,42))`n"; $gpuDnaOutput += "$($hw.Substring(84))`n" } else { $gpuDnaOutput += "$($hw.Substring(42))`n" }
            } else { $gpuDnaOutput += "$hw`n" }
            $gpuDnaOutput += "`n"
        }
        $sync.GPU_DNA_Text = $gpuDnaOutput

        # 4. CPU DNA
        $cpuDnaOutput = ""
        foreach ($c in $rawCpuList) {
            $dCpuId = if ($pLvl -ge 1) { "[ CONFIDENTIAL ]" } else { $c.HWID }
            $cpuDnaOutput += "--- PHYSICAL & DIGITAL IDENTITY ---`nVendor          : $($c.Mfg)`nArchitecture    : $($c.Arch)`nSocket          : $($c.Socket)`nVirtualization  : $($c.Virt)`nStatus          : $($c.Status)`nHW ID           : $dCpuId`n"
        }
        $sync.CPU_DNA_Text = $cpuDnaOutput


        # --- TELEMETRIA DINÂMICA (REAL-TIME) ---
        $sync.CPU_KernelData = [UltimateEngine]::GetKernelHardwareData($pLvl)

        $cpuSys = [UltimateEngine]::GetCpuSystemData().Split(';')
        $sync.P_CpuLoad  = $cpuSys[0]; $sync.P_HardF    = $cpuSys[1]; $sync.P_Procs    = $cpuSys[2]; $sync.P_Threads  = $cpuSys[3]
        $sync.P_Commit   = "$($cpuSys[4]) / $($cpuSys[5]) MB"
        $sync.P_CpuPerf  = $cpuSys[6]; $sync.P_Queue    = $cpuSys[7]; $sync.P_SysTemp  = $cpuSys[8]
        $sync.P_Handles  = $cpuSys[9]; $sync.P_PageSize = $cpuSys[10]; $sync.P_SysCache = $cpuSys[11]; $sync.P_KernelTot= $cpuSys[12]
        $sync.P_PagPool  = $cpuSys[13]; $sync.P_NonPaged = $cpuSys[14]; $sync.P_CommitPk = $cpuSys[15]; $sync.P_Cores    = $cpuSys[16]

        $kp = [UltimateEngine]::GetKernelPulseData().Split(';')
        $sync.P_SysCalls = $kp[0]; $sync.P_User = $kp[1]; $sync.P_Priv = $kp[2]; $sync.P_Dpc = $kp[3]; $sync.P_Int = $kp[4]; $sync.P_Mod = $kp[5]

        $perf = [double]$sync.P_CpuPerf; $base = [double]$sync.CPU_BaseClock
        if ($base -gt 0) { $sync.P_CpuFreq = [math]::Round($base * ($perf / 100), 0) } else { $sync.P_CpuFreq = 0 }
        if ($perf -gt 100) { $sync.P_State = "Turbo" } elseif ($perf -lt 100 -and $perf -gt 0) { $sync.P_State = "Eco" } else { $sync.P_State = "Base" }
        $sync.P_PfDisk = [math]::Round([UltimateEngine]::GetPageFileUsage(), 1)

        $ram = [UltimateEngine]::GetRamData().Split(';')
        $sync.P_RamLoad      = $ram[0]; $sync.P_RamLoadPrec  = $ram[1]; $sync.P_RamTotal     = $ram[2]; $sync.P_RamUsed      = $ram[3]
        $sync.P_RamFree      = $ram[4]; $sync.P_PfTotal      = $ram[5]; $sync.P_PfUsed       = $ram[6]
        $sync.P_HwRsvd = [math]::Max(0, [int]$sync.RAM_BiosTotalMB - [int]$sync.P_RamTotal)

        $gpu = [UltimateEngine]::GetGpuData($pLvl).Split(';')
        if ($gpu.Count -ge 23) {
            $sync.P_GpuIdentity = "--- PHYSICAL & DIGITAL IDENTITY ---`nUUID            :`n$($gpu[0])`nArchitecture    : $($gpu[22])`nDriver          : $($gpu[1])`nVBIOS           : $($gpu[2])`n"
            $sync.P_GpuLiveText = "--- GPU STATS ---`nLoad            : $($gpu[3]) %`nCore Clock      : $($gpu[4]) MHz`nMem Clock       : $($gpu[5]) MHz`nP-State         : P$($gpu[6]) (P0=Max, P8=PowerSave)`nCurr Power Draw : $($gpu[7]) W / $($gpu[8]) W`nStatus          : $($gpu[9])`nPCIe Bus        : Gen$($gpu[10]) x$($gpu[11])`n`n--- VRAM & BUS ---`nCalc. VRAM Load : $($gpu[12]) %`nVRAM Total      : $($gpu[13]) MB`nVRAM Used       : $($gpu[14]) MB`nVRAM Free       : $($gpu[15]) MB`nBAR1 Size       : $($gpu[16]) MB (Exposed to CPU)`nBAR1 Used       : $($gpu[17]) MB (Mapped by CPU)`nPCIe Throughp TX: $($gpu[18]) MB/s (To CPU)`nPCIe Throughp RX: $($gpu[19]) MB/s (From CPU)`n`n--- SENSORS ---`nGPU Temp        : $($gpu[20]) C`nCooling Fan Spd : $($gpu[21])"
        } else {
            $sync.P_GpuIdentity = "--- PHYSICAL & DIGITAL IDENTITY ---`nUUID            :`nN/A`nArchitecture    : N/A`nDriver          : N/A`nVBIOS           : N/A`n"
            $sync.P_GpuLiveText = "API NVML OFFLINE."
        }

        # A pausa perfeitamente limpa controlada pelas suas Settings
        Start-Sleep -Milliseconds $sync.RefreshRate
    }
    
    # Limpeza de Memória Não-Gerenciada (Evita Memory Leaks de DLLs Nativas)
    [UltimateEngine]::CloseAll()
}

$runspacePool = [runspacefactory]::CreateRunspacePool(1, 1)
$runspacePool.Open()
$ps = [powershell]::Create().AddScript($workerScript).AddArgument($syncHash)
$ps.RunspacePool = $runspacePool
$workerHandle = $ps.BeginInvoke()


# =========================================================================================
# 3. GRAPHICAL INTERFACE - MODULAR WINDOWS
# =========================================================================================

# BLINDAGEM DPI: Forçando unidade em Pixels absolutos (Regra 2)
$fTitle = New-Object System.Drawing.Font("Consolas", 15, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
$fSub   = New-Object System.Drawing.Font("Consolas", 12, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)

# --- WINDOW: CORE LOADS ---
$winCores = New-Object System.Windows.Forms.Form
$winCores.Text = "CORE LOADS (LIVE)"
$winCores.ClientSize = New-Object System.Drawing.Size(350, 500)
$winCores.BackColor = "Black"
$winCores.StartPosition = "CenterScreen"
$winCores.FormBorderStyle = 'FixedSingle'
$winCores.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::None # BLINDAGEM DPI: Desliga AutoScale (Regra 1)
$winCores.MaximizeBox = $false
$winCores.Add_FormClosing({ $_.Cancel = $true; $winCores.Hide() })

$pnlCores = New-Object System.Windows.Forms.Panel
$pnlCores.Dock = [System.Windows.Forms.DockStyle]::Fill
$pnlCores.AutoScroll = $true
$winCores.Controls.Add($pnlCores)

$lCoresLive = New-Object System.Windows.Forms.Label
$lCoresLive.Location = New-Object System.Drawing.Point(10, 10)
$lCoresLive.AutoSize = $true
$lCoresLive.Font = $fSub
$lCoresLive.ForeColor = "White"
$pnlCores.Controls.Add($lCoresLive)


# =========================================================================================
# 4. GRAPHICAL INTERFACE - MAIN WINDOW 
# =========================================================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "NATIVE HARDWARE MONITOR"
# Altura aumentada para 930 para compensar a barra de título (+30px)
$form.ClientSize = New-Object System.Drawing.Size(1540, 930) 
$form.BackColor = "Black"
$form.FormBorderStyle = 'None' # BLINDAGEM DPI: Remove Bordas Nativas (Regra 3)
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::None # BLINDAGEM DPI: Desliga AutoScale (Regra 1)
$form.StartPosition = "CenterScreen"

# --- INÍCIO DA GERAÇÃO DO ÍCONE DINÂMICO E P/INVOKE DO DRAG ---
# O Win32API foi expandido para suportar o arrastar da janela sem bordas nativas
try {
    $win32 = Add-Type -MemberDefinition '
        [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern bool DestroyIcon(IntPtr handle);
        [DllImport("user32.dll")] public static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);
        [DllImport("user32.dll")] public static extern bool ReleaseCapture();
    ' -Name "Win32Icon" -Namespace "Win32API" -PassThru
} catch { }

# 1. Lógica de Tema (Barra Clara/Escura)
$isLightTaskbar = $true
try {
    $regPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    $themeValue = Get-ItemProperty -Path $regPath -Name "SystemUsesLightTheme" -ErrorAction Stop
    if ($null -ne $themeValue.SystemUsesLightTheme) { $isLightTaskbar = [bool]$themeValue.SystemUsesLightTheme }
} catch { }

$iconColor = if ($isLightTaskbar) { [System.Drawing.Color]::Black } else { [System.Drawing.Color]::White }

# 2. Super-Sampling e Canva (64x64)
$canvasSize = 64
$bmp = New-Object System.Drawing.Bitmap($canvasSize, $canvasSize)
$graphics = [System.Drawing.Graphics]::FromImage($bmp)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
$graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$graphics.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

# 3. Bloqueio da Fonte e Desenho
$fontSize = 50
$font = New-Object System.Drawing.Font("Segoe MDL2 Assets", $fontSize, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
$brush = New-Object System.Drawing.SolidBrush($iconColor)
$stringFormat = New-Object System.Drawing.StringFormat
$stringFormat.Alignment = [System.Drawing.StringAlignment]::Center
$stringFormat.LineAlignment = [System.Drawing.StringAlignment]::Center
$rect = New-Object System.Drawing.RectangleF(0, 0, $canvasSize, $canvasSize)

$graphics.DrawString([char]0xEC4E, $font, $brush, $rect, $stringFormat)

# 4. Aplicação na sua Janela e Limpeza de Memória
$hIcon = $bmp.GetHicon()
$tempIcon = [System.Drawing.Icon]::FromHandle($hIcon)
$form.Icon = $tempIcon.Clone()

[void][Win32API.Win32Icon]::DestroyIcon($hIcon)
$tempIcon.Dispose(); $stringFormat.Dispose(); $brush.Dispose()
$font.Dispose(); $graphics.Dispose(); $bmp.Dispose()
# --- FIM DA GERAÇÃO DO ÍCONE ---


# --- BARRA DE TÍTULO CUSTOMIZADA (Drag & Drop Suave) ---
$titleBar = New-Object System.Windows.Forms.Panel
$titleBar.Size = New-Object System.Drawing.Size(1540, 30)
$titleBar.Location = New-Object System.Drawing.Point(0, 0)
$titleBar.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$form.Controls.Add($titleBar)

$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "NATIVE HARDWARE MONITOR"
$titleLabel.ForeColor = "White"
$titleLabel.Font = $fTitle
$titleLabel.AutoSize = $true
$titleLabel.Location = New-Object System.Drawing.Point(10, 6)
$titleBar.Controls.Add($titleLabel)

# Eventos de clique para permitir arrastar a janela clicando no topo
$dragAction = {
    if ($_.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
        [Win32API.Win32Icon]::ReleaseCapture()
        [Win32API.Win32Icon]::SendMessage($form.Handle, 0xA1, 0x2, 0)
    }
}
$titleBar.Add_MouseDown($dragAction)
$titleLabel.Add_MouseDown($dragAction)

# --- NOVO: BOTÃO MINIMIZAR ---
$btnMinimize = New-Object System.Windows.Forms.Button
$btnMinimize.Text = "-"
$btnMinimize.Size = New-Object System.Drawing.Size(40, 30)
$btnMinimize.Location = New-Object System.Drawing.Point(1460, 0) # Fica 40px à esquerda do botão Fechar
$btnMinimize.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnMinimize.FlatAppearance.BorderSize = 0
$btnMinimize.ForeColor = "White"
$btnMinimize.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$btnMinimize.Font = $fTitle
$btnMinimize.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnMinimize.Add_Click({ $form.WindowState = [System.Windows.Forms.FormWindowState]::Minimized })
$btnMinimize.Add_MouseEnter({ $btnMinimize.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60) }) # Fica cinza claro ao passar o rato
$btnMinimize.Add_MouseLeave({ $btnMinimize.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20) })
$titleBar.Controls.Add($btnMinimize)

# --- BOTÃO FECHAR ---
$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = "X"
$btnClose.Size = New-Object System.Drawing.Size(40, 30)
$btnClose.Location = New-Object System.Drawing.Point(1500, 0)
$btnClose.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnClose.FlatAppearance.BorderSize = 0
$btnClose.ForeColor = "White"
$btnClose.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$btnClose.Font = $fTitle
$btnClose.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnClose.Add_Click({ $form.Close() })
$btnClose.Add_MouseEnter({ $btnClose.BackColor = [System.Drawing.Color]::Red })
$btnClose.Add_MouseLeave({ $btnClose.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20) })
$titleBar.Controls.Add($btnClose)
# ------------------------------------------------


# --- COLUNA 1: CPU & SYSTEM ---
# Y ajustado de 20 para 50 devido à barra de título
$grpCpu = New-Object System.Windows.Forms.GroupBox; $grpCpu.Location=New-Object System.Drawing.Point(20, 50); $grpCpu.Size=New-Object System.Drawing.Size(360, 860); $grpCpu.ForeColor="Yellow"; $grpCpu.Text="CPU & SYSTEM"; $grpCpu.Font=$fTitle; $form.Controls.Add($grpCpu)
$lCpuName = New-Object System.Windows.Forms.Label; $lCpuName.Location=New-Object System.Drawing.Point(10, 30); $lCpuName.Size=New-Object System.Drawing.Size(340, 40); $lCpuName.Font=$fSub; $lCpuName.ForeColor="Yellow"; $grpCpu.Controls.Add($lCpuName)
$lCpuDna  = New-Object System.Windows.Forms.Label; $lCpuDna.Location=New-Object System.Drawing.Point(10, 70); $lCpuDna.Size=New-Object System.Drawing.Size(340, 120); $lCpuDna.Font=$fSub; $lCpuDna.ForeColor="White"; $grpCpu.Controls.Add($lCpuDna)
$lCpuData = New-Object System.Windows.Forms.Label; $lCpuData.Location=New-Object System.Drawing.Point(10, 190); $lCpuData.Size=New-Object System.Drawing.Size(340, 380); $lCpuData.Font=$fSub; $lCpuData.ForeColor="White"; $grpCpu.Controls.Add($lCpuData)
$lSysData = New-Object System.Windows.Forms.Label; $lSysData.Location=New-Object System.Drawing.Point(10, 580); $lSysData.Size=New-Object System.Drawing.Size(340, 90); $lSysData.Font=$fSub; $lSysData.ForeColor="White"; $grpCpu.Controls.Add($lSysData)

$btnCores = New-Object System.Windows.Forms.Button
$btnCores.Location = New-Object System.Drawing.Point(10, 730)
$btnCores.Size = New-Object System.Drawing.Size(340, 25)
$btnCores.Text = "[ OPEN CORE LOADS ]"
$btnCores.Font = $fTitle
$btnCores.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnCores.FlatAppearance.BorderColor = [System.Drawing.Color]::Yellow
$btnCores.FlatAppearance.BorderSize = 1
$btnCores.ForeColor = [System.Drawing.Color]::Yellow
$btnCores.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnCores.Add_Click({ $winCores.Show(); $winCores.BringToFront() })
$grpCpu.Controls.Add($btnCores)

$lCpuStatus = New-Object System.Windows.Forms.Label
$lCpuStatus.Location = New-Object System.Drawing.Point(10, 765)
$lCpuStatus.AutoSize = $true
$lCpuStatus.Font = $fSub
$lCpuStatus.ForeColor = "Gray"
$lCpuStatus.Text = "System cores are being monitored`nin the background.`nClick the button above to`nview real-time telemetry."
$grpCpu.Controls.Add($lCpuStatus)


# --- COLUNA 2: RAM MEMORY ---
$grpRam = New-Object System.Windows.Forms.GroupBox; $grpRam.Location=New-Object System.Drawing.Point(400, 50); $grpRam.Size=New-Object System.Drawing.Size(300, 860); $grpRam.ForeColor="Yellow"; $grpRam.Text="RAM MEMORY SPECS"; $grpRam.Font=$fTitle; $form.Controls.Add($grpRam)
$lRamName = New-Object System.Windows.Forms.Label; $lRamName.Location=New-Object System.Drawing.Point(10, 30); $lRamName.Size=New-Object System.Drawing.Size(280, 40); $lRamName.Font=$fSub; $lRamName.ForeColor="Yellow"; $grpRam.Controls.Add($lRamName)
$lRamDna = New-Object System.Windows.Forms.Label; $lRamDna.Location=New-Object System.Drawing.Point(10, 70); $lRamDna.Size=New-Object System.Drawing.Size(280, 240); $lRamDna.Font=$fSub; $lRamDna.ForeColor="White"; $grpRam.Controls.Add($lRamDna)
$lRamData = New-Object System.Windows.Forms.Label; $lRamData.Location=New-Object System.Drawing.Point(10, 310); $lRamData.Size=New-Object System.Drawing.Size(280, 540); $lRamData.Font=$fSub; $lRamData.ForeColor="White"; $grpRam.Controls.Add($lRamData)


# --- COLUNA 3: NVIDIA GPU ---
$grpGpu = New-Object System.Windows.Forms.GroupBox; $grpGpu.Location=New-Object System.Drawing.Point(720, 50); $grpGpu.Size=New-Object System.Drawing.Size(340, 860); $grpGpu.ForeColor="Yellow"; $grpGpu.Text="NVIDIA GPU"; $grpGpu.Font=$fTitle; $form.Controls.Add($grpGpu)
$lGpuName = New-Object System.Windows.Forms.Label; $lGpuName.Location=New-Object System.Drawing.Point(10, 30); $lGpuName.Size=New-Object System.Drawing.Size(320, 40); $lGpuName.Font=$fSub; $lGpuName.ForeColor="Yellow"; $grpGpu.Controls.Add($lGpuName)
$lGpuDna = New-Object System.Windows.Forms.Label; $lGpuDna.Location=New-Object System.Drawing.Point(10, 70); $lGpuDna.Size=New-Object System.Drawing.Size(320, 240); $lGpuDna.Font=$fSub; $lGpuDna.ForeColor="White"; $grpGpu.Controls.Add($lGpuDna)
$lGpuData = New-Object System.Windows.Forms.Label; $lGpuData.Location=New-Object System.Drawing.Point(10, 310); $lGpuData.Size=New-Object System.Drawing.Size(320, 540); $lGpuData.Font=$fSub; $lGpuData.ForeColor="White"; $grpGpu.Controls.Add($lGpuData)


# --- COLUNA 4 (METADE SUPERIOR): SYSTEM & MOTHERBOARD ---
$grpSys = New-Object System.Windows.Forms.GroupBox; $grpSys.Location=New-Object System.Drawing.Point(1080, 50); $grpSys.Size=New-Object System.Drawing.Size(440, 380); $grpSys.ForeColor="Yellow"; $grpSys.Text="SYSTEM & MOTHERBOARD"; $grpSys.Font=$fTitle; $form.Controls.Add($grpSys)

$lSysDna = New-Object System.Windows.Forms.Label
$lSysDna.Location = New-Object System.Drawing.Point(10, 30)
$lSysDna.AutoSize = $true
$lSysDna.Font = $fSub
$lSysDna.ForeColor = "White"
$grpSys.Controls.Add($lSysDna)

$lSysTpm = New-Object System.Windows.Forms.Label
$lSysTpm.Location = New-Object System.Drawing.Point(10, 250)
$lSysTpm.AutoSize = $true
$lSysTpm.Font = $fSub
$lSysTpm.ForeColor = "White"
$grpSys.Controls.Add($lSysTpm)


# --- COLUNA 4 (METADE INFERIOR): SETTINGS ---
# Y ajustado de 410 para 440 devido ao deslocamento
$grpSettings = New-Object System.Windows.Forms.GroupBox; $grpSettings.Location=New-Object System.Drawing.Point(1080, 440); $grpSettings.Size=New-Object System.Drawing.Size(440, 470); $grpSettings.ForeColor="Yellow"; $grpSettings.Text="SETTINGS"; $grpSettings.Font=$fTitle; $form.Controls.Add($grpSettings)

$lblRefreshDesc = New-Object System.Windows.Forms.Label
$lblRefreshDesc.Location = New-Object System.Drawing.Point(10, 30)
$lblRefreshDesc.AutoSize = $true
$lblRefreshDesc.Font = $fSub
$lblRefreshDesc.ForeColor = "White"
$lblRefreshDesc.Text = "Hardware Polling Frequency (ms):"
$grpSettings.Controls.Add($lblRefreshDesc)

$txtRefresh = New-Object System.Windows.Forms.TextBox
$txtRefresh.Location = New-Object System.Drawing.Point(14, 50)
$txtRefresh.Size = New-Object System.Drawing.Size(80, 25)
$txtRefresh.Font = $fTitle
$txtRefresh.BackColor = "Black"
$txtRefresh.ForeColor = "Yellow"
$txtRefresh.MaxLength = 5
$txtRefresh.Text = $defaultRate.ToString()
$grpSettings.Controls.Add($txtRefresh)

$txtRefresh.Add_KeyPress({
    $char = $_.KeyChar
    if ([char]::IsControl($char)) { return }
    if (-not [char]::IsDigit($char)) { $_.Handled = $true; return }
    
    $isFirstChar = ($txtRefresh.Text.Length -eq 0) -or 
                   ($txtRefresh.SelectionLength -eq $txtRefresh.Text.Length) -or 
                   ($txtRefresh.SelectionStart -eq 0 -and $txtRefresh.SelectionLength -eq 0)
                   
    if ($isFirstChar -and $char -eq '0') { $_.Handled = $true }
})

$lblPrivacyDesc = New-Object System.Windows.Forms.Label
$lblPrivacyDesc.Location = New-Object System.Drawing.Point(10, 90)
$lblPrivacyDesc.AutoSize = $true
$lblPrivacyDesc.Font = $fSub
$lblPrivacyDesc.ForeColor = "White"
$lblPrivacyDesc.Text = "Privacy Mode (Safe Screen Sharing):"
$grpSettings.Controls.Add($lblPrivacyDesc)

$cmbPrivacy = New-Object System.Windows.Forms.ComboBox
$cmbPrivacy.Location = New-Object System.Drawing.Point(14, 110)
$cmbPrivacy.Size = New-Object System.Drawing.Size(250, 25)
$cmbPrivacy.Font = $fSub
$cmbPrivacy.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$cmbPrivacy.BackColor = "Black"
$cmbPrivacy.ForeColor = "Yellow"
$cmbPrivacy.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
[void]$cmbPrivacy.Items.Add("Privacy: Disabled")
[void]$cmbPrivacy.Items.Add("Privacy: Standard")
[void]$cmbPrivacy.Items.Add("Privacy: Maximum")
$cmbPrivacy.SelectedIndex = $defaultPriv
$grpSettings.Controls.Add($cmbPrivacy)

$btnApply = New-Object System.Windows.Forms.Button
$btnApply.Location = New-Object System.Drawing.Point(14, 155)
$btnApply.Size = New-Object System.Drawing.Size(100, 26)
$btnApply.Text = "[ APPLY ]"
$btnApply.Font = $fTitle
$btnApply.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnApply.FlatAppearance.BorderColor = [System.Drawing.Color]::Yellow
$btnApply.FlatAppearance.BorderSize = 1
$btnApply.ForeColor = [System.Drawing.Color]::Yellow
$btnApply.Cursor = [System.Windows.Forms.Cursors]::Hand
$grpSettings.Controls.Add($btnApply)

$lblApplyStatus = New-Object System.Windows.Forms.Label
$lblApplyStatus.Location = New-Object System.Drawing.Point(14, 195)
$lblApplyStatus.AutoSize = $true
$lblApplyStatus.Font = $fSub
$lblApplyStatus.ForeColor = "LimeGreen"
$lblApplyStatus.Text = ""
$grpSettings.Controls.Add($lblApplyStatus)

$lblDisclaimer = New-Object System.Windows.Forms.Label
$lblDisclaimer.Location = New-Object System.Drawing.Point(10, 230)
$lblDisclaimer.AutoSize = $true
# BLINDAGEM DPI: Fonte convertida rigorosamente para Pixels
$lblDisclaimer.Font = New-Object System.Drawing.Font("Consolas", 11, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
$lblDisclaimer.ForeColor = "Gray"
$lblDisclaimer.Text = "[ UNDER THE HOOD - DATA SOURCES ]`nC# PInvoke (No Delay): kernel32.dll, pdh.dll,`npsapi.dll, advapi32.dll, user32.dll.`nNVIDIA API (Driver Delay): nvml.dll.`nPS Native (1000ms HW Lock): Get-CimInstance,`nInvoke-CimMethod."
$grpSettings.Controls.Add($lblDisclaimer)

$btnApply.Add_Click({
    if (-not [string]::IsNullOrWhiteSpace($txtRefresh.Text)) {
        $newVal = [int]$txtRefresh.Text
        $newPriv = $cmbPrivacy.SelectedIndex

        if ($newVal -gt 0) { 
            $timer.Interval = $newVal
            $syncHash.RefreshRate = $newVal
            $syncHash.PrivacyLevel = $newPriv

            Set-Content -Path $configFile -Value "RefreshRate=$newVal`nPrivacyLevel=$newPriv"
            
            $lblApplyStatus.Text = "Saved to Config.ini and Applied!"
            
            $timerClear = New-Object System.Windows.Forms.Timer
            $timerClear.Interval = 3000
            $timerClear.Add_Tick({
                $lblApplyStatus.Text = ""
                $this.Stop()
                $this.Dispose()
            })
            $timerClear.Start()
        }
    }
})


# --- TIMER DO ECRÃ PRINCIPAL E DAS JANELAS FILHAS ---
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = $syncHash.RefreshRate
$timer.Add_Tick({
    
    if ($lSysDna.Text -ne $syncHash.System_CIM_Text) { 
        $lSysDna.Text = $syncHash.System_CIM_Text 
        $lSysTpm.Top = $lSysDna.Bottom
    }

    if ($lSysTpm.Text -ne $syncHash.System_TPM_Text) { 
        $lSysTpm.Text = $syncHash.System_TPM_Text 
        if ($syncHash.System_TPM_Color -eq "Red") { $lSysTpm.ForeColor = [System.Drawing.Color]::Red } 
        else { $lSysTpm.ForeColor = [System.Drawing.Color]::White }
    }

    if ($lCpuDna.Text -ne $syncHash.CPU_DNA_Text) { $lCpuDna.Text = $syncHash.CPU_DNA_Text }
    if ($lRamDna.Text -ne $syncHash.RAM_DNA_Text) { $lRamDna.Text = $syncHash.RAM_DNA_Text }
    if ($lGpuDna.Text -ne $syncHash.GPU_DNA_Text -and $syncHash.P_GpuIdentity) { $lGpuDna.Text = $syncHash.P_GpuIdentity + $syncHash.GPU_DNA_Text }

    if ($syncHash.StartTrigger) {
        
        if ($lCpuName.Text -ne $syncHash.CPU_Name) { $lCpuName.Text = $syncHash.CPU_Name }
        if ($lGpuName.Text -ne $syncHash.GPU_Name) { $lGpuName.Text = $syncHash.GPU_Name }
        if ($lRamName.Text -ne $syncHash.RAM_Name) { $lRamName.Text = $syncHash.RAM_Name }

        if ($winCores.Visible) {
            if ($lCoresLive.Text -ne $syncHash.P_Cores) { $lCoresLive.Text = $syncHash.P_Cores }
        }

        $newCpuData = "Load            : $($syncHash.P_CpuLoad) %`nClock           : $($syncHash.P_CpuFreq) MHz`nBase Clock      : $($syncHash.CPU_BaseClock) MHz`nPerformance     : $($syncHash.P_CpuPerf) %`nState           : $($syncHash.P_State)`nTopology        : $($syncHash.CPU_Topo)`n$($syncHash.CPU_Cache)`nQueue           : $($syncHash.P_Queue) tasks`nMem Hard Faults : $($syncHash.P_HardF) /s`n`n--- KERNEL & HARDWARE ---`n$($syncHash.CPU_KernelData)`n`n--- KERNEL PULSE ---`nSystem Calls    : $($syncHash.P_SysCalls) /s`nUser Mode       : $($syncHash.P_User) %`nKernel Mode     : $($syncHash.P_Priv) %`nDPC Time        : $($syncHash.P_Dpc) %`nInterrupts      : $($syncHash.P_Int) %"
        if ($lCpuData.Text -ne $newCpuData) { $lCpuData.Text = $newCpuData }

        $newSysData = "Active Processes: $($syncHash.P_Procs)`nThreads         : $($syncHash.P_Threads)`nHandles         : $($syncHash.P_Handles)`nPage Size       : $($syncHash.P_PageSize) Bytes`nCommit          : $($syncHash.P_Commit)"
        if ($lSysData.Text -ne $newSysData) { $lSysData.Text = $newSysData }

        $newRamData = "--- LIVE USAGE ---`nRAM Load        : $($syncHash.P_RamLoad) %`nPrecision Load  : $($syncHash.P_RamLoadPrec) %`nRAM Used        : $($syncHash.P_RamUsed) MB`nRAM Free        : $($syncHash.P_RamFree) MB`nRAM Total       : $($syncHash.P_RamTotal) MB`nRAM Total (BIOS): $($syncHash.RAM_BiosTotalMB) MB`nHardware Rsvd   : $($syncHash.P_HwRsvd) MB`nPagefile        : $($syncHash.P_PfUsed) / $($syncHash.P_PfTotal) MB`nPage File Disk  : $($syncHash.P_PfDisk) %`n`n--- KERNEL POOLS ---`nSys Cache       : $($syncHash.P_SysCache) MB`nTotal Kernel Pl : $($syncHash.P_KernelTot) MB`nPaged Kernel Pl : $($syncHash.P_PagPool) MB`nNon-Paged       : $($syncHash.P_NonPaged) MB`nModified        : $($syncHash.P_Mod) MB`nCommit Peak     : $($syncHash.P_CommitPk) MB`n`n--- CONFIGURED PROFILE ---`n$($syncHash.RAM_WMI_Live)"
        if ($lRamData.Text -ne $newRamData) { $lRamData.Text = $newRamData }

        if ($lGpuData.Text -ne $syncHash.P_GpuLiveText) { $lGpuData.Text = $syncHash.P_GpuLiveText }
    }
})

$form.Add_Load({ $timer.Start() })
$form.Add_FormClosed({
    $syncHash.Run = $false
    $timer.Stop(); $timer.Dispose()
    
    $winCores.Dispose()

    [void]$ps.EndInvoke($workerHandle)
    $ps.Dispose(); $runspacePool.Close(); $runspacePool.Dispose()
})

[System.Windows.Forms.Application]::Run($form)