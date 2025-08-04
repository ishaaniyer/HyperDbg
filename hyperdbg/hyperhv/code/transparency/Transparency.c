/**
 * @file Transparency.c
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief try to hide the debugger from anti-debugging and anti-hypervisor methods
 * @details
 * @version 0.1
 * @date 2020-07-07
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"


/**
 * @brief Hide debugger on transparent-mode (activate transparent-mode)
 *
 * @param TransparentModeRequest
 * @return BOOLEAN
 */



typedef struct _DEVICE_SPOOF_ENTRY {
    const WCHAR* OriginalPattern;     // What to look for
    const WCHAR* ReplacementPattern;  // What to replace it with
    const WCHAR* DeviceType;          // PCI, USB, HDAUDIO
} DEVICE_SPOOF_ENTRY, *PDEVICE_SPOOF_ENTRY;

// TODO: Not using DeviceType anymore
const DEVICE_SPOOF_ENTRY SPOOF_ENTRIES[] = {
    // PCI Devices - VMware to Intel 
    { L"VEN_15AD&DEV_0405", L"VEN_8086&DEV_244E", L"PCI" },
    { L"VEN_15AD&DEV_0740", L"VEN_8086&DEV_244E", L"PCI" },
    { L"VEN_15AD&DEV_0770", L"VEN_8086&DEV_244E", L"PCI" },
    { L"VEN_15AD&DEV_0774", L"VEN_8086&DEV_244E", L"PCI" },
    { L"VEN_15AD&DEV_077A", L"VEN_8086&DEV_244E", L"PCI" },
    { L"VEN_15AD&DEV_0790", L"VEN_8086&DEV_244E", L"PCI" },
    { L"VEN_15AD&DEV_07A0", L"VEN_8086&DEV_244E", L"PCI" },
    { L"VEN_15AD&DEV_07E0", L"VEN_8086&DEV_244E", L"PCI" },
    { L"VEN_15AD&DEV_07F0", L"VEN_8086&DEV_244E", L"PCI" },
    { L"VEN_15AD&DEV_1977", L"VEN_8086&DEV_244E", L"PCI" },
    { L"ROOT_HUB&VID15AD&PID0774", L"ROOT_HUB&VID8086&PID07DB", L"USB" },
    { L"ROOT_HUB&VID_15AD&PID_0774", L"ROOT_HUB&VID_8086&PID_07DB", L"USB" },
    { L"ROOT_HUB&VID15AD", L"ROOT_HUB&VID8086", L"USB" }, // Catch-all for any ROOT_HUB VMware devices

    // Additional ROOT_HUB patterns for other VM vendors
    { L"ROOT_HUB&VID80EE", L"ROOT_HUB&VID8086", L"USB" }, // VirtualBox
    { L"ROOT_HUB&VID_80EE", L"ROOT_HUB&VID_8086", L"USB" }, // VirtualBox
    { L"ROOT_HUB&VID1AF4", L"ROOT_HUB&VID8086", L"USB" }, // QEMU
    { L"ROOT_HUB&VID_1AF4", L"ROOT_HUB&VID_8086", L"USB" },
    // PCI Subsystem IDs - VMware to Intel 
    { L"SUBSYS_040515AD", L"SUBSYS_244E8086", L"PCI" },
    { L"SUBSYS_074015AD", L"SUBSYS_244E8086", L"PCI" },
    { L"SUBSYS_077015AD", L"SUBSYS_244E8086", L"PCI" },
    { L"SUBSYS_197615AD", L"SUBSYS_244E8086", L"PCI" },
    { L"SUBSYS_077A15AD", L"SUBSYS_244E8086", L"PCI" },
    { L"SUBSYS_079015AD", L"SUBSYS_244E8086", L"PCI" },
    { L"SUBSYS_07A015AD", L"SUBSYS_244E8086", L"PCI" },
    { L"SUBSYS_07E015AD", L"SUBSYS_244E8086", L"PCI" },
    { L"SUBSYS_07F015AD", L"SUBSYS_244E8086", L"PCI" },
    { L"SUBSYS_197715AD", L"SUBSYS_244E8086", L"PCI" },
    { L"SUBSYS_15AD1975", L"SUBSYS_244E8086", L"PCI" },
    
    // HDAUDIO - VMware to Intel 
    { L"VEN_15AD&DEV_1975", L"VEN_8086&DEV_244E", L"HDAUDIO" },
    { L"SUBSYS_15AD1975", L"SUBSYS_244E8086", L"HDAUDIO" },
    
    // USB - VMware Root Hub 
    { L"VID15AD&PID0774", L"VID8086&PID07DB", L"USB" },          
    { L"VID_15AD&PID_0774", L"VID_8086&PID_07DB", L"USB" },       
    
    // USB - VMware Virtual USB Mouse/Tablet 
    { L"VID_0E0F&PID_0003", L"VID_8086&PID_07DB", L"USB" },       
    { L"VID0E0F&PID0003", L"VID8086&PID07DB", L"USB" },           
    
    // Additional VMware USB device patterns
    { L"VID_15AD", L"VID_8086", L"USB" },                         
    { L"VID15AD", L"VID8086", L"USB" },                          
    
    // VirtualBox entries 
    { L"VEN_80EE", L"VEN_8086", L"PCI" },
    { L"VID_80EE", L"VID_8086", L"USB" },
    { L"VID80EE", L"VID8086", L"USB" },
    
    // QEMU entries
    { L"VEN_1AF4", L"VEN_8086", L"PCI" },
    { L"VID_1AF4", L"VID_8086", L"USB" },
    { L"VID1AF4", L"VID8086", L"USB" },
};

const ULONG NUM_SPOOF_ENTRIES = sizeof(SPOOF_ENTRIES) / sizeof(DEVICE_SPOOF_ENTRY);

NTSTATUS SpoofHardwareIds(HANDLE hDeviceKey);
VOID ScanDeviceInstances(HANDLE hDeviceTypeKey);
VOID ScanAndModify(PUNICODE_STRING RootPath);
BOOLEAN ShouldProcessDevice(PWCHAR DeviceName);


BOOLEAN ShouldProcessDevice(PWCHAR DeviceName) {
    // Check if this device contains any VMware, VirtualBox, or QEMU identifiers
    return (wcsstr(DeviceName, L"15AD") != NULL || // VMware
            wcsstr(DeviceName, L"80EE") != NULL || // VirtualBox  
            wcsstr(DeviceName, L"1AF4") != NULL || // QEMU
            wcsstr(DeviceName, L"0E0F") != NULL || // VMware USB devices
            wcsstr(DeviceName, L"ROOT_HUB") != NULL); // ROOT_HUB devices
}

//Spoofs Hardware IDs of the Windows Registry
NTSTATUS SpoofHardwareIds(HANDLE hDeviceKey) {
    NTSTATUS status;
    PKEY_VALUE_PARTIAL_INFORMATION pValueInfo = NULL;
    ULONG valueSize = 0;
    UNICODE_STRING hardwareIdValueName;

    RtlInitUnicodeString(&hardwareIdValueName, L"HardwareID");

    status = ZwQueryValueKey(hDeviceKey, &hardwareIdValueName, KeyValuePartialInformation, NULL, 0, &valueSize);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        return status;
    }

    pValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, valueSize, 'Valu');
    if (!pValueInfo) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryValueKey(hDeviceKey, &hardwareIdValueName, KeyValuePartialInformation, pValueInfo, valueSize, &valueSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(pValueInfo, 'Valu');
        return status;
    }

    PWCHAR currentSrc = (PWCHAR)pValueInfo->Data;
    BOOLEAN wasModified = FALSE;

    // Process each string in the REG_MULTI_SZ
    while (*currentSrc) {
        // Apply all applicable transformations to this string
        for (ULONG i = 0; i < NUM_SPOOF_ENTRIES; i++) {
            PWCHAR found = wcsstr(currentSrc, SPOOF_ENTRIES[i].OriginalPattern);
            if (found) {
                size_t originalLen = wcslen(SPOOF_ENTRIES[i].OriginalPattern);                     
                // We assume original len == replacement len (True for entries in current spoof table)
                RtlCopyMemory(found, SPOOF_ENTRIES[i].ReplacementPattern, originalLen * sizeof(WCHAR));
                wasModified = TRUE;                                
            }
        }
        currentSrc += wcslen(currentSrc) + 1; 
    }

    if (wasModified) {
        status = ZwSetValueKey(hDeviceKey, &hardwareIdValueName, 0, REG_MULTI_SZ, pValueInfo->Data, pValueInfo->DataLength);
        if (!NT_SUCCESS(status)) {
           DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Failed to write new HardwareID value. Status: 0x%X\n", status);
        }
    }

    ExFreePoolWithTag(pValueInfo, 'Valu');
    
    return STATUS_SUCCESS;
}

//Scan devices
VOID ScanDeviceInstances(HANDLE hDeviceTypeKey) {
    NTSTATUS status;
    ULONG index = 0;
    ULONG resultLength;
    UCHAR buffer[512];
    PKEY_BASIC_INFORMATION pKeyInfo = (PKEY_BASIC_INFORMATION)buffer;
    
    status = ZwEnumerateKey(hDeviceTypeKey, index, KeyBasicInformation, pKeyInfo, sizeof(buffer), &resultLength);
    while (NT_SUCCESS(status)) {
        pKeyInfo->Name[pKeyInfo->NameLength / sizeof(WCHAR)] = L'\0';
        
        UNICODE_STRING instanceKeyName;
        RtlInitUnicodeString(&instanceKeyName, pKeyInfo->Name);
        
        OBJECT_ATTRIBUTES instanceObjAttr;
        HANDLE hInstanceKey;
        InitializeObjectAttributes(&instanceObjAttr, &instanceKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hDeviceTypeKey, NULL);
        
        status = ZwOpenKey(&hInstanceKey, KEY_READ | KEY_WRITE, &instanceObjAttr);
        if (NT_SUCCESS(status)) {
            SpoofHardwareIds(hInstanceKey);
            ZwClose(hInstanceKey);
        }

        index++;
        status = ZwEnumerateKey(hDeviceTypeKey, index, KeyBasicInformation, pKeyInfo, sizeof(buffer), &resultLength);
    }
}

VOID ScanAndModify(PUNICODE_STRING RootPath) {
    OBJECT_ATTRIBUTES objAttr;
    HANDLE hRootKey;
    NTSTATUS status;

    InitializeObjectAttributes(&objAttr, RootPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&hRootKey, KEY_READ, &objAttr);
    if (!NT_SUCCESS(status)) {
        return;
    }

    
    ULONG index = 0;
    ULONG resultLength;
    UCHAR buffer[512]; 
    PKEY_BASIC_INFORMATION pKeyInfo = (PKEY_BASIC_INFORMATION)buffer;
    
    // Enumerate device type keys
    status = ZwEnumerateKey(hRootKey, index, KeyBasicInformation, pKeyInfo, sizeof(buffer), &resultLength);
    while (NT_SUCCESS(status)) {
        pKeyInfo->Name[pKeyInfo->NameLength / sizeof(WCHAR)] = L'\0';

        // Check if this device should be processed
        if (ShouldProcessDevice(pKeyInfo->Name)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[!] Target device found: %ws\n", pKeyInfo->Name);
            
            UNICODE_STRING deviceTypeKeyName;
            RtlInitUnicodeString(&deviceTypeKeyName, pKeyInfo->Name);
            
            OBJECT_ATTRIBUTES deviceTypeObjAttr;
            HANDLE hDeviceTypeKey;
            InitializeObjectAttributes(&deviceTypeObjAttr, &deviceTypeKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hRootKey, NULL);
            
            status = ZwOpenKey(&hDeviceTypeKey, KEY_READ | KEY_WRITE, &deviceTypeObjAttr);
            if (NT_SUCCESS(status)) {
                ScanDeviceInstances(hDeviceTypeKey);
                ZwClose(hDeviceTypeKey);
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Failed to open device type key: %ws. Status: 0x%X\n", pKeyInfo->Name, status);
            }
        }

        index++;
        status = ZwEnumerateKey(hRootKey, index, KeyBasicInformation, pKeyInfo, sizeof(buffer), &resultLength);
    }

    ZwClose(hRootKey);
}



BOOLEAN
TransparentHideDebugger(PDEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE TransparentModeRequest)
{
    //
    // Check whether the transparent-mode was already initialized or not
    //

    if (!g_TransparentMode)
    {

        //
        // Enable the transparent-mode
        //
        g_TransparentMode                    = TRUE;
        TransparentModeRequest->KernelStatus = DEBUGGER_OPERATION_WAS_SUCCESSFUL;
        PAGED_CODE(); // Ensure this code runs at IRQL < DISPATCH_LEVEL

        UNICODE_STRING pciPath, usbPath, hdAudioPath;

        RtlInitUnicodeString(&pciPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\PCI");
        RtlInitUnicodeString(&usbPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\USB");
        RtlInitUnicodeString(&hdAudioPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\HDAUDIO");

        ScanAndModify(&pciPath);
        ScanAndModify(&usbPath);
        ScanAndModify(&hdAudioPath);

        if (g_TransparentRand == 0){  
            LARGE_INTEGER systemTime;
            ULONG seedForPrng;
            KeQuerySystemTimePrecise(&systemTime);
            seedForPrng = systemTime.LowPart ^ systemTime.HighPart;
            g_TransparentRand = RtlRandomEx(&seedForPrng);
        }


        BroadcastIoBitmapChangeAllCores(0xCFC);
        BroadcastIoBitmapChangeAllCores(0xCFD);
        BroadcastIoBitmapChangeAllCores(0xCFE);
        BroadcastIoBitmapChangeAllCores(0xCFF);
        BroadcastIoBitmapChangeAllCores(0xCF8);
        BroadcastIoBitmapChangeAllCores(0x5658);
        BroadcastIoBitmapChangeAllCores(0x5659);
     
        BroadcastSetExceptionBitmapAllCores(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT);
        //
        // Successfully enabled the transparent-mode
        //
        return TRUE;
    }
    else
    {
        TransparentModeRequest->KernelStatus = DEBUGGER_ERROR_DEBUGGER_ALREADY_HIDE;
        return FALSE;
    }
}

/**
 * @brief Deactivate transparent-mode
 * @param TransparentModeRequest
 *
 * @return BOOLEAN
 */
BOOLEAN
TransparentUnhideDebugger(PDEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE TransparentModeRequest)
{
    if (g_TransparentMode)
    {
        //
        // Disable the transparent-mode
        //
        g_TransparentMode = FALSE;

        TransparentModeRequest->KernelStatus = DEBUGGER_OPERATION_WAS_SUCCESSFUL;
        return TRUE;
    }
    else
    {
        TransparentModeRequest->KernelStatus = DEBUGGER_ERROR_DEBUGGER_ALREADY_UNHIDE;
        return FALSE;
    }
}

/**
 * @brief Handle Cpuid Vmexits when the Transparent mode is enabled
 *
 * @param CpuInfo The temporary logical processor registers
 * @param Regs Vcpu's GP registers
 * @return VOID
 */
VOID
TransparentCPUID(INT32 CpuInfo[], PGUEST_REGS Regs)
{
    if (Regs->rax == CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS)
    {
        //
        // Unset the Hypervisor Present-bit in RCX, which Intel and AMD have both
        // reserved for this indication
        //
        CpuInfo[2] &= ~HYPERV_HYPERVISOR_PRESENT_BIT;
    }
    else if (Regs->rax == CPUID_HV_VENDOR_AND_MAX_FUNCTIONS || Regs->rax == HYPERV_CPUID_INTERFACE)
    {
        //
        // When transparent, all CPUID leaves in the 0x40000000+ range should contain no usable data
        //
        CpuInfo[0] = CpuInfo[1] = CpuInfo[2] = CpuInfo[3] = 0;
    }
}

//
// /**
//  * @brief maximum random value
//  */
// #define MY_RAND_MAX 32768
//
//     /**
//      * @brief pre-defined log result
//      * @details we used this because we want to avoid using floating-points in
//      * kernel
//      */
//     int TransparentTableLog[] =
//     {
//         0,
//         69,
//         110,
//         139,
//         161,
//         179,
//         195,
//         208,
//         220,
//         230,
//         240,
//         248,
//         256,
//         264,
//         271,
//         277,
//         283,
//         289,
//         294,
//         300,
//         304,
//         309,
//         314,
//         318,
//         322,
//         326,
//         330,
//         333,
//         337,
//         340,
//         343,
//         347,
//         350,
//         353,
//         356,
//         358,
//         361,
//         364,
//         366,
//         369,
//         371,
//         374,
//         376,
//         378,
//         381,
//         383,
//         385,
//         387,
//         389,
//         391,
//         393,
//         395,
//         397,
//         399,
//         401,
//         403,
//         404,
//         406,
//         408,
//         409,
//         411,
//         413,
//         414,
//         416,
//         417,
//         419,
//         420,
//         422,
//         423,
//         425,
//         426,
//         428,
//         429,
//         430,
//         432,
//         433,
//         434,
//         436,
//         437,
//         438,
//         439,
//         441,
//         442,
//         443,
//         444,
//         445,
//         447,
//         448,
//         449,
//         450,
//         451,
//         452,
//         453,
//         454,
//         455,
//         456,
//         457,
//         458,
//         460,
//         461};
//
// /**
//  * @brief Generate a random number by utilizing RDTSC instruction.
//  *
//  * Masking 16 LSB of the measured clock time.
//  * @return UINT32
//  */
// UINT32
// TransparentGetRand()
// {
//     UINT64 Tsc;
//     UINT32 Rand;
//
//     Tsc  = __rdtsc();
//     Rand = Tsc & 0xffff;
//
//     return Rand;
// }
//
// /**
//  * @brief Integer power function definition.
//  *
//  * @params x Base Value
//  * @params p Power Value
//  * @return int
//  */
// int
// TransparentPow(int x, int p)
// {
//     int Res = 1;
//     for (int i = 0; i < p; i++)
//     {
//         Res = Res * x;
//     }
//     return Res;
// }
//
// /**
//  * @brief Integer Natural Logarithm function estimation.
//  *
//  * @params x input value
//  * @return int
//  */
// int
// TransparentLog(int x)
// {
//     int n     = x;
//     int Digit = 0;
//
//     while (n >= 100)
//     {
//         n = n / 10;
//         Digit++;
//     }
//
//     //
//     // Use pre-defined values of logarithms and estimate the total value
//     //
//     return TransparentTableLog[n] / 100 + (Digit * 23) / 10;
// }
// /**
//  * @brief Integer root function estimation.
//  *
//  * @params x input value
//  * @return int
//  */
// int
// TransparentSqrt(int x)
// {
//     int Res = 0;
//     int Bit;
//
//     //
//     // The second-to-top bit is set.
//     //
//     Bit = 1 << 30;
//
//     //
//     // "Bit" starts at the highest power of four <= the argument.
//     //
//     while (Bit > x)
//         Bit >>= 2;
//
//     while (Bit != 0)
//     {
//         if (x >= Res + Bit)
//         {
//             x -= Res + Bit;
//             Res = (Res >> 1) + Bit;
//         }
//         else
//             Res >>= 1;
//         Bit >>= 2;
//     }
//     return Res;
// }
//
// /**
//  * @brief Integer Gaussian Random Number Generator(GRNG) based on Box-Muller method. A Float to Integer
//  * mapping is used in the function.
//  *
//  * @params Average Mean
//  * @parans Sigma Standard Deviation of the targeted Gaussian Distribution
//  * @return int
//  */
// int
// TransparentRandn(int Average, int Sigma)
// {
//     int U1, r1, U2, r2, W, Mult;
//     int X1, X2 = 0, XS1;
//     int LogTemp = 0;
//
//     do
//     {
//         r1 = TransparentGetRand();
//         r2 = TransparentGetRand();
//
//         U1 = (r1 % MY_RAND_MAX) - (MY_RAND_MAX / 2);
//
//         U2 = (r2 % MY_RAND_MAX) - (MY_RAND_MAX / 2);
//
//         W = U1 * U1 + U2 * U2;
//     } while (W >= MY_RAND_MAX * MY_RAND_MAX / 2 || W == 0);
//
//     LogTemp = (TransparentLog(W) - TransparentLog(MY_RAND_MAX * MY_RAND_MAX));
//
//     Mult = TransparentSqrt((-2 * LogTemp) * (MY_RAND_MAX * MY_RAND_MAX / W));
//
//     X1  = U1 * Mult / MY_RAND_MAX;
//     XS1 = U1 * Mult;
//
//     X2 = U2 * Mult / MY_RAND_MAX;
//
//     return (Average + (Sigma * XS1) / MY_RAND_MAX);
// }
//
// /**
//  * @brief Add name or process id of the target process to the list
//  * of processes that HyperDbg should apply transparent-mode on them
//  *
//  * @param Measurements
//  * @return BOOLEAN
//  */
// BOOLEAN
// TransparentAddNameOrProcessIdToTheList(PDEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE Measurements)
// {
//     SIZE_T                SizeOfBuffer;
//     PTRANSPARENCY_PROCESS PidAndNameBuffer;
//
//     //
//     // Check whether it's a process id or it's a process name
//     //
//     if (Measurements->TrueIfProcessIdAndFalseIfProcessName)
//     {
//         //
//         // It's a process Id
//         //
//         SizeOfBuffer = sizeof(TRANSPARENCY_PROCESS);
//     }
//     else
//     {
//         //
//         // It's a process name
//         //
//         SizeOfBuffer = sizeof(TRANSPARENCY_PROCESS) + Measurements->LengthOfProcessName;
//     }
//
//     //
//     // Allocate the Buffer
//     //
//     PidAndNameBuffer = PlatformMemAllocateZeroedNonPagedPool(SizeOfBuffer);
//
//     if (PidAndNameBuffer == NULL)
//     {
//         return FALSE;
//     }
//
//     //
//     // Save the address of the buffer for future de-allocation
//     //
//     PidAndNameBuffer->BufferAddress = PidAndNameBuffer;
//
//     //
//     // Check again whether it's a process id or it's a process name
//     // then fill the structure
//     //
//     if (Measurements->TrueIfProcessIdAndFalseIfProcessName)
//     {
//         //
//         // It's a process Id
//         //
//         PidAndNameBuffer->ProcessId                            = Measurements->ProcId;
//         PidAndNameBuffer->TrueIfProcessIdAndFalseIfProcessName = TRUE;
//     }
//     else
//     {
//         //
//         // It's a process name
//         //
//         PidAndNameBuffer->TrueIfProcessIdAndFalseIfProcessName = FALSE;
//
//         //
//         // Move the process name string to the end of the buffer
//         //
//         RtlCopyBytes((void *)((UINT64)PidAndNameBuffer + sizeof(TRANSPARENCY_PROCESS)),
//                      (const void *)((UINT64)Measurements + sizeof(DEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE)),
//                      Measurements->LengthOfProcessName);
//
//         //
//         // Set the process name location
//         //
//         PidAndNameBuffer->ProcessName = (PVOID)((UINT64)PidAndNameBuffer + sizeof(TRANSPARENCY_PROCESS));
//     }
//
//     //
//     // Link it to the list of process that we need to transparent
//     // vm-exits for them
//     //
//     InsertHeadList(&g_TransparentModeMeasurements->ProcessList, &(PidAndNameBuffer->OtherProcesses));
//
//     return TRUE;
// }
//
// /**
//  * @brief Hide debugger on transparent-mode (activate transparent-mode)
//  *
//  * @param Measurements
//  * @return NTSTATUS
//  */
// NTSTATUS
// TransparentHideDebugger(PDEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE Measurements)
// {
//     //
//     // Check whether the transparent-mode was already initialized or not
//     //
//     if (!g_TransparentMode)
//     {
//         //
//         // Allocate the measurements buffer
//         //
//         g_TransparentModeMeasurements = (PTRANSPARENCY_MEASUREMENTS)PlatformMemAllocateZeroedNonPagedPool(sizeof(TRANSPARENCY_MEASUREMENTS));
//
//         if (!g_TransparentModeMeasurements)
//         {
//             return STATUS_INSUFFICIENT_RESOURCES;
//         }
//
//         //
//         // Initialize the lists
//         //
//         InitializeListHead(&g_TransparentModeMeasurements->ProcessList);
//
//         //
//         // Fill the transparency details CPUID
//         //
//         g_TransparentModeMeasurements->CpuidAverage           = Measurements->CpuidAverage;
//         g_TransparentModeMeasurements->CpuidMedian            = Measurements->CpuidMedian;
//         g_TransparentModeMeasurements->CpuidStandardDeviation = Measurements->CpuidStandardDeviation;
//
//         //
//         // Fill the transparency details RDTSC
//         //
//         g_TransparentModeMeasurements->RdtscAverage           = Measurements->RdtscAverage;
//         g_TransparentModeMeasurements->RdtscMedian            = Measurements->RdtscMedian;
//         g_TransparentModeMeasurements->RdtscStandardDeviation = Measurements->RdtscStandardDeviation;
//
//         //
//         // add the new process name or Id to the list
//         //
//         TransparentAddNameOrProcessIdToTheList(Measurements);
//
//         //
//         // Enable RDTSC and RDTSCP exiting on all cores
//         //
//         BroadcastEnableRdtscExitingAllCores();
//
//         //
//         // Finally, enable the transparent-mode
//         //
//         g_TransparentMode = TRUE;
//     }
//     else
//     {
//         //
//         // It's already initialized, we just need to
//         // add the new process name or Id to the list
//         //
//         TransparentAddNameOrProcessIdToTheList(Measurements);
//     }
//
//     return STATUS_SUCCESS;
// }
//
// /**
//  * @brief Deactivate transparent-mode
//  *
//  * @return NTSTATUS
//  */
// NTSTATUS
// TransparentUnhideDebugger()
// {
//     PLIST_ENTRY TempList           = 0;
//     PVOID       BufferToDeAllocate = 0;
//
//     if (g_TransparentMode)
//     {
//         //
//         // Disable the transparent-mode
//         //
//         g_TransparentMode = FALSE;
//
//         //
//         // Disable RDTSC and RDTSCP emulation
//         //
//         BroadcastDisableRdtscExitingAllCores();
//
//         //
//         // Free list of allocated buffers
//         //
//         // Check for process id and process name, if not match then we don't emulate it
//         //
//         TempList = &g_TransparentModeMeasurements->ProcessList;
//         while (&g_TransparentModeMeasurements->ProcessList != TempList->Flink)
//         {
//             TempList                             = TempList->Flink;
//             PTRANSPARENCY_PROCESS ProcessDetails = (PTRANSPARENCY_PROCESS)CONTAINING_RECORD(TempList, TRANSPARENCY_PROCESS, OtherProcesses);
//
//             //
//             // Save the buffer so we can de-allocate it
//             //
//             BufferToDeAllocate = ProcessDetails->BufferAddress;
//
//             //
//             // We have to remove the event from the list
//             //
//             RemoveEntryList(&ProcessDetails->OtherProcesses);
//
//             //
//             // Free the buffer
//             //
//             PlatformMemFreePool(BufferToDeAllocate);
//         }
//
//         //
//         // Deallocate the measurements buffer
//         //
//         PlatformMemFreePool(g_TransparentModeMeasurements);
//         g_TransparentModeMeasurements = NULL;
//
//         return STATUS_SUCCESS;
//     }
//     else
//     {
//         return STATUS_UNSUCCESSFUL;
//     }
// }
//
// /**
//  * @brief VM-Exit handler for different exit reasons
//  * @details Should be called from vmx-root
//  *
//  * @param VCpu The virtual processor's state
//  * @param ExitReason Exit Reason
//  * @return BOOLEAN Return True we should emulate RDTSCP
//  *  or return false if we should not emulate RDTSCP
//  */
// BOOLEAN
// TransparentModeStart(VIRTUAL_MACHINE_STATE * VCpu, UINT32 ExitReason)
// {
//     UINT32      Aux                = 0;
//     PLIST_ENTRY TempList           = 0;
//     PCHAR       CurrentProcessName = 0;
//     UINT32      CurrentProcessId;
//     UINT64      CurrrentTime;
//     HANDLE      CurrentThreadId;
//     BOOLEAN     Result                      = TRUE;
//     BOOLEAN     IsProcessOnTransparencyList = FALSE;
//
//     //
//     // Save the current time
//     //
//     CurrrentTime = __rdtscp(&Aux);
//
//     //
//     // Save time of vm-exit on each logical processor separately
//     //
//     VCpu->TransparencyState.PreviousTimeStampCounter = CurrrentTime;
//
//     //
//     // Find the current process id and name
//     //
//     CurrentProcessId   = HANDLE_TO_UINT32(PsGetCurrentProcessId());
//     CurrentProcessName = CommonGetProcessNameFromProcessControlBlock(PsGetCurrentProcess());
//
//     //
//     // Check for process id and process name, if not match then we don't emulate it
//     //
//     TempList = &g_TransparentModeMeasurements->ProcessList;
//     while (&g_TransparentModeMeasurements->ProcessList != TempList->Flink)
//     {
//         TempList                             = TempList->Flink;
//         PTRANSPARENCY_PROCESS ProcessDetails = (PTRANSPARENCY_PROCESS)CONTAINING_RECORD(TempList, TRANSPARENCY_PROCESS, OtherProcesses);
//         if (ProcessDetails->TrueIfProcessIdAndFalseIfProcessName)
//         {
//             //
//             // This entry is process id
//             //
//             if (ProcessDetails->ProcessId == CurrentProcessId)
//             {
//                 //
//                 // Let the transparency handler to handle it
//                 //
//                 IsProcessOnTransparencyList = TRUE;
//                 break;
//             }
//         }
//         else
//         {
//             //
//             // This entry is a process name
//             //
//             if (CurrentProcessName != NULL && CommonIsStringStartsWith(CurrentProcessName, ProcessDetails->ProcessName))
//             {
//                 //
//                 // Let the transparency handler to handle it
//                 //
//                 IsProcessOnTransparencyList = TRUE;
//                 break;
//             }
//         }
//     }
//
//     //
//     // Check whether we find this process on transparency list or not
//     //
//     if (!IsProcessOnTransparencyList)
//     {
//         //
//         // No, we didn't let's do the normal tasks
//         //
//         return TRUE;
//     }
//
//     //
//     // Get current thread Id
//     //
//     CurrentThreadId = PsGetCurrentThreadId();
//
//     //
//     // Check whether we are in new thread or in previous thread
//     //
//     if (VCpu->TransparencyState.ThreadId != CurrentThreadId)
//     {
//         //
//         // It's a new thread Id reset everything
//         //
//         VCpu->TransparencyState.ThreadId                        = CurrentThreadId;
//         VCpu->TransparencyState.RevealedTimeStampCounterByRdtsc = NULL64_ZERO;
//         VCpu->TransparencyState.CpuidAfterRdtscDetected         = FALSE;
//     }
//
//     //
//     // Now, it's time to check and play with RDTSC/P and CPUID
//     //
//
//     if (ExitReason == VMX_EXIT_REASON_EXECUTE_RDTSC || ExitReason == VMX_EXIT_REASON_EXECUTE_RDTSCP)
//     {
//         if (VCpu->TransparencyState.RevealedTimeStampCounterByRdtsc == NULL64_ZERO)
//         {
//             //
//             // It's a timing and the previous time for the thread is null
//             // so we need to save the time (maybe) for future use
//             //
//             VCpu->TransparencyState.RevealedTimeStampCounterByRdtsc = CurrrentTime;
//         }
//         else if (VCpu->TransparencyState.CpuidAfterRdtscDetected == TRUE)
//         {
//             //
//             // Someone tries to know about the hypervisor
//             // let's play with them
//             //
//
//             // LogInfo("Possible RDTSC+CPUID+RDTSC");
//         }
//         else if (VCpu->TransparencyState.RevealedTimeStampCounterByRdtsc != NULL64_ZERO &&
//                  VCpu->TransparencyState.CpuidAfterRdtscDetected == FALSE)
//         {
//             //
//             // It's a new rdtscp, let's save the new value
//             //
//             VCpu->TransparencyState.RevealedTimeStampCounterByRdtsc +=
//                 TransparentRandn((UINT32)g_TransparentModeMeasurements->CpuidAverage,
//                                  (UINT32)g_TransparentModeMeasurements->CpuidStandardDeviation);
//         }
//
//         //
//         // Adjust the rdtsc based on RevealedTimeStampCounterByRdtsc
//         //
//         VCpu->Regs->rax = 0x00000000ffffffff &
//                           VCpu->TransparencyState.RevealedTimeStampCounterByRdtsc;
//
//         VCpu->Regs->rdx = 0x00000000ffffffff &
//                           (VCpu->TransparencyState.RevealedTimeStampCounterByRdtsc >> 32);
//
//         //
//         // Check if we need to adjust rcx as a result of rdtscp
//         //
//         if (ExitReason == VMX_EXIT_REASON_EXECUTE_RDTSCP)
//         {
//             VCpu->Regs->rcx = 0x00000000ffffffff & Aux;
//         }
//         //
//         // Shows that vm-exit handler should not emulate the RDTSC/P
//         //
//         Result = FALSE;
//     }
//     else if (ExitReason == VMX_EXIT_REASON_EXECUTE_CPUID &&
//              VCpu->TransparencyState.RevealedTimeStampCounterByRdtsc != NULL64_ZERO)
//     {
//         //
//         // The guy executed one or more CPUIDs after an rdtscp so we
//         //  need to add new cpuid value to previous timer and also
//         //  we need to store it somewhere to remember this behavior
//         //
//         VCpu->TransparencyState.RevealedTimeStampCounterByRdtsc +=
//             TransparentRandn((UINT32)g_TransparentModeMeasurements->CpuidAverage,
//                              (UINT32)g_TransparentModeMeasurements->CpuidStandardDeviation);
//
//         VCpu->TransparencyState.CpuidAfterRdtscDetected = TRUE;
//     }
//
//     return Result;
// }
//
