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


 // For srand()

/**
 * @brief Hide debugger on transparent-mode (activate transparent-mode)
 *
 * @param TransparentModeRequest
 * @return BOOLEAN
 */

#define ACPI_MCFG_SIGNATURE 0x4746434D // "MCFG"
#define ECAM_MEMORY_PER_BUS (1024ULL * 1024ULL) 

#pragma pack(push, 1) // Push current packing and set to 1-byte alignment

// Standard ACPI Table Header


// MCFG Table Structure (PCI Express memory mapped configuration space base address description table)
typedef struct _MCFG_TABLE {
    ULONG Signature;
    ULONG Length;
    UCHAR Revision;
    UCHAR Checksum;
    UCHAR OemId[6];
    UCHAR OemTableId[8];
    ULONG OemRevision;
    ULONG CreatorId;
    ULONG CreatorRevision;
    ULONGLONG Reserved; // Reserved 8 bytes
} MCFG_TABLE, *PMCFG_TABLE;

// PCI Express Memory Mapped Configuration Space Base Address Allocation Structure
typedef struct _MCFG_ALLOCATION_STRUCTURE {
    ULONGLONG BaseAddress;      // Base address of the configuration space for this segment group
    USHORT PciSegmentGroup;     // PCI segment group number
    UCHAR StartBusNumber;       // Starting PCI bus number for this segment group
    UCHAR EndBusNumber;         // Ending PCI bus number for this segment group
    ULONG Reserved;             // Reserved 4 bytes
} MCFG_ALLOCATION_STRUCTURE, *PMCFG_ALLOCATION_STRUCTURE;

#pragma pack(pop) 

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

        NTSTATUS status; // Will be set by ExGetSystemFirmwareTable but not explicitly checked for errors
        ULONG tableBufferSize = 0;
        PMCFG_TABLE mcfgTable = NULL;

        PAGED_CODE(); // Ensure this code runs at IRQL < DISPATCH_LEVEL

        
        status = ExGetSystemFirmwareTable('ACPI', ACPI_MCFG_SIGNATURE, NULL, 0, &tableBufferSize);

       
        if (tableBufferSize > 0) // Basic check to prevent allocating 0 bytes if table not found initially
        {
            mcfgTable = (PMCFG_TABLE)ExAllocatePool2(POOL_FLAG_NON_PAGED, tableBufferSize, 'MCFG');
        }
       

        // Step 3: Get the actual MCFG table.
        // We assume mcfgTable is a valid pointer (allocation succeeded) and this call succeeds.
        if (mcfgTable != NULL) // Proceed only if allocation was attempted and potentially successful
        {
            status = ExGetSystemFirmwareTable('ACPI', ACPI_MCFG_SIGNATURE, mcfgTable, tableBufferSize, &tableBufferSize);

            // Step 4: Directly access the first allocation structure and print its base address.
            // This assumes the table was successfully read and is correctly structured,
            // and that there's at least one allocation structure.
            ULONG allocationStructuresOffset = sizeof(MCFG_TABLE);
            PMCFG_ALLOCATION_STRUCTURE AllocationStructure =
                (PMCFG_ALLOCATION_STRUCTURE)((PUCHAR)mcfgTable + allocationStructuresOffset);

            
            
            g_EcamBase = AllocationStructure->BaseAddress;
            g_EcamSize = 4096 *  ((AllocationStructure->EndBusNumber - AllocationStructure->StartBusNumber) * DEVICE_MAX_NUM * FUNCTION_MAX_NUM);
            
            for (USHORT bus = AllocationStructure->StartBusNumber; bus <= AllocationStructure->EndBusNumber; bus++)
        {
            for (USHORT device = 0; device < DEVICE_MAX_NUM; device++)
            {
                

                for (USHORT function = 0; function < FUNCTION_MAX_NUM; function++)
                {
                    
                    QWORD retValue = PciReadCam(bus, device, function, 0, sizeof(QWORD));
                    if (retValue != MAXDWORD64){
                        
                        ULONGLONG functionBaseAddress = AllocationStructure->BaseAddress +
                                                        ((ULONGLONG)bus << 20) |
                                                        ((ULONGLONG)device << 15) |
                                                        ((ULONGLONG)function << 12);
                        
                        
                         WORD VendorID = (WORD)(retValue & 0xFFFF);
                         if (VendorID == 0x15AD){
                            BOOLEAN retvalueofhookedpage = EptHookCreateHookPagePCIECAM(0x8086, 0x244E, functionBaseAddress);
                           LogInfo("functionalbase: %llx, %d\n", functionBaseAddress, retvalueofhookedpage);

                         }
                    }
                }
              }
            
            }
        
        } else {
            LogInfo("Failed to allocate memory for MCFG table or table not found initially.\n");
 
         
        }
      
        if (mcfgTable != NULL)
        {
            ExFreePoolWithTag(mcfgTable, 'MCFG');
        }

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
        //BroadcastIoBitmapChangeAllCores(0x5658);
        //BroadcastIoBitmapChangeAllCores(0x5659);
       
      
     
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
