/**
 * @file IoHandler.c
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief The I/O Handler for vm-exit
 * @details
 * @version 0.1
 * @date 2020-06-06
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

#define MAX_VALUES 4
#define NUM_KEYS 18

//
// Structure for holding device spoofing information.
//
typedef struct
{
    UINT16 DeviceId;
    UINT32 Id[MAX_VALUES];
    UINT8  Count; // Renamed from 'count'
} ENTRY;

//
// Global dictionary for storing spoofable device IDs and their replacements.
//
ENTRY g_SpoofingDictionary[NUM_KEYS] =
{
    { 0x0405, {0x59128086, 0x1C8110DE, 0x67DF1002}, 3 }, // Intel HD 630, NVIDIA GTX 1050, AMD Radeon RX 570
    { 0x0406, {0x59178086, 0x1B8010DE, 0x687F1002}, 3 }, // Intel UHD 620, NVIDIA GTX 1080, AMD Radeon RX Vega 64
    { 0x0710, {0x04128086, 0x138010DE, 0x67DF1002}, 3 }, // Intel HD 4600, GTX 750 Ti, Radeon RX 570
    { 0x0720, {0x100E8086, 0x816810EC, 0x165F14E4}, 3 }, // Intel 82540EM, Realtek RTL8111/8168, Broadcom BCM5720
    { 0x0740, {0x860910B5, 0x1E3A8086, 0x15781022}, 3 }, // PLX PEX 8609 switch, Intel MEI, AMD PSP 2.0
    { 0x0770, {0x293A8086, 0x0AA610DE, 0x31041106}, 3 }, // Intel ICH9 EHCI, nVidia MCP79 EHCI, VIA VT6212
    { 0x0774, {0x71128086, 0x29348086, 0x30381106}, 3 }, // Intel PIIX4 UHCI, Intel ICH9 UHCI, VIA VT83C572
    { 0x0778, {0x1E318086, 0x10421B21, 0x11001B73}, 3 }, // Intel Panther Point xHCI, ASM1042, Fresco FL1100
    { 0x0779, {0x8C318086, 0x11421B21, 0x00151912}, 3 }, // Intel Lynx Point xHCI, ASM1042A, Renesas uPD720202
    { 0x0790, {0x244E8086, 0x12378086, 0x860910B5}, 3 }, // Intel 82801 PCI-PCI, Intel 440FX bridge, PLX PEX 8609
    { 0x07A0, {0x29A08086, 0x34088086, 0x14831022}, 3 }, // Intel Q35 root-port, Intel 5520/X58 root-port, AMD Starship root-port
    { 0x07B0, {0x15638086, 0x100315B3, 0x165F14E4}, 3 }, // Intel X550 10 GbE, Mellanox ConnectX-3, Broadcom BCM5720
    { 0x07C0, {0x00581000, 0x00721000, 0x00901000}, 3 }, // LSI SAS1068E, LSI SAS2008, LSI SAS3108
    { 0x07E0, {0x29228086, 0x43911002, 0x92301B4B}, 3 }, // Intel ICH9 AHCI, AMD SB7x0 AHCI, Marvell 88SE9230
    { 0x07F0, {0xA808144D, 0xF1A68086, 0x500615B7}, 3 }, // Samsung PM981, Intel 760p/7600p, WD SN750
    { 0x0801, {0x860910B5, 0x1E3A8086, 0x15781022}, 3 }, // PLX PEX 8609, Intel MEI, AMD PSP 2.0
    { 0x0820, {0x100315B3, 0x101515B3},               2 }, // Mellanox ConnectX-3 & ConnectX-4 Lx
    { 0x1977, {0x26688086, 0x14571022, 0x10F010DE},   3 }  // Intel ICH6 HDA, AMD Family 17h HDA, nVidia GP104 HDA
};

UINT16
CheckIfSpoofingNeeded(UINT8 Offset, UINT32 TargetAddress)
{
    UINT8 BusNumber      = (UINT8)((TargetAddress >> 16) & 0xFF);
    UINT8 DeviceNumber   = (UINT8)((TargetAddress >> 11) & 0x1F);
    UINT8 FunctionNumber = (UINT8)((TargetAddress >> 8) & 0x07);
    DWORD FullId = (DWORD)PciReadCam(BusNumber, DeviceNumber, FunctionNumber, Offset, sizeof(UINT32)); // Read full DWORD
    WORD  VendorId = (WORD)(FullId & 0x0000FFFF);
    WORD  DeviceId = (WORD)(FullId >> 16);

    if (VendorId == 0x15AD || VendorId == 0x10EE)
    {
        return DeviceId;
    }
    else
    {
        return (UINT16)0;
    }
}

UINT32
GetFakeID(UINT16 DeviceId) 
{
    //
    // Iterate through the spoofing dictionary to find a match for the given DeviceId.
    //
    for (int CurrentIndex = 0; CurrentIndex < NUM_KEYS; CurrentIndex++) 
    {
        if (g_SpoofingDictionary[CurrentIndex].DeviceId == DeviceId)
        {
            UINT8 ReplacementCount = g_SpoofingDictionary[CurrentIndex].Count; 
            if (ReplacementCount > 0)
            {
                return g_SpoofingDictionary[CurrentIndex].Id[g_TransparentRand % ReplacementCount];
            }
        }
    }
    
    // Fallback ID if no specific replacement is found
    return g_SpoofingDictionary[9].Id[0]; 
}

/**
 * @brief VM-Exit handler for I/O Instructions (in/out)
 *
 * @param VCpu The virtual processor's state
 * @param IoQualification The I/O Qualification that indicates the instruction
 * @param Flags Guest's RFLAGs
 *
 * @return VOID
 */
VOID 
IoHandleIoVmExits(VIRTUAL_MACHINE_STATE * VCpu, VMX_EXIT_QUALIFICATION_IO_INSTRUCTION IoQualification, RFLAGS Flags)
{
    UINT16    Port      = 0;
    UINT32    Count     = 0;
    UINT32    Size      = 0;
    PGUEST_REGS GuestRegs = VCpu->Regs;

    //
    // VMWare tools uses port  (port 0x5658/0x5659) as I/O backdoor
    // This function will not handle these cases so if you put bitmap
    // to cause vm-exit on port 0x5658/0x5659 then VMWare tools will
    // crash
    //

    union
    {
        unsigned char * AsBytePtr;
        unsigned short *AsWordPtr;
        unsigned long * AsDwordPtr;

        void * AsPtr;
        UINT64 AsUint64;

    } PortValue;

    //
    // The I/O Implementation is derived from Petr Benes's hvpp
    // Take a look at :
    // https://github.com/wbenny/hvpp/blob/f1eece7d0def506f329b5770befd892497be2047/src/hvpp/hvpp/vmexit/vmexit_passthrough.cpp
    //

    //
    // We don't check if CPL == 0 here, because the CPU would
    // raise #GP instead of VM-exit.
    //
    // See Vol3C[25.1.1(Relative Priority of Faults and VM Exits)]
    //

    //
    // Resolve address of the source or destination.
    //
    if (IoQualification.StringInstruction)
    {
        //
        // String operations always operate either on RDI (in) or
        // RSI (out) registers.
        //
        PortValue.AsPtr = (PVOID)(IoQualification.DirectionOfAccess == AccessIn ? GuestRegs->rdi : GuestRegs->rsi);
    }
    else
    {
        //
        // Save pointer to the RAX register.
        //
        PortValue.AsPtr = &GuestRegs->rax;
    }

    //
    // Resolve port as a nice 16-bit number.
    //
    Port = (UINT16)IoQualification.PortNumber;

    //
    // Resolve number of bytes to send/receive.
    // REP prefixed instructions always take their count
    // from *CX register.
    //
    Count = IoQualification.RepPrefixed ? (GuestRegs->rcx & 0xffffffff) : 1;

    Size = (UINT32)(IoQualification.SizeOfAccess + 1);

    BOOLEAN InstructionHandled = FALSE;

    //
    // Check if transparent mode is enabled for PCI CAM spoofing.
    //
    if (g_TransparentMode == TRUE)
    {
        //
        // Handle write to PCI Configuration Address Port (0xCF8).
        //
        if (Port == 0xCF8 && IoQualification.DirectionOfAccess == AccessOut && !IoQualification.StringInstruction && Size == 4)
        {
            //
            // Store the address the guest wants to access for subsequent IN operations.
            //
            VCpu->LastPciConfigAddress = (UINT32)GuestRegs->rax;
            //
            // Perform the actual hardware OUT so subsequent INs work as expected by the PCI bus.
            //
            IoOutDword(Port, VCpu->LastPciConfigAddress);
            InstructionHandled = TRUE;
        }
        //
        // Handle read from PCI Configuration Data Ports (0xCFC-0xCFF). Writes are passed through
        //
        else if ((Port >= 0xCFC && Port <= 0xCFF) && IoQualification.DirectionOfAccess == AccessIn && !IoQualification.StringInstruction)
        {
            UINT32 TargetAddress = VCpu->LastPciConfigAddress;

            //
            // Ensure the target address is valid and PCI configuration access is enabled.
            //
            if (TargetAddress != 0 && (TargetAddress & 0x80000000))
            {
                UINT8 BusNumber      = (UINT8)((TargetAddress >> 16) & 0xFF);
                UINT8 DeviceNumber   = (UINT8)((TargetAddress >> 11) & 0x1F);
                UINT8 FunctionNumber = (UINT8)((TargetAddress >> 8) & 0x07);
                UINT8 PortByteOffset = (UINT8)(Port - 0xCFC);

                //
                // Determine the base 4-byte aligned PCI configuration offset selected by 0xCF8.
                //
                UINT8 BasePciDwordOffset = (UINT8)(TargetAddress & 0xFC);

                //
                // Read the original full 4-byte DWORD from the PCI configuration space.
                //
                UINT32 OriginalDwordData = (UINT32)PciReadCam(BusNumber, DeviceNumber, FunctionNumber, BasePciDwordOffset, sizeof(UINT32));

                UINT32 EffectiveDwordData = OriginalDwordData;

                //
                // Check if the currently selected DWORD is a "danger zone" that might need spoofing.
                //
                if ((BasePciDwordOffset == 0x00) || (BasePciDwordOffset == 0x2C) || (BasePciDwordOffset == 0x44))
                {
                    //
                    // Determine if spoofing is needed for this specific danger zone.
                    // CheckIfSpoofingNeeded uses the base offset of the danger zone.
                    //
                    UINT16 OriginalDeviceIDFromDZ = CheckIfSpoofingNeeded(BasePciDwordOffset, TargetAddress);
                    if (OriginalDeviceIDFromDZ != 0)
                    {
                        //
                        // Spoofing is required; get the fake ID.
                        //
                        EffectiveDwordData = GetFakeID(OriginalDeviceIDFromDZ);
                    }
                }

                UINT32 ValueToReturn = 0;

                if (Size == 1)
                {
                    ValueToReturn        = (EffectiveDwordData >> (PortByteOffset * 8)) & 0xFF;
                    *PortValue.AsBytePtr = (UINT8)ValueToReturn;
                }
                else if (Size == 2)
                {
                    if (PortByteOffset <= 2)
                    { // Valid word read from 0xCFC, 0xCFD, 0xCFE
                        ValueToReturn        = (EffectiveDwordData >> (PortByteOffset * 8)) & 0xFFFF;
                        *PortValue.AsWordPtr = (UINT16)ValueToReturn;
                    }
                    else
                    { 
                        ValueToReturn        = (EffectiveDwordData >> (3 * 8)) & 0xFF; // Return last byte
                        *PortValue.AsWordPtr = (UINT16)(ValueToReturn & 0xFF);
                    }
                }
                else if (Size == 4)
                {
                    if (PortByteOffset == 0)
                    { // Full DWORD read from 0xCFC
                        ValueToReturn          = EffectiveDwordData;
                        *PortValue.AsDwordPtr = (UINT32)ValueToReturn;
                    }
                    else
                    { // "Unaligned" DWORD read from 0xCFD, 0xCFE, 0xCFF
                        ValueToReturn          = (EffectiveDwordData >> (PortByteOffset * 8));
                        *PortValue.AsDwordPtr = (UINT32)ValueToReturn;
                    }
                }
                InstructionHandled = TRUE;
            }
        }

        else if (Port == 0x5658 || Port == 0x5659) // Handling VMware backdoor ports
        {
            PCHAR ProcessName = CommonGetProcessNameFromProcessControlBlock(PsGetCurrentProcess());
           
            if (_stricmp(ProcessName, "vmwaretools.exe") != 0) {
                LogInfo("Non authorised process, blocked access to VMware backdoor\n");
                VCpu->Regs->rax = 0xFFFFFFFF;
                VCpu->Regs->rbx = 0;
                VCpu->Regs->rcx = 0;
                VCpu->Regs->rdx = 0;
                InstructionHandled = TRUE;
            }       
        }
    }

 
    if (InstructionHandled)
    {
        return;
    }

    switch (IoQualification.DirectionOfAccess)
    {
    case AccessIn:
        if (IoQualification.StringInstruction)
        {
            switch (Size)
            {
            case 1:
                IoInByteString(Port, (UINT8 *)PortValue.AsBytePtr, Count);
                break;
            case 2:
                IoInWordString(Port, (UINT16 *)PortValue.AsWordPtr, Count);
                break;
            case 4:
                IoInDwordString(Port, (UINT32 *)PortValue.AsDwordPtr, Count);
                break;
            }
        }
        else
        {
            //
            // Note that port_value holds pointer to the
            // vp.context().rax member, therefore we're
            // directly overwriting the RAX value.
            //
            switch (Size)
            {
            case 1:
                *PortValue.AsBytePtr = IoInByte(Port);
                break;
            case 2:
                *PortValue.AsWordPtr = IoInWord(Port);
                break;
            case 4:
                *PortValue.AsDwordPtr = IoInDword(Port);
                break;
            }
        }
        break;

    case AccessOut:
        if (IoQualification.StringInstruction)
        {
            switch (Size)
            {
            case 1:
                IoOutByteString(Port, (UINT8 *)PortValue.AsBytePtr, Count);
                break;
            case 2:
                IoOutWordString(Port, (UINT16 *)PortValue.AsWordPtr, Count);
                break;
            case 4:
                IoOutDwordString(Port, (UINT32 *)PortValue.AsDwordPtr, Count);
                break;
            }
        }
        else
        {
            //
            // Note that port_value holds pointer to the
            // vp.context().rax member, therefore we're
            // directly reading from the RAX value.
            //
            switch (Size)
            {
            case 1:
                IoOutByte(Port, *PortValue.AsBytePtr);
                break;
            case 2:
                IoOutWord(Port, *PortValue.AsWordPtr);
                break;
            case 4:
                IoOutDword(Port, *PortValue.AsDwordPtr);
                break;
            }
        }
        break;
    }

    if (IoQualification.StringInstruction)
    {
        //
        // Update register:
        // If the DF (direction flag) is set, decrement,
        // otherwise increment.
        //
        // For in the register is RDI, for out it's RSI.
        //
        UINT64 GpReg = IoQualification.DirectionOfAccess == AccessIn ? GuestRegs->rdi : GuestRegs->rsi;

        if (Flags.DirectionFlag)
        {
            GpReg -= Count * Size;
        }
        else
        {
            GpReg += Count * Size;
        }

        //
        // We've sent/received everything, reset counter register
        // to 0.
        //
        if (IoQualification.RepPrefixed)
        {
            GuestRegs->rcx = 0;
        }
    }
}




/**
 * @brief Set bits in I/O Bitmap
 *
 * @param VCpu The virtual processor's state
 * @param Port Port
 *
 * @return BOOLEAN Returns true if the I/O Bitmap is successfully applied or false if not applied
 */
BOOLEAN
IoHandleSetIoBitmap(VIRTUAL_MACHINE_STATE * VCpu, UINT32 Port)
{
    if (Port <= 0x7FFF)
    {
        SetBit(Port, (unsigned long *)VCpu->IoBitmapVirtualAddressA);
    }
    else if ((0x8000 <= Port) && (Port <= 0xFFFF))
    {
        SetBit(Port - 0x8000, (unsigned long *)VCpu->IoBitmapVirtualAddressB);
    }
    else
    {
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Change I/O Bitmap
 * @details should be called in vmx-root mode
 *
 * @param VCpu The virtual processor's state
 * @param IoPort Port
 * @return VOID
 */
VOID
IoHandlePerformIoBitmapChange(VIRTUAL_MACHINE_STATE * VCpu, UINT32 Port)
{
    if (Port == DEBUGGER_EVENT_ALL_IO_PORTS)
    {
        //
        // Means all the bitmaps should be put to 1
        //
        memset((void *)VCpu->IoBitmapVirtualAddressA, 0xFF, PAGE_SIZE);
        memset((void *)VCpu->IoBitmapVirtualAddressB, 0xFF, PAGE_SIZE);
    }
    else
    {
        //
        // Means only one i/o bitmap is target
        //
        IoHandleSetIoBitmap(VCpu, Port);
    }
}

/**
 * @brief Reset I/O Bitmap
 * @details should be called in vmx-root mode
 * @param VCpu The virtual processor's state
 *
 * @return VOID
 */
VOID
IoHandlePerformIoBitmapReset(VIRTUAL_MACHINE_STATE * VCpu)
{
    //
    // Means all the bitmaps should be put to 0
    //
    memset((void *)VCpu->IoBitmapVirtualAddressA, 0x0, PAGE_SIZE);
    memset((void *)VCpu->IoBitmapVirtualAddressB, 0x0, PAGE_SIZE);
}
