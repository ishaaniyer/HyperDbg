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
ENTRY g_SpoofingDictionary[NUM_KEYS] = { // Renamed from 'dictionary' and added 'g_'
    {                                    // 1. VMware SVGA II Adapter
     0x0405,
     {0x1AF41050, 0x101300B8, 0x12341111}, // VirtIO GPU, Cirrus Logic CLGD 5446, Bochs VBE
     3},
    {                                    // 2. VMware SVGA II Adapter (Fusion)
     0x0406,
     {0x1AF41050, 0x101300B8}, // VirtIO GPU, Cirrus Logic CLGD 5446
     2},
    {                                    // 3. VMware SVGA Adapter
     0x0710,
     {0x1AF41050, 0x12341111, 0x101300B8}, // VirtIO GPU, Bochs VBE, Cirrus Logic CLGD 5446
     3},
    {                                    // 4. VMware VMXNET Ethernet Controller
     0x0720,
     {0x8086100E, 0x10222000, 0x1AF41000, 0x10EC8139}, // Intel E1000, AMD PCnet, VirtIO NET, Realtek RTL8139
     4},
    {                                    // 5. VMware Virtual Machine Communication Interface (VMCI)
     0x0740,
     {0x1AF41003, 0x1AF41045}, // VirtIO Console, VirtIO Vsock PCI
     2},
    {                                    // 6. VMware USB2 EHCI Controller
     0x0770,
     {0x8086293A, 0x1B36000D, 0x11063104}, // Intel ICH9 EHCI, QEMU EHCI, VIA EHCI
     3},
    {                                    // 7. VMware USB1.1 UHCI Controller
     0x0774,
     {0x80867112, 0x80862934, 0x11063038}, // Intel PIIX4 UHCI, Intel ICH9 UHCI, VIA UHCI
     3},
    {                                    // 8. VMware USB3 xHCI 0.96 Controller
     0x0778,
     {0x80861E31, 0x1B36000E, 0x1B731100}, // Intel Panther Point xHCI, QEMU xHCI, Fresco Logic FL1100
     3},
    {                                    // 9. VMware USB3 xHCI 1.0 Controller
     0x0779,
     {0x80868C31, 0x1B211142, 0x19120015}, // Intel Lynx Point xHCI, ASMedia ASM1042, Renesas uPD720202
     3},
    {                                    // 10. VMware PCI bridge
     0x0790,
     {0x8086244E, 0x8086123B, 0x80862640}, // Intel 82801 PCI Bridge, QEMU i440FX PCI-PCI, Intel 6300ESB PCI-PCI
     3},
    {                                    // 11. VMware PCI Express Root Port
     0x07A0,
     {0x808629A0, 0x80863A40, 0x10221483}, // Intel Q35 PCIe RP, Intel ICH10 PCIe RP, AMD Starship PCIe RP
     3},
    {                                    // 12. VMware VMXNET3 Ethernet Controller
     0x07B0,
     {0x1AF41041, 0x808610D3, 0x808610E6}, // VirtIO NET (modern), Intel E1000E (82574L), Intel IGB (82576)
     3},
    {                                    // 13. VMware PVSCSI SCSI Controller
     0x07C0,
     {0x1AF41004, 0x10000058, 0x1000007}, // VirtIO SCSI, LSI Logic SAS1068E, LSI Logic MegaRAID SAS 2008
     3},
    {                                    // 14. VMware SATA AHCI controller
     0x07E0,
     {0x80862922, 0x1AF41001, 0x1B4B9230}, // Intel ICH9 AHCI, VirtIO Block, Marvell 88SE9230 AHCI
     3},
    {                                    // 15. VMware NVMe SSD Controller
     0x07F0,
     {0x80865845, 0x8086F1A6, 0x1AF41001}, // Emulated Intel NVMe (e.g. Optane), Samsung PM981, Intel Client NVMe, VirtIO Block
     3},
    {                                    // 16. VMware Virtual Machine Interface (Hypervisor ROM Interface)
     0x0801,                             // Device ID 0x0801, Subsystem ID 0x15AD0800
     {0x1AF41002, 0x1AF41005, 0x1AF41110}, // VirtIO Memballoon, VirtIO RNG, IVSHMEM (QEMU)
     3},
    {                                    // 17. VMware Paravirtual RDMA controller
     0x0820,
     {0x15B31003, 0x15B31015}, // Mellanox ConnectX-3, Mellanox ConnectX-4 Lx
     2},
    {                                    // 18. VMware HD Audio Controller
     0x1977,
     {0x80862668, 0x8086293E, 0x1AF41052, 0x808624D5}, // Intel ICH6 HD Audio, Intel ICH9 HD Audio, VirtIO Sound, Intel AC'97
     4}};

UINT16
CheckIfSpoofingNeeded(UINT8 Offset, UINT32 TargetAddress)
{
    UINT8 BusNumber      = (UINT8)((TargetAddress >> 16) & 0xFF);
    UINT8 DeviceNumber   = (UINT8)((TargetAddress >> 11) & 0x1F);
    UINT8 FunctionNumber = (UINT8)((TargetAddress >> 8) & 0x07);
    DWORD FullId = (DWORD)PciReadCam(BusNumber, DeviceNumber, FunctionNumber, Offset, sizeof(UINT32)); // Read full DWORD
    WORD  VendorId = (WORD)(FullId & 0x0000FFFF);
    WORD  DeviceId = (WORD)(FullId >> 16);

    if (VendorId == 0x15AD)
    {
        return DeviceId;
    }
    else
    {
        return (UINT16)0;
    }
}

UINT32
GetFakeID(UINT16 DeviceId) // Renamed parameter
{
    //
    // Iterate through the spoofing dictionary to find a match for the given DeviceId.
    //
    for (int CurrentIndex = 0; CurrentIndex < NUM_KEYS; CurrentIndex++) // Variable 'i' to 'CurrentIndex' for clarity (optional, 'i' is common)
    {
        if (g_SpoofingDictionary[CurrentIndex].DeviceId == DeviceId)
        {
            UINT8 ReplacementCount = g_SpoofingDictionary[CurrentIndex].Count; // Renamed 'count' to 'ReplacementCount'
            //
            // Ensure Count is not zero to prevent division by zero or incorrect modulo.
            //
            if (ReplacementCount > 0)
            {
                //
                // Corrected modulo indexing.
                //
                return g_SpoofingDictionary[CurrentIndex].Id[g_TransparentRand % ReplacementCount];
            }
        }
    }
    
    // Fallback ID if no specific replacement is found
    return g_SpoofingDictionary[9].Id[0]; // Ensure dictionary[3] is a safe fallback.
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
VOID IoHandleIoVmExits(
    VIRTUAL_MACHINE_STATE * VCpu,
    VMX_EXIT_QUALIFICATION_IO_INSTRUCTION IoQualification,
    RFLAGS                                   Flags)
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
        // Handle read from PCI Configuration Data Ports (0xCFC - 0xCFF).
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

                //
                // Extract the specific byte(s) the guest requested from the (potentially spoofed) EffectiveDwordData.
                //
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
                    { // Word read from 0xCFF (PortByteOffset 3) is unusual
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
            
            if (IoQualification.StringInstruction)
            {
                InstructionHandled = TRUE;
            }
            else // Non-String Instruction (most common for these ports)
            {
                if (IoQualification.DirectionOfAccess == AccessIn) // Guest is doing an IN instruction
                {
                    switch (Size)
                    {
                        case 1: // 1-byte IN (guest expects result in AL)
                            *PortValue.AsBytePtr = 0xFFU; // Set AL to 0xFF
                            break;

                        case 2: // 2-byte IN (guest expects result in AX)
                            *PortValue.AsWordPtr = 0xFFFFU; // Set AX to 0xFFFF
                            break;

                        case 4: // 4-byte IN (guest expects result in EAX)
                            *PortValue.AsDwordPtr = 0xFFFFFFFFUL; // Set EAX to 0xFFFFFFFF
                            break;

                        default:
                            break;
                    }
                    
                    InstructionHandled = TRUE;
                }
                else{
                    InstructionHandled = TRUE;
                }
            }
        }
    }

    //
    // If the instruction was not handled by custom PCI CAM logic, pass it through.
    //
    if (!InstructionHandled)
    {
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
    }

    //
    // Update guest registers for string instructions if REP prefixed.
    //
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
        // Update the actual guest register based on direction.
        //
        if (IoQualification.DirectionOfAccess == AccessIn)
        {
            GuestRegs->rdi = GpReg;
        }
        else
        {
            GuestRegs->rsi = GpReg;
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