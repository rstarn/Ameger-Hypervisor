#include "../../Global.h"

__forceinline void HandleInvalid(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    UNREFERENCED_PARAMETER(vpData);

    guestContext->VpRegs->Rax = 0xFFFF;
}

__forceinline void HandleCheckPresence(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    UNREFERENCED_PARAMETER(vpData);

    guestContext->VpRegs->Rax = Shared::COMM_CHECK;
}

void HandleGetProcess(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    UNREFERENCED_PARAMETER(vpData);

    const ULONG64 processId = guestContext->VpRegs->R8;
    guestContext->VpRegs->Rax = reinterpret_cast<ULONG64>(Utils::FindProcess(reinterpret_cast<HANDLE>(processId)));
}

void HandleGetDirectoryBase(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    UNREFERENCED_PARAMETER(vpData);

    const ULONG64 targetProcess = guestContext->VpRegs->R8;

    /*
     * If we don't reference the process object, the address space will
     * be trashed when the process starts exiting or crashes, which will
     * lead to system crash or freeze due to us overwriting the cr3 value
     * when reading the memory.
     */
    Utils::ReferenceObject(reinterpret_cast<PEPROCESS>(targetProcess));

    guestContext->VpRegs->Rax = Memory::GetDirectoryBase(reinterpret_cast<PEPROCESS>(targetProcess));
}

void HandleCopyProcessMemory(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    UNREFERENCED_PARAMETER(vpData);

    const UINT32 processorIndex = static_cast<UINT32>(vpData->HostStackLayout.ProcessorIndex);
    const ULONG64 controlData = guestContext->VpRegs->R8;
    const ULONG64 currentProcessCr3 = guestContext->VpRegs->R9;

    /*
     * The guest state save area holds the CR3 that was loaded when the
     * VMMCALL executed - the live directory base of the calling process.
     * Anti-cheats may keep this value different from the kernel-side
     * directory base reported by GetDirectoryBase; passing both lets the
     * memory routines resolve through whichever base maps the page
     * (PR #13 discussion).
     */
    const ULONG64 currentProcessDirectoryTableBase = vpData->GuestVmcb.StateSaveArea.Cr3;

    Shared::COPY_MEMORY_DATA copyData = { 0 };
    SIZE_T bytesRead;
    NTSTATUS status = Memory::ReadProcessMemoryEx(processorIndex, currentProcessCr3, currentProcessDirectoryTableBase, controlData, &copyData, sizeof(Shared::COPY_MEMORY_DATA), &bytesRead);
    if (!NT_SUCCESS(status))
    {
        guestContext->VpRegs->Rax = Shared::ErrorCodes::ControlBlockReadFail;
        return;
    }

    if (copyData.NumberOfBytes > Shared::MAX_RW_SIZE)
    {
        guestContext->VpRegs->Rax = Shared::ErrorCodes::MemoryCopyTooLarge;
        return;
    }

    status = Memory::CopyProcessMemoryEx(processorIndex, copyData.SourceDirectoryBase, copyData.SourceAddress, copyData.DestinationDirectoryBase, copyData.DestinationAddress, currentProcessCr3, currentProcessDirectoryTableBase, copyData.NumberOfBytes);
    if (!NT_SUCCESS(status))
    {
        guestContext->VpRegs->Rax = status == STATUS_ABANDONED ? Shared::ErrorCodes::MemoryCopyFailSource : Shared::ErrorCodes::MemoryCopyFailTarget;
        return;
    }

    guestContext->VpRegs->Rax = Shared::ErrorCodes::Success;
}

void HandleProtectSelf(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    UNREFERENCED_PARAMETER(vpData);

    SVM::ProtectSelf(vpData->HostStackLayout.SharedVpData);

    vpData->GuestVmcb.ControlArea.VmcbClean &= 0xFFFFFFEF;
    vpData->GuestVmcb.ControlArea.TlbControl = 1;

    guestContext->VpRegs->Rax = Shared::ErrorCodes::Success;
}

void SVM::HandleVMCall(const PVIRTUAL_PROCESSOR_DATA vpData, const PGUEST_CONTEXT guestContext)
{
    const ULONG64 magic = guestContext->VpRegs->Rcx;
    if (magic == Shared::MAGIC)
    {
        const ULONG64 command = guestContext->VpRegs->Rdx;
        switch (command)
        {
        case Shared::CheckPresence:
            HandleCheckPresence(vpData, guestContext);
            break;
        case Shared::GetProcess:
            HandleGetProcess(vpData, guestContext);
            break;
        case Shared::GetDirectoryBase:
            HandleGetDirectoryBase(vpData, guestContext);
            break;
        case Shared::CopyProcessMemory:
            HandleCopyProcessMemory(vpData, guestContext);
            break;
        case Shared::ProtectSelf:
            HandleProtectSelf(vpData, guestContext);
            break;
        default:
            HandleInvalid(vpData, guestContext);
            break;
        }
    }
    else
    {
        /*
         * PR #15: a VMMCALL from code that is not the intended hyper
         * interface is not supported in the current context and must fault
         * with #UD (AMD APM 24593, page 20).
         */
        InjectUndefinedOpcodeException(vpData);
        return;
    }

    vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;
}