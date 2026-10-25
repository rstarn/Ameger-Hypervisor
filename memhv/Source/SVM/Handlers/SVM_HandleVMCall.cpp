#include "../../Global.h" // IWYU pragma: keep
#include "../../HVLog.h"

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
    const PEPROCESS process = Utils::FindProcess(reinterpret_cast<HANDLE>(processId));
    if (!process)
    {
        guestContext->VpRegs->Rax = 0;
        return;
    }

    /*
     * The client keeps this pointer and hands it back to GetDirectoryBase
     * later, so the object has to stay alive after the list walk.  The
     * reference is deliberately never released: leaking one reference per
     * attach is far safer than returning a dangling EPROCESS.
     */
    Utils::ReferenceObject(process);

    guestContext->VpRegs->Rax = reinterpret_cast<ULONG64>(process);
}

void HandleGetDirectoryBase(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    UNREFERENCED_PARAMETER(vpData);

    const ULONG64 targetProcess = guestContext->VpRegs->R8;

    /*
     * R8 is fully user-controlled and ReferenceObject dereferences the
     * OBJECT_HEADER behind it, so a bogus pointer would corrupt or crash
     * the kernel.  Only accept a canonical, aligned EPROCESS that really
     * appears in the active process list.
     */
    if (!Utils::IsValidProcess(reinterpret_cast<PEPROCESS>(targetProcess)))
    {
        guestContext->VpRegs->Rax = Shared::ErrorCodes::InvalidProcess;
        return;
    }

    /*
     * If we don't reference the process object, the address space will
     * be trashed when the process starts exiting or crashes, which will
     * lead to system crash or freeze due to us overwriting the cr3 value
     * when reading the memory.  As in HandleGetProcess the reference is
     * intentionally leaked.
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
     * R8 is fully user-controlled and is used as the virtual address the
     * control block is read from.  Reject anything outside user space
     * before it reaches the page walk; a kernel or non-canonical address
     * would be resolved through the guest directory base and copied into
     * this buffer.
     */
    if (!Utils::ValidUsermodeAddress(controlData))
    {
        guestContext->VpRegs->Rax = Shared::ErrorCodes::ControlBlockReadFail;
        return;
    }

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
        HV::LogNum("HandleCopyProcessMemory: control block read failed", static_cast<unsigned long long>(status));
        guestContext->VpRegs->Rax = Shared::ErrorCodes::ControlBlockReadFail;
        return;
    }

    if (copyData.NumberOfBytes > Shared::MAX_RW_SIZE)
    {
        HV::Log("HandleCopyProcessMemory: size over limit");
        guestContext->VpRegs->Rax = Shared::ErrorCodes::MemoryCopyTooLarge;
        return;
    }

    status = Memory::CopyProcessMemoryEx(processorIndex, copyData.SourceDirectoryBase, copyData.SourceAddress, copyData.DestinationDirectoryBase, copyData.DestinationAddress, currentProcessCr3, currentProcessDirectoryTableBase, copyData.NumberOfBytes);
    if (!NT_SUCCESS(status))
    {
        HV::LogNum("HandleCopyProcessMemory: copy failed", static_cast<unsigned long long>(status));
        guestContext->VpRegs->Rax = status == STATUS_ABANDONED ? Shared::ErrorCodes::MemoryCopyFailSource : Shared::ErrorCodes::MemoryCopyFailTarget;
        return;
    }

    guestContext->VpRegs->Rax = Shared::ErrorCodes::Success;
}

void HandleProtectSelf(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    UNREFERENCED_PARAMETER(vpData);

    HV::Log("HandleProtectSelf: enter");

    const NTSTATUS status = SVM::ProtectSelf(vpData->HostStackLayout.SharedVpData);
    if (!NT_SUCCESS(status))
    {
        /*
         * Shared::ErrorCodes has no self-hide-specific code, so report the
         * generic failure sentinel HandleInvalid() already uses rather than
         * inventing a value the client does not know.  Protect() only checks
         * for Success, so any non-zero value is a failure for the client.
         */
        guestContext->VpRegs->Rax = 0xFFFF;
        return;
    }

    HV::Log("HandleProtectSelf: ProtectSelf ok, arming TlbControl");

    SVM::MarkControlAreaDirty(vpData->GuestVmcb.ControlArea);
    vpData->GuestVmcb.ControlArea.TlbControl = 1;

    guestContext->VpRegs->Rax = Shared::ErrorCodes::Success;
}

void HandleProtectRange(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    const ULONG64 virtualBase = guestContext->VpRegs->R8;
    const SIZE_T size = static_cast<SIZE_T>(guestContext->VpRegs->R9);

    HV::LogNum("HandleProtectRange: HideRange size", size);

    //
    // R8/R9 are fully guest-controlled and become the virtual range the
    // NPT walk blanks, one MmGetPhysicalAddress() per page.  The walk only
    // acts on kernel addresses that MmGetPhysicalAddress() resolves to a real
    // page, so a bogus or user-mode range simply matches nothing and reports
    // STATUS_NOT_FOUND instead of touching any page.
    //
    const NTSTATUS status = SVM::HideRange(vpData->HostStackLayout.SharedVpData, virtualBase, size);
    if (!NT_SUCCESS(status))
    {
        guestContext->VpRegs->Rax = 0xFFFF;
        return;
    }

    SVM::MarkControlAreaDirty(vpData->GuestVmcb.ControlArea);
    vpData->GuestVmcb.ControlArea.TlbControl = 1;

    guestContext->VpRegs->Rax = Shared::ErrorCodes::Success;
}

void HandleFlushNpt(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    UNREFERENCED_PARAMETER(vpData);

    /*
     * Deliberately does nothing.  HandleExit()'s NptFlushGeneration check runs
     * before the exit dispatch, so the #VMEXIT this VMMCALL causes is itself
     * what re-arms TlbControl in this CPU's VMCB.  Touching any guest state
     * here would be wrong: the client uses the command purely to force one
     * exit per processor.
     */
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
        case Shared::ProtectRange:
            HandleProtectRange(vpData, guestContext);
            break;
        case Shared::FlushNpt:
            HandleFlushNpt(vpData, guestContext);
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