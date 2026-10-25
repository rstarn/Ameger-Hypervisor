#include "../../../Core/Global.h" // IWYU pragma: keep
#include "../../../Common/HVLogs.h"

namespace
{
    bool LookupProcessById(const ULONG32 processId, PEPROCESS* process)
    {
        if (processId == 0 || !process)
            return false;

        return NT_SUCCESS(PsLookupProcessByProcessId(
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId)), process));
    }
}

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

    const ULONG32 processId = static_cast<ULONG32>(guestContext->VpRegs->R8);

    PEPROCESS process = nullptr;
    if (!LookupProcessById(processId, &process))
    {
        guestContext->VpRegs->Rax = 0;
        return;
    }

    //
    // This value is informational only (the client prints it); all memory
    // operations use PIDs.  The reference is dropped immediately, so the
    // pointer must not be dereferenced after the process can exit.
    //
    ObDereferenceObject(process);
    guestContext->VpRegs->Rax = reinterpret_cast<ULONG64>(process);
}

void HandleGetDirectoryBase(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    UNREFERENCED_PARAMETER(vpData);

    const ULONG32 processId = static_cast<ULONG32>(guestContext->VpRegs->R8);

    PEPROCESS process = nullptr;
    if (!LookupProcessById(processId, &process))
    {
        //
        // 0 is the unambiguous failure result: the client rejects a zero
        // directory base explicitly, while every real CR3 is non-zero and
        // page aligned.  Returning the InvalidProcess code here was read as a
        // (bogus) directory base by callers that only rejected 0.
        //
        guestContext->VpRegs->Rax = 0;
        return;
    }

    const ULONG64 directoryBase = Memory::GetDirectoryBase(process);
    ObDereferenceObject(process);

    if (directoryBase == 0)
    {
        guestContext->VpRegs->Rax = 0;
        return;
    }

    guestContext->VpRegs->Rax = directoryBase;
}

void HandleCopyProcessMemory(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    const UINT32 processorIndex = static_cast<UINT32>(vpData->HostStackLayout.ProcessorIndex);
    const ULONG64 controlData = guestContext->VpRegs->R8;

    /*
     * R8 is fully user-controlled and is used as the virtual address the
     * control block is read from.  Reject anything outside user space, or a
     * range that would wrap, before it reaches the page walk.
     */
    if (!Utils::ValidUsermodeAddress(controlData) ||
        controlData > Global::HighestUserAddress - sizeof(Shared::COPY_MEMORY_DATA))
    {
        guestContext->VpRegs->Rax = Shared::ErrorCodes::ControlBlockReadFail;
        return;
    }

    const PEPROCESS currentProcess = PsGetCurrentProcess();
    const ULONG64 currentDirectoryBase = Memory::GetDirectoryBase(currentProcess);
    if (currentDirectoryBase == 0)
    {
        guestContext->VpRegs->Rax = Shared::ErrorCodes::ControlBlockReadFail;
        return;
    }

    Shared::COPY_MEMORY_DATA copyData = { 0 };
    SIZE_T bytesRead = 0;
    const NTSTATUS readStatus = Memory::ReadProcessMemoryEx(
        processorIndex, currentDirectoryBase, controlData,
        &copyData, sizeof(copyData), &bytesRead);
    if (!NT_SUCCESS(readStatus) || bytesRead != sizeof(copyData))
    {
        Hypervisor::LogNum("HandleCopyProcessMemory: control block read failed", static_cast<unsigned long long>(readStatus));
        guestContext->VpRegs->Rax = Shared::ErrorCodes::ControlBlockReadFail;
        return;
    }

    if (copyData.NumberOfBytes > Shared::MAX_RW_SIZE)
    {
        Hypervisor::Log("HandleCopyProcessMemory: size over limit");
        guestContext->VpRegs->Rax = Shared::ErrorCodes::MemoryCopyTooLarge;
        return;
    }

    if (copyData.NumberOfBytes == 0)
    {
        guestContext->VpRegs->Rax = Shared::ErrorCodes::Success;
        return;
    }

    PEPROCESS sourceProcess = nullptr;
    PEPROCESS targetProcess = nullptr;

    if (!LookupProcessById(copyData.SourceProcessId, &sourceProcess) ||
        !LookupProcessById(copyData.DestinationProcessId, &targetProcess))
    {
        if (sourceProcess)
            ObDereferenceObject(sourceProcess);
        if (targetProcess)
            ObDereferenceObject(targetProcess);

        guestContext->VpRegs->Rax = Shared::ErrorCodes::InvalidProcess;
        return;
    }

    const ULONG64 sourceDirectoryBase = Memory::GetDirectoryBase(sourceProcess);
    const ULONG64 targetDirectoryBase = Memory::GetDirectoryBase(targetProcess);

    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (sourceDirectoryBase != 0 && targetDirectoryBase != 0)
    {
        status = Memory::CopyProcessMemoryEx(
            processorIndex,
            sourceDirectoryBase, copyData.SourceAddress,
            targetDirectoryBase, copyData.DestinationAddress,
            copyData.NumberOfBytes);
    }

    ObDereferenceObject(sourceProcess);
    ObDereferenceObject(targetProcess);

    if (!NT_SUCCESS(status))
    {
        Hypervisor::LogNum("HandleCopyProcessMemory: copy failed", static_cast<unsigned long long>(status));
        guestContext->VpRegs->Rax = Shared::ErrorCodes::MemoryCopyFailTarget;
        return;
    }

    guestContext->VpRegs->Rax = Shared::ErrorCodes::Success;
}

void HandleProtectSelf(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    UNREFERENCED_PARAMETER(vpData);

    Hypervisor::Log("HandleProtectSelf: enter");

    const NTSTATUS status = SVM::ProtectSelf(vpData->HostStackLayout.SharedVpData);
    if (!NT_SUCCESS(status))
    {
        guestContext->VpRegs->Rax = 0xFFFF;
        return;
    }

    Hypervisor::Log("HandleProtectSelf: ProtectSelf ok, arming TlbControl");

    SVM::MarkControlAreaDirty(vpData->GuestVmcb.ControlArea);
    vpData->GuestVmcb.ControlArea.TlbControl = 1;

    guestContext->VpRegs->Rax = Shared::ErrorCodes::Success;
}

void HandleProtectRange(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    const ULONG64 virtualBase = guestContext->VpRegs->R8;
    const SIZE_T size = static_cast<SIZE_T>(guestContext->VpRegs->R9);

    Hypervisor::LogNum("HandleProtectRange: HideRange size", size);

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
    //
    // The hypercall interface is a user-mode contract: every command reads
    // or writes user memory, and the process lookup path requires PASSIVE
    // IRQL.  A VMMCALL from guest kernel code is not part of the interface
    // and must not be able to reach the copy path.
    //
    if (!IsInUserland(vpData) || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        guestContext->VpRegs->Rax = 0xFFFF;
        vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;
        return;
    }

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
