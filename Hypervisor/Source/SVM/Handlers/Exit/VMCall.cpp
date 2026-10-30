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
    Hypervisor::Log("HandleProtectSelf: enter");

    //
    // R8/R9 carry the image's executable range, [textBase, textBase +
    // textSize).  HideRange() leaves those pages mapped - hiding code the
    // driver itself executes in guest mode guarantees a permanent #NPF
    // supply.  Zero in either register means the caller has no executable
    // range to report and selects the legacy full-image hide.
    //
    const ULONG64 textBase = guestContext->VpRegs->R8;
    const SIZE_T textSize = static_cast<SIZE_T>(guestContext->VpRegs->R9);

    const NTSTATUS status = SVM::ProtectSelf(vpData->HostStackLayout.SharedVpData, textBase, textSize);
    if (!NT_SUCCESS(status))
    {
        guestContext->VpRegs->Rax = 0xFFFF;
        return;
    }

    Hypervisor::Log("HandleProtectSelf: ProtectSelf ok, arming TlbControl");

    SVM::MarkVmcbDirty(vpData->GuestVmcb.ControlArea);
    vpData->GuestVmcb.ControlArea.TlbControl = 1;

    guestContext->VpRegs->Rax = Shared::ErrorCodes::Success;
}

void HandleProtectRange(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    const ULONG64 virtualBase = guestContext->VpRegs->R8;
    const SIZE_T size = static_cast<SIZE_T>(guestContext->VpRegs->R9);

    Hypervisor::LogNum("HandleProtectRange: HideRange size", size);

    //
    // ProtectRange hides an arbitrary guest virtual range (the mapper's
    // HideMemory), so it has no executable section to preserve: 0/0 skips
    // nothing.
    //
    const NTSTATUS status = SVM::HideRange(vpData->HostStackLayout.SharedVpData, virtualBase, size, 0, 0);
    if (!NT_SUCCESS(status))
    {
        guestContext->VpRegs->Rax = 0xFFFF;
        return;
    }

    SVM::MarkVmcbDirty(vpData->GuestVmcb.ControlArea);
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

void HandleGetDriverInfo(const SVM::PVIRTUAL_PROCESSOR_DATA vpData, const SVM::PGUEST_CONTEXT guestContext)
{
    const UINT32 processorIndex = static_cast<UINT32>(vpData->HostStackLayout.ProcessorIndex);
    const ULONG64 userBuffer = guestContext->VpRegs->R8;

    //
    // R8 is the caller's user buffer that receives the DRIVER_INFO struct.
    // Validate it (user space, and leaving room for sizeof(DRIVER_INFO))
    // before the page walk, mirroring HandleCopyProcessMemory's checks.
    //
    if (!Utils::ValidUsermodeAddress(userBuffer) ||
        userBuffer > Global::HighestUserAddress - sizeof(Shared::DRIVER_INFO))
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

    //
    // Resolve the driver's own image base/size, then self-sufficiently parse
    // the driver's PE headers for its .text section (TextBase/TextSize).  On
    // parse failure the text range stays 0 (fail open).
    //
    ULONG64 driverBase = 0;
    SIZE_T driverSize = 0;
    if (!NT_SUCCESS(Utils::GetCurrentDriverInfo(&driverBase, &driverSize)))
    {
        Hypervisor::Log("HandleGetDriverInfo: driver info unavailable");
        guestContext->VpRegs->Rax = 0xFFFF;
        return;
    }

    Shared::DRIVER_INFO info;
    info.DriverBase = driverBase;
    info.DriverSize = driverSize;
    info.TextBase = 0;
    info.TextSize = 0;
#if HYPERVISOR_ENABLE_SELF_HIDE
    SVM::GetDriverTextRange(&info.TextBase, &info.TextSize);
#endif

    SIZE_T bytesWritten = 0;
    const NTSTATUS writeStatus = Memory::WriteProcessMemoryEx(
        processorIndex, currentDirectoryBase, userBuffer,
        &info, sizeof(info), &bytesWritten);
    if (!NT_SUCCESS(writeStatus) || bytesWritten != sizeof(info))
    {
        Hypervisor::LogNum("HandleGetDriverInfo: write failed", static_cast<unsigned long long>(writeStatus));
        guestContext->VpRegs->Rax = 0xFFFF;
        return;
    }

    Hypervisor::LogNum("HandleGetDriverInfo: wrote DriverBase", driverBase);
    guestContext->VpRegs->Rax = Shared::ErrorCodes::Success;
}

void SVM::HandleVMCall(const PVIRTUAL_PROCESSOR_DATA vpData, const PGUEST_CONTEXT guestContext)
{
    //
    // 1. Validate the magic (RCX per the VMCALL ABI). A VMMCALL that is not
    // the intended hyper interface must fault with #UD (AMD APM 24593, p.20).
    //
    const ULONG64 magic = guestContext->VpRegs->Rcx;
    if (magic != Shared::MAGIC)
    {
        //
        // #UD is a fault, not a trap: the guest's handler must see RIP at the
        // VMMCALL, which is what the VMCB already holds after #VMEXIT.  Do
        // NOT copy NRip here - advancing RIP and injecting #UD at the same
        // time delivers the exception at the wrong instruction.
        //
        InjectUndefinedOpcodeException(vpData);
        return;
    }

    const ULONG64 command = guestContext->VpRegs->Rdx;

    if (command == Shared::CheckPresence)
    {
        //
        // CheckPresence is a read-only probe that returns the constant
        // COMM_CHECK. It exists so a kernel-mode loader (Mapper, running at
        // CPL0) can detect whether a hypervisor is already installed without
        // tripping the #UD injection that other non-CPL3 calls cause. The
        // magic gate above still applies; only a caller that knows the magic
        // can invoke CheckPresence from ring 0. No state is mutated.
        //
        HandleCheckPresence(vpData, guestContext);
        vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;
        return;
    }

    //
    // 2. Every other command reads or writes user memory and (the process
    // lookup path) requires PASSIVE IRQL. A VMMCALL from guest kernel code is
    // not part of the user-mode contract and must fault with #UD rather than
    // reach the copy path.
    //
    if (!IsInUserland(vpData) || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        //
        // Same fault semantics as above: the injected #UD must be delivered
        // at the VMMCALL, so RIP stays where #VMEXIT left it.
        //
        InjectUndefinedOpcodeException(vpData);
        return;
    }

    //
    // 3. Normal dispatch for the CPL3 + PASSIVE commands.
    //
    switch (command)
    {
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
    case Shared::GetDriverInfo:
        HandleGetDriverInfo(vpData, guestContext);
        break;
    default:
        HandleInvalid(vpData, guestContext);
        break;
    }

    vpData->GuestVmcb.StateSaveArea.Rip = vpData->GuestVmcb.ControlArea.NRip;
}
