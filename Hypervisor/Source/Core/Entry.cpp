#include "Global.h"
#include "../Common/HVLogs.h"

bool Utils::GetOffsets()
{
    UNICODE_STRING stringPsGetProcessId;
    RtlInitUnicodeString(&stringPsGetProcessId, L"PsGetProcessId");

    BYTE* routinePsGetProcessId = static_cast<BYTE*>(MmGetSystemRoutineAddress(&stringPsGetProcessId));
    if (!routinePsGetProcessId)
        return false;

    //
    // PsGetProcessId proc near
    // mov rax, [rcx + <disp32>]
    // 48 8B 81 (xx xx xx xx)
    // VOID* UniqueProcessId;
    // struct _LIST_ENTRY ActiveProcessLinks;
    //
    // Validate the opcode before trusting the displacement: if Microsoft
    // ever changes the prologue the defaults stay untouched instead of
    // loading garbage into the offsets.
    if (routinePsGetProcessId[0] != 0x48 ||
        routinePsGetProcessId[1] != 0x8B ||
        routinePsGetProcessId[2] != 0x81)
    {
        return false;
    }

    const UINT32 uniqueProcessId =
        *reinterpret_cast<UINT32*>(routinePsGetProcessId + 3);

    //
    // Sanity-check the resolved offset: EPROCESS is a few kilobytes and
    // both fields sit well inside it.
    if (uniqueProcessId == 0 || uniqueProcessId > 0x1000)
        return false;

    Global::Offsets::UniqueProcessId = uniqueProcessId;
    Global::Offsets::ActiveProcessLinks = uniqueProcessId + 8;

    //
    // DirectoryTableBase: instead of trusting a hardcoded offset, derive it
    // from this exact kernel build. Attach to the always-alive System
    // process, read the CR3 the CPU is actually running on, then scan the
    // EPROCESS image for the field holding that same physical page. AMD does
    // not use KVA-shadow CR3 flipping, so the attached CR3 is the process
    // directory base itself; PCID bits are masked out.
    //
    const PEPROCESS systemProcess = PsInitialSystemProcess;
    if (systemProcess)
    {
        KAPC_STATE apcState;
        KeStackAttachProcess(systemProcess, &apcState);

        const ULONG64 liveDirectoryBase = __readcr3() & 0x000FFFFFFFFFF000;

        KeUnstackDetachProcess(&apcState);

        if (liveDirectoryBase)
        {
            const PULONG64 fields = reinterpret_cast<PULONG64>(systemProcess);

            for (UINT32 offset = 0; offset < 0x800; offset += sizeof(ULONG64))
            {
                const ULONG64 value = fields[offset / sizeof(ULONG64)];

                if (value != 0 &&
                    (value & 0x000FFFFFFFFFF000) == liveDirectoryBase &&
                    value < 0x0000800000000000) // physical addresses stay far below the canonical split
                {
                    Global::Offsets::DirectoryTableBase = offset;
                    break;
                }
            }
        }
    }

    //
    // Both fields are mandatory: without DirectoryTableBase every later
    // read would use offset 0 of the EPROCESS (the first 8 bytes of the
    // object) as a CR3, and without ActiveProcessLinks the process walk
    // would follow the wrong list.
    //
    if (Global::Offsets::UniqueProcessId == 0 ||
        Global::Offsets::ActiveProcessLinks == 0 ||
        Global::Offsets::DirectoryTableBase == 0)
    {
        return false;
    }

    return true;
}

NTSTATUS PreallocatePools()
{
    for (UINT32 i = 0; i < ARRAYSIZE(Global::PreallocatedPools); i++)
    {
        Global::PreallocatedPools[i] = Utils::AllocatePageAligned(Utils::PreallocatedPoolSize);
        if (!Global::PreallocatedPools[i])
            return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

EXTERN_C NTSTATUS Entry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    //
    // Fail closed unless the caller is at PASSIVE_LEVEL.  Everything below
    // assumes it: PsCreateSystemThread() must be called at PASSIVE_LEVEL, and
    // KeWaitForSingleObject() on a non-signaled event at DISPATCH_LEVEL is a
    // bugcheck/hang rather than a wait.  An external mapper is free to invoke
    // DriverEntry from a raised IRQL, in which case the load would freeze
    // instead of failing - so refuse it before the first allocation or log
    // write.  The real loader always calls at PASSIVE_LEVEL.
    //
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    //
    // Start the log flusher (debug builds only; a production build no-ops).
    //
    Hypervisor::StartLogFlusher();

    Hypervisor::Log("Entry: start");

    //
    // Drain synchronously once, right now.  The file channel is created
    // write-through, so from this point on the trail is on disk as it
    // happens - it survives even an instant hard freeze, and a broken file
    // channel shows up as a missing file immediately instead of only after
    // the next freeze.  (The flusher thread sleeps before its first drain,
    // so the two writers do not overlap.)
    //
    Hypervisor::FlushToFile();

    //
    // Record the image range this driver is actually resident at.  The loader
    // and the mapper both pass a DRIVER_OBJECT describing it; the mapper
    // strips the PE header, so __ImageBase points one page before the
    // allocation and is only a last-resort fallback for a caller that passes
    // no object at all.
    //
    // The first argument is not always an object: a manual mapper run with
    // "pass the allocation base" hands the image base over instead.  Reading
    // DriverStart/DriverSize out of raw image bytes would produce a garbage
    // range that later looks like a valid one, so the pointer is validated as
    // a DRIVER_OBJECT before it is trusted.
    //
    // Bound the accepted range as well: a caller that hands over an
    // unrelated object of the right type would otherwise supply an
    // arbitrarily large DriverSize, and ProtectSelf() would walk it.  The
    // real loader always reports a kernel VA with SizeOfImage well under
    // 16 MB, so both checks are free for it and fail closed here.
    //
    if (DriverObject != nullptr &&
        DriverObject->Type == IO_TYPE_DRIVER &&
        DriverObject->DriverStart != nullptr &&
        DriverObject->DriverSize != 0 &&
        DriverObject->DriverSize <= 0x1000000UL &&
        reinterpret_cast<ULONG64>(DriverObject->DriverStart) >= 0xFFFF800000000000ULL)
    {
        Global::DriverBase = reinterpret_cast<ULONG64>(DriverObject->DriverStart);
        Global::DriverSize = DriverObject->DriverSize;
    }
    else
    {
        //
        // Last resort: read the image's own headers.  Only meaningful when
        // the PE header was not stripped; the size stays zero otherwise, so
        // GetCurrentDriverInfo() still refuses the range.
        //
        Global::DriverBase = reinterpret_cast<ULONG64>(&__ImageBase);

        if (__ImageBase.e_magic == IMAGE_DOS_SIGNATURE)
        {
            const PIMAGE_NT_HEADERS64 headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(
                Global::DriverBase + __ImageBase.e_lfanew);

            if (headers->Signature == IMAGE_NT_SIGNATURE)
                Global::DriverSize = headers->OptionalHeader.SizeOfImage;
        }
    }

    //
    // Resolve the EPROCESS layout for this exact kernel build first, so
    // every later consumer (process walk, CR3 resolution) uses dynamic
    // offsets instead of hardcoded ones.
    //
    if (!Utils::GetOffsets())
        return STATUS_PROCEDURE_NOT_FOUND;

    Global::Offsets::Resolved = true;

    Hypervisor::Log("Entry: GetOffsets ok");

    //
    // Cache the machine's RAM ranges while still at PASSIVE_LEVEL, before any
    // #VMEXIT can run the copy path.  That path validates every physical
    // address it touches against this cache and must not resolve anything
    // itself.  A failure is not fatal for the driver: the cache stays
    // unusable and every physical access is then refused (fail closed).
    //
    Utils::InitPhysicalMemoryRanges();

    //
    // Read the user/kernel boundary from this kernel's MmHighestUserAddress
    // export (64-bit user space on this Win11 24H2 build).
    //
    Global::HighestUserAddress = reinterpret_cast<ULONG64>(MmHighestUserAddress);

    //
    // Resolve the MSR permission-map geometry for this CPU from CPUID
    // Fn8000_000A (Zen 2, Ryzen 7 4800H).
    //
    Utils::InitMsrRanges();

    Hypervisor::Log("Entry: init ranges ok");

    if (!Memory::PreparePages())
        return STATUS_INSUFFICIENT_RESOURCES;

    Hypervisor::Log("Entry: PreparePages ok");

    NTSTATUS status = SVM::CheckSupport();
    if (!NT_SUCCESS(status))
        return status;

    Hypervisor::Log("Entry: CheckSupport ok");

    status = PreallocatePools();
    if (!NT_SUCCESS(status))
        return status;

    Hypervisor::Log("Entry: PreallocatePools ok");

    Global::BlankPage = Utils::AllocatePageAligned(PAGE_SIZE);
    if (!Global::BlankPage)
        return STATUS_INSUFFICIENT_RESOURCES;

    //
    // Arm the readiness event before the thread exists, so the thread can
    // never signal an uninitialized event and never sees a stale status.
    //
    KeInitializeEvent(&Global::VirtualizationReady, NotificationEvent, FALSE);
    Global::VirtualizationStatus = STATUS_PENDING;

    HANDLE threadHandle;
    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr, SVM::VirtualizeAllProcessors, nullptr);
    if (!NT_SUCCESS(status))
        return status;

    Hypervisor::Log("Entry: thread created, waiting for virtualization");

    //
    // Do not wait on the thread object: once the last CPU has been
    // virtualized the thread keeps running in guest mode, so its lifetime is
    // not a usable completion signal.  The event is.  The handle is closed
    // either way; the thread object itself stays alive until the thread
    // terminates.
    //
    LARGE_INTEGER timeout;
    timeout.QuadPart = -30 * 1000 * 1000 * 10LL; // 30 seconds, relative

    status = KeWaitForSingleObject(&Global::VirtualizationReady, Executive, KernelMode, FALSE, &timeout);

    Hypervisor::LogNum("Entry: wait status", status);

    //
    // The virtualization outcome is the last milestone Entry() logs; make
    // sure it is on disk before returning into the mapper's flow.
    //
    Hypervisor::FlushToFile();

    const NTSTATUS virtualizationStatus = Global::VirtualizationStatus;

    ZwClose(threadHandle);

    if (status == STATUS_TIMEOUT)
        return STATUS_TIMEOUT;

    if (!NT_SUCCESS(status))
        return status;

    //
    // Best-effort self-hide: the VirtualizationReady event fires only after
    // every CPU has been virtualized, so now is the moment to hide the
    // driver's own image (minus its .text) from the guest's nested page
    // tables.  A failure here is logged and the load continues - a
    // functional hypervisor beats a failed load.
    //
    // The shared per-CPU state is not a Global::SharedData field; it is
    // reached through Global::VirtualizedCpus: each slot is a
    // SVM::PVIRTUAL_PROCESSOR_DATA whose HostStackLayout.SharedVpData points at
    // the one SVM::SHARED_VIRTUAL_PROCESSOR_DATA that VirtualizeAllProcessors()
    // allocates.  Slot 0 is the first CPU's record.
    //
    SVM::PSHARED_VIRTUAL_PROCESSOR_DATA sharedData = nullptr;
    if (Global::VirtualizedCpus)
    {
        //
        // Slot 0 can be null when the first CPU failed before publishing its
        // vpData (CheckAndSetInstalled() allocation failure); dereferencing it
        // blindly would bugcheck the machine on a path that is already
        // handling an error.
        //
        const SVM::PVIRTUAL_PROCESSOR_DATA firstCpu =
            reinterpret_cast<SVM::PVIRTUAL_PROCESSOR_DATA*>(Global::VirtualizedCpus)[0];
        if (firstCpu)
            sharedData = firstCpu->HostStackLayout.SharedVpData;
    }

    if (sharedData)
    {
        const NTSTATUS hideStatus = SVM::ProtectSelf(sharedData, 0, 0);
        if (!NT_SUCCESS(hideStatus))
            Hypervisor::LogNum("Entry: ProtectSelf failed; continuing (best-effort hide)", hideStatus);
        else
            Hypervisor::Log("Entry: ProtectSelf complete");
    }

    return virtualizationStatus;
}