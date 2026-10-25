#include "../Global.h"
#include "../HVLog.h"

NTSTATUS SVM::CheckSupport()
{
    int registers[4];

    //
    // If a hypervisor is already resident (EFER.SVME set by a previous run that
    // never cleaned up), the CPUs are already running as guests. LaunchVM-ing a
    // second time rewrites their host state save area and triple-faults, so
    // refuse cleanly instead of corrupting the machine and freezing it.
    //
    if (__readmsr(IA32_MSR_EFER) & EFER_SVME)
        return STATUS_HV_INVALID_DEVICE_STATE;

    __cpuid(registers, CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING);
    if ((registers[1] != 'htuA') ||
        (registers[3] != 'itne') ||
        (registers[2] != 'DMAc'))
        return STATUS_HV_INVALID_DEVICE_ID;

    __cpuid(registers, CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX);
    if (!(registers[2] & CPUID_FN8000_0001_ECX_SVM))
        return STATUS_HV_CPUID_FEATURE_VALIDATION_ERROR;

    __cpuid(registers, CPUID_SVM_FEATURES);
    if (!(registers[3] & CPUID_FN8000_000A_EDX_NP))
        return STATUS_HV_CPUID_FEATURE_VALIDATION_ERROR;

    const ULONG64 vmcr = __readmsr(SVM_MSR_VM_CR);
    if (vmcr & SVM_VM_CR_SVMDIS)
        return STATUS_HV_INVALID_DEVICE_STATE;

    return STATUS_SUCCESS;
}

void SVM::BuildNestedPageTables(const PSHARED_VIRTUAL_PROCESSOR_DATA sharedData)
{
    //
    // Map the complete 48-bit guest-physical address space 1:1 to host
    // physical addresses with 1 GB pages: 512 PML4 entries, each pointing at
    // a 4 KB PDPT page holding 512 1 GB entries (512 * 4 KB = 2 MB of PDPT
    // pages).  Covering less leaves guest GPAs without an NPT entry, and an
    // NPF has no recovery path - it would bugcheck.
    //
    // Note that the arrays must be zeroed beyond the entries filled in here:
    // the CPU walks all 512 entries of the PML4 page, and the PML4 is only
    // sizeof(PML4E_64) * 512 = 4 KB in total.
    //
    constexpr ULONG64 pml4EntryCount = 512;
    constexpr ULONG64 pdpEntryCount = 512;

    sharedData->Pml4Entries = static_cast<PML4E_64*>(Utils::AllocatePageAligned(PAGE_SIZE));
    sharedData->PdpEntries = static_cast<PDPTE_1GB(*)[512]>(Utils::AllocatePageAligned(sizeof(PDPTE_1GB) * pdpEntryCount * pml4EntryCount));

    for (ULONG64 pml4Index = 0; pml4Index < pml4EntryCount; pml4Index++)
    {
        const ULONG64 pdpBasePa = MmGetPhysicalAddress(&sharedData->PdpEntries[pml4Index]).QuadPart;
        sharedData->Pml4Entries[pml4Index].Present = 1;
        sharedData->Pml4Entries[pml4Index].Write = 1;
        sharedData->Pml4Entries[pml4Index].Supervisor = 1;
        sharedData->Pml4Entries[pml4Index].PageFrameNumber = pdpBasePa >> PAGE_SHIFT;

        for (ULONG64 pdpIndex = 0; pdpIndex < pdpEntryCount; pdpIndex++)
        {
            const ULONG64 translationPa = (pml4Index * 512ULL + pdpIndex);
            sharedData->PdpEntries[pml4Index][pdpIndex].Present = 1;
            sharedData->PdpEntries[pml4Index][pdpIndex].Write = 1;
            sharedData->PdpEntries[pml4Index][pdpIndex].Supervisor = 1;
            sharedData->PdpEntries[pml4Index][pdpIndex].LargePage = 1;
            sharedData->PdpEntries[pml4Index][pdpIndex].PageFrameNumber = translationPa;
        }
    }
}

#if SVM_ENABLE_SELF_HIDE
namespace SVM
{
namespace
{
    PVOID PhysicalToVirtual(const ULONG64 physicalAddress)
    {
        PHYSICAL_ADDRESS address;
        address.QuadPart = static_cast<LONGLONG>(physicalAddress);
        return MmGetVirtualForPhysical(address);
    }

    //
    // Returns the 4 KB page table backing the 2 MB region
    // [pml4Index][pdpIndex][pdIndex], splitting the 1 GB and 2 MB large
    // pages on the way down.  Every table comes from the boot-time pool so
    // that no allocation happens inside the VMEXIT handler.
    //
    PT_ENTRY_4KB* GetOrSplitPageTable(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, const ULONG64 pml4Index, const ULONG64 pdpIndex, const ULONG64 pdIndex)
    {
        const ULONG64 pdBase = (pml4Index * 512ULL + pdpIndex) * PAGE_SIZE_1GB;

        PDPTE_1GB* pdpte = &sharedData->PdpEntries[pml4Index][pdpIndex];
        if (pdpte->LargePage)
        {
            PD_ENTRY_2MB* newPdTable = static_cast<PD_ENTRY_2MB*>(Utils::GetPreallocatedPool(sizeof(PD_ENTRY_2MB) * 512));
            if (!newPdTable)
                return nullptr;

            for (ULONG64 pdEntry = 0; pdEntry < 512; pdEntry++)
            {
                newPdTable[pdEntry].Present = 1;
                newPdTable[pdEntry].Write = 1;
                newPdTable[pdEntry].Supervisor = 1;
                newPdTable[pdEntry].LargePage = 1;
                newPdTable[pdEntry].PageFrameNumber = (pdBase + pdEntry * PAGE_SIZE_2MB) >> PD_PAGE_SHIFT;
            }

            PDPTE_2MB splitEntry;
            splitEntry.AsUInt = pdpte->AsUInt;
            splitEntry.LargePage = 0;
            splitEntry.Reserved2 = 0;
            splitEntry.PageFrameNumber = MmGetPhysicalAddress(newPdTable).QuadPart >> PAGE_SHIFT;

            InterlockedExchange64(
                reinterpret_cast<volatile LONGLONG*>(&pdpte->AsUInt),
                static_cast<LONGLONG>(splitEntry.AsUInt)
            );
        }

        //
        // A split PDPT entry holds a 36-bit PFN, which only the 4 KB view of
        // the entry (PDPTE_2MB) can represent - PDPTE_1GB truncates it to
        // 18 bits.
        //
        const PDPTE_2MB* splitPdpte = reinterpret_cast<const PDPTE_2MB*>(pdpte);
        PDE_4KB* pd = static_cast<PDE_4KB*>(PhysicalToVirtual(static_cast<ULONG64>(splitPdpte->PageFrameNumber) << PAGE_SHIFT));
        if (!pd)
            return nullptr;

        PDE_4KB* pde = &pd[pdIndex];
        if (pde->LargePage)
        {
            PT_ENTRY_4KB* newPtTable = static_cast<PT_ENTRY_4KB*>(Utils::GetPreallocatedPool(sizeof(PT_ENTRY_4KB) * 512));
            if (!newPtTable)
                return nullptr;

            const ULONG64 ptBase = pdBase + pdIndex * PAGE_SIZE_2MB;
            for (ULONG64 ptEntry = 0; ptEntry < 512; ptEntry++)
            {
                newPtTable[ptEntry].Present = 1;
                newPtTable[ptEntry].Write = 1;
                newPtTable[ptEntry].Supervisor = 1;
                newPtTable[ptEntry].PageFrameNumber = (ptBase + ptEntry * PAGE_SIZE_4KB) >> PAGE_SHIFT;
            }

            //
            // Publish the finished entry with one 64-bit store.  Writing
            // the fields one at a time leaves a window where another CPU
            // walking this 2 MB region sees Present=1 with a PFN of 0 and
            // translates it to physical 0.
            //
            PDE_4KB splitPde = {};
            splitPde.Present = 1;
            splitPde.Write = 1;
            splitPde.Supervisor = 1;
            splitPde.PageFrameNumber = (MmGetPhysicalAddress(newPtTable).QuadPart & ~0xFFFull) >> PAGE_SHIFT;

            InterlockedExchange64(
                reinterpret_cast<volatile LONGLONG*>(&pde->AsUInt),
                static_cast<LONGLONG>(splitPde.AsUInt)
            );
        }

        return static_cast<PT_ENTRY_4KB*>(PhysicalToVirtual(static_cast<ULONG64>(pde->PageFrameNumber) << PAGE_SHIFT));
    }
}
}
#endif

SVM::PT_ENTRY_4KB* SVM::GetPageTableEntry(const SVM::PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, const ULONG64 physical)
{
#if SVM_ENABLE_SELF_HIDE
    return GetOrSplitPageTable(
        sharedData,
        physical >> PML4_PAGE_SHIFT,
        (physical >> PDP_PAGE_SHIFT) & INDEX_MASK,
        (physical >> PD_PAGE_SHIFT) & INDEX_MASK);
#else
    UNREFERENCED_PARAMETER(sharedData);
    UNREFERENCED_PARAMETER(physical);

    return nullptr;
#endif
}

bool SVM::RestoreHiddenPage(const PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, const ULONG64 gpa)
{
#if SVM_ENABLE_SELF_HIDE
    PT_ENTRY_4KB* entry = GetPageTableEntry(sharedData, gpa);
    if (!entry || entry->Present)
        return false;

    //
    // HideRange() cleared only the Present bit, leaving the real PFN and Write
    // flag intact, so restoring is one atomic Present set.
    //
    InterlockedExchange64(reinterpret_cast<volatile LONGLONG*>(&entry->AsUInt64), entry->AsUInt64 | 1);
    return true;
#else
    UNREFERENCED_PARAMETER(sharedData);
    UNREFERENCED_PARAMETER(gpa);

    return false;
#endif
}

void SVM::TrackForRehide(const PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, SVM::PT_ENTRY_4KB* entry)
{
#if SVM_ENABLE_SELF_HIDE
    if (!entry)
        return;

    //
    // Best-effort, race-tolerant: a clobbered or overflowed slot simply leaves
    // its page mapped (a small stealth loss), never a correctness failure.
    //
    const LONG slot = InterlockedIncrement(&sharedData->NptRehideIndex) & (NPT_REHIDE_CAPACITY - 1);
    sharedData->NptRehide[slot] = entry;
    sharedData->NptRehideRestoreExit[slot] = sharedData->NptExitCounter;
#else
    UNREFERENCED_PARAMETER(sharedData);
    UNREFERENCED_PARAMETER(entry);
#endif
}

NTSTATUS SVM::HideRange(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, const ULONG64 virtualBase, const SIZE_T size)
{
#if SVM_ENABLE_SELF_HIDE
    HV::LogNum("HideRange: enter, size", size);

    const ULONG64 pageMask = ~(static_cast<ULONG64>(PAGE_SIZE) - 1);
    const ULONG64 blankPagePhysical = MmGetPhysicalAddress(Global::BlankPage).QuadPart & pageMask;

    //
    // Pages that must keep their real mapping: the NPT root and its PDPT
    // array, the MSR permission map, and the preallocated split tables
    // themselves.  The page holding this code is not among them - the handler
    // runs on the host CR3, not through the NPT, so blanking its guest
    // mapping hides a full .text page without affecting the handler.
    //
    const ULONG64 pml4Physical = MmGetPhysicalAddress(sharedData->Pml4Entries).QuadPart;
    const ULONG64 pdpPhysical = MmGetPhysicalAddress(sharedData->PdpEntries).QuadPart;
    const ULONG64 pdpSize = sizeof(PDPTE_1GB) * 512 * 512;
    const ULONG64 msrpmPhysical = MmGetPhysicalAddress(sharedData->MsrPermissionsMap).QuadPart;

    ULONG64 poolPhysical[ARRAYSIZE(Global::PreallocatedPools)] = { 0 };
    for (SIZE_T poolIndex = 0; poolIndex < ARRAYSIZE(Global::PreallocatedPools); poolIndex++)
    {
        if (Global::PreallocatedPools[poolIndex])
            poolPhysical[poolIndex] = MmGetPhysicalAddress(Global::PreallocatedPools[poolIndex]).QuadPart & pageMask;
    }

    bool found = false;

    //
    // Set when a page in the range is already not-present - i.e. a previous
    // HideRange() (typically ProtectSelf(), which the mapper follows with a
    // HideMemory() call covering the same allocation) already hid it.  That
    // is the requested end state, so it counts as success below instead of
    // collapsing into "nothing found".
    //
    bool alreadyHidden = false;

    //
    // Walk the range one virtual page at a time.  A PE image is not
    // physically contiguous, so a linear [base, base + size) sweep over the
    // physical addresses would blank unrelated kernel allocations that
    // happened to live in that physical range.  Only the PFN behind each
    // virtual page is blanked here; a PFN reached twice is skipped (dedupe),
    // so hiding overlapping ranges is harmless.
    //
    // The size is an allocation size, which
    // need not be a multiple of PAGE_SIZE - and neither does the base need to
    // be page aligned.  Round the range *inward*, so that only pages lying
    // entirely inside [base, base + size) are hidden.
    //
    // A manually mapped image comes from ExAllocatePoolWithTag, which only
    // guarantees 16-byte alignment: the page containing the base also holds
    // the POOL_HEADER in front of the allocation, and the page containing the
    // end holds the first bytes of the next pool block.  Blanking either one
    // gives the guest's allocator a page whose header reads as zeros, which it
    // turns into an arbitrary write on the next free/coalesce.
    //
    const ULONG64 firstPage = (virtualBase + PAGE_SIZE - 1) & pageMask;
    const ULONG64 endPage = (virtualBase + size) & pageMask;

    //
    // Nothing is fully contained in the range (smaller than a page, or
    // misaligned on both ends).  Report it rather than hiding a page that also
    // holds data this caller does not own.
    //
    if (endPage <= firstPage)
        return STATUS_NOT_FOUND;

    for (ULONG64 pageVirtual = firstPage; pageVirtual < endPage; pageVirtual += PAGE_SIZE)
    {
        const ULONG64 pagePhysical = MmGetPhysicalAddress(reinterpret_cast<PVOID>(pageVirtual)).QuadPart & pageMask;

        //
        // A page with no physical backing is not part of the resident image
        // (or the base/size are wrong).  Skipping it keeps one unmapped page
        // from turning the whole hide into a bugcheck.
        //
        if (pagePhysical == 0)
            continue;

        if (pagePhysical == blankPagePhysical)
            continue;

        if (pagePhysical >= pml4Physical && pagePhysical < pml4Physical + PAGE_SIZE)
            continue;

        if (pagePhysical >= pdpPhysical && pagePhysical < pdpPhysical + pdpSize)
            continue;

        if (pagePhysical >= msrpmPhysical && pagePhysical < msrpmPhysical + Global::MsrPermissionsMapSize)
            continue;

        bool isPoolPage = false;
        for (SIZE_T poolIndex = 0; poolIndex < ARRAYSIZE(Global::PreallocatedPools); poolIndex++)
        {
            if (pagePhysical == poolPhysical[poolIndex])
            {
                isPoolPage = true;
                break;
            }
        }
        if (isPoolPage)
            continue;

        PT_ENTRY_4KB* pageTable = GetOrSplitPageTable(
            sharedData,
            pagePhysical >> PML4_PAGE_SHIFT,
            (pagePhysical >> PDP_PAGE_SHIFT) & INDEX_MASK,
            (pagePhysical >> PD_PAGE_SHIFT) & INDEX_MASK);
        if (!pageTable)
            return STATUS_NOT_FOUND;

        PT_ENTRY_4KB* pageTableEntry = &pageTable[(pagePhysical >> PAGE_SHIFT) & INDEX_MASK];
        if (pageTableEntry->Present == 0)
        {
            alreadyHidden = true;
            continue;
        }

        //
        // Clear ONLY the Present bit and leave the real PFN and Write flag in
        // the entry.  The page becomes not-present in the NPT, so any guest
        // access raises a nested page fault that RestoreHiddenPage() resolves
        // by setting Present again (a transparent restore: no #PF is injected,
        // so the guest never observes it).  Blanking the PFN to the shared
        // BlankPage would instead make reads return zeros, which the guest
        // executes as garbage and hangs the machine.
        //
        InterlockedExchange64(reinterpret_cast<volatile LONGLONG*>(&pageTableEntry->AsUInt64),
            pageTableEntry->AsUInt64 & ~1ULL);
        found = true;
    }

    //
    // Nothing in range could be hidden and nothing was already hidden: the
    // base/size handed in do not describe a resident image.  Report it to the
    // client rather than bugchecking the guest on a bad range.  A range whose
    // pages are all already hidden is a success - that is the state the
    // caller asked for (the mapper hides the resident allocation right after
    // ProtectSelf() covered the same pages).
    //
    if (!found && !alreadyHidden)
        return STATUS_NOT_FOUND;

    //
    // The rewrite above is shared by every vCPU (one NPT root, one PDPT
    // array), but only this CPU's VMCB is guaranteed to be looked at again
    // with the new state in mind.  Publish it:
    //
    //   - The generation increment is the release that orders it after every
    //     NPT entry store.  On x86 the plain entry stores cannot be observed
    //     after the locked increment, and the increment is what HandleExit()
    //     compares against, so a vCPU that reads the new generation has also
    //     read the new entries.
    //   - TlbControl = 1 in every registered VMCB makes the flush happen at
    //     that CPU's next VMRUN.  InterlockedExchange (not a plain store)
    //     keeps the store from being reordered with the NPT writes above.
    //
    // This CPU's own VMCB is included; HandleProtectSelf() sets TlbControl
    // again, which is harmless (the field is a write-1-to-flush command).
    //
    InterlockedIncrement(&sharedData->NptFlushGeneration);

    PVIRTUAL_PROCESSOR_DATA* const virtualizedCpus = reinterpret_cast<PVIRTUAL_PROCESSOR_DATA*>(Global::VirtualizedCpus);
    if (virtualizedCpus)
    {
        for (ULONG cpuIndex = 0; cpuIndex < Global::VirtualizedCpuCount; cpuIndex++)
        {
            const PVIRTUAL_PROCESSOR_DATA cpu = virtualizedCpus[cpuIndex];
            if (!cpu)
                continue;

            InterlockedExchange(reinterpret_cast<volatile LONG*>(&cpu->GuestVmcb.ControlArea.TlbControl), 1);
            MarkControlAreaDirty(cpu->GuestVmcb.ControlArea);
        }
    }

    HV::Log("HideRange: done");

    return STATUS_SUCCESS;
#else
    //
    // Self-hide is disabled (SVM_ENABLE_SELF_HIDE == 0, see Global.h): every
    // NPT entry keeps its real mapping, so guest-mode access to the hidden
    // ranges keeps working.  The command still reports success to the client.
    //
    UNREFERENCED_PARAMETER(sharedData);
    UNREFERENCED_PARAMETER(virtualBase);
    UNREFERENCED_PARAMETER(size);

    return STATUS_SUCCESS;
#endif
}

NTSTATUS SVM::ProtectSelf(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData)
{
#if SVM_ENABLE_SELF_HIDE
    HV::Log("ProtectSelf: enter");

    //
    // ProtectSelf is a one-shot, system-wide operation; make the
    // check-and-set atomic so two CPUs cannot split the NPT concurrently.
    //
    static volatile LONG alreadyProtected = 0;
    if (InterlockedCompareExchange(&alreadyProtected, 1, 0) != 0)
        return STATUS_SUCCESS;

    ULONG64 driverVirtualBase = 0;
    SIZE_T driverSize = 0;
    const NTSTATUS status = Utils::GetCurrentDriverInfo(&driverVirtualBase, &driverSize);
    if (!NT_SUCCESS(status))
    {
        //
        // With the mapper's header stripping __ImageBase sits outside the
        // allocation, so this is a normal, expected failure - report it
        // instead of bugchecking the guest.  The one-shot flag is released so
        // a retry with a valid range still does the work instead of being
        // answered with a stale success.
        //
        InterlockedExchange(&alreadyProtected, 0);

        return status;
    }

    HV::LogNum("ProtectSelf: HideRange base, size", driverSize);

    const NTSTATUS result = HideRange(sharedData, driverVirtualBase, driverSize);

    HV::LogNum("ProtectSelf: HideRange result", result);

    if (!NT_SUCCESS(result))
        InterlockedExchange(&alreadyProtected, 0);

    return result;
#else
    UNREFERENCED_PARAMETER(sharedData);

    return STATUS_SUCCESS;
#endif
}

void SVM::BuildPermissionMap(const PVOID permissionMap)
{
    static const UINT32 BITS_PER_MSR = 2;
    static const UINT32 SECOND_MSR_RANGE_BASE = 0xc0000000;

    //
    // AMD APM Vol. 2 ("MSR Intercepts"): the MSRPM is 8 KB, made of four
    // 2 KB ranges of 8192 MSRs each, with the LSB of each 2-bit pair
    // controlling reads and the MSB controlling writes:
    //
    //   range 0 - 0x00000000-0x00001FFF  -> byte offset 0x0000
    //   range 1 - 0xC0000000-0xC0001FFF  -> byte offset 0x0800
    //   range 2 - 0xC0010000-0xC0011FFF  -> byte offset 0x1000
    //   range 3 - reserved               -> byte offset 0x1800
    //
    // EFER (0xC0000080) therefore lives at bit 0x800 * 8 + 0x80 * 2 = 0x4100,
    // and its write-intercept bit is 0x4101.
    //
    static const UINT32 SECOND_MSRPM_OFFSET = 0x800 * CHAR_BIT;

    RTL_BITMAP bitmapHeader;
    RtlInitializeBitMap(&bitmapHeader, static_cast<PULONG>(permissionMap), static_cast<ULONG>(Global::MsrPermissionsMapSize * CHAR_BIT));
    RtlClearAllBits(&bitmapHeader);

    const ULONG offsetFrom2ndBase = (IA32_MSR_EFER - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR;
    const ULONG offset = SECOND_MSRPM_OFFSET + offsetFrom2ndBase;

    //
    // Both bits of each MSRPM pair are set (LSB read, MSB write): reads and
    // writes alike must exit.  The read intercept is what hides the
    // hypervisor - a guest reading EFER gets SVME masked, and reads of
    // VM_CR / VM_HSAVE_PA get zero instead of the host state area's
    // physical address (see HandleMSRAccess).
    //
    RtlSetBits(&bitmapHeader, offset, 2);

    //
    // Intercept reads and writes to the two MSRs that control the
    // hypervisor itself (VM_CR carries SVMDIS, VM_HSAVE_PA points at the
    // host state save area).  Without an intercept bit the CheckMSR() hard
    // block in HandleMSRAccess would never run, because the access would go
    // straight to the CPU.  Both live in the 0xC0010000 range, which starts
    // at map offset 0x1000.
    //
    static const UINT32 THIRD_MSR_RANGE_BASE = 0xc0010000;
    static const UINT32 THIRD_MSRPM_OFFSET = 0x1000 * CHAR_BIT;

    const ULONG vmCrOffset = THIRD_MSRPM_OFFSET + (SVM_MSR_VM_CR - THIRD_MSR_RANGE_BASE) * BITS_PER_MSR;
    const ULONG vmHsavePaOffset = THIRD_MSRPM_OFFSET + (SVM_MSR_VM_HSAVE_PA - THIRD_MSR_RANGE_BASE) * BITS_PER_MSR;

    RtlSetBits(&bitmapHeader, vmCrOffset, 2);
    RtlSetBits(&bitmapHeader, vmHsavePaOffset, 2);
}

bool SVM::CheckAndSetInstalled()
{
    //
    // Track per-CPU state with a dynamically-sized array: this machine
    // has 16 logical CPUs, but any AMD system works regardless of core
    // count (8 cores / 16 threads, or up to 512 logical CPUs).
    //
    static PBYTE installedCpus = nullptr;
    static SIZE_T installedCpusCapacity = 0;

    if (!installedCpus)
    {
        //
        // KeQueryActiveProcessors() returns an affinity mask, not a count,
        // so it must not be used as an array size.  KeQueryActiveProcessorCountEx
        // returns the real number of active logical processors across all
        // processor groups.
        //
        const ULONG processorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        const SIZE_T needed = (processorCount > 0 ? processorCount : 1);
        installedCpus = static_cast<PBYTE>(ExAllocatePool(NonPagedPool, needed));
        if (installedCpus)
        {
            RtlZeroMemory(installedCpus, needed);
            installedCpusCapacity = needed;
        }
    }

    //
    // KeGetCurrentProcessorNumber() is relative to the current processor
    // group; KeGetProcessorIndexFromNumber() maps it to the system-wide
    // index that KeQueryActiveProcessorCountEx counts.
    //
    PROCESSOR_NUMBER processorNumber;
    KeGetCurrentProcessorNumberEx(&processorNumber);
    const ULONG processorIndex = KeGetProcessorIndexFromNumber(&processorNumber);
    if (!installedCpus || processorIndex >= installedCpusCapacity)
        return true;

    if (installedCpus[processorIndex])
        return true;

    installedCpus[processorIndex] = 1;
    return false;
}

UINT16 SVM::GetSegmentAccessRights(const UINT16 segmentSelector, const ULONG_PTR gdtBase)
{
    const PSEGMENT_DESCRIPTOR descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(gdtBase + (segmentSelector & ~RPL_MASK));

    SEGMENT_ATTRIBUTE attribute;
    attribute.Fields.Type = descriptor->Fields.Type;
    attribute.Fields.System = descriptor->Fields.System;
    attribute.Fields.Dpl = descriptor->Fields.Dpl;
    attribute.Fields.Present = descriptor->Fields.Present;
    attribute.Fields.Avl = descriptor->Fields.Avl;
    attribute.Fields.LongMode = descriptor->Fields.LongMode;
    attribute.Fields.DefaultBit = descriptor->Fields.DefaultBit;
    attribute.Fields.Granularity = descriptor->Fields.Granularity;
    attribute.Fields.Reserved1 = 0;

    return attribute.AsUInt16;
}

ULONG SVM::GetSegmentLimit(const UINT16 segmentSelector, const ULONG_PTR gdtBase)
{
    //
    // GDT entries are 8 bytes each.  Mask off the RPL (requested-privilege-level)
    // bits to get the descriptor index.
    //
    const PSEGMENT_DESCRIPTOR descriptor =
        reinterpret_cast<PSEGMENT_DESCRIPTOR>(gdtBase + (segmentSelector & ~RPL_MASK));

    //
    // The 20-bit limit is split across the descriptor:
    //   [0:15]  from LimitLow
    //   [16:19] from LimitHigh (4 bits)
    // When the granularity flag is set, the limit is in 4 KiB pages and the
    // lower 12 bits are all ones.
    //
    const ULONG limit =
        static_cast<ULONG>(descriptor->Fields.LimitLow) |
        (static_cast<ULONG>(descriptor->Fields.LimitHigh) << 16);

    if (descriptor->Fields.Granularity)
        return (limit << 12) | 0xFFF;

    return limit;
}

void SVM::PrepareForVirtualization(const PVIRTUAL_PROCESSOR_DATA vpData, const PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData, const PCONTEXT contextRecord)
{
    PROCESSOR_NUMBER processorNumber;
    KeGetCurrentProcessorNumberEx(&processorNumber);
    const ULONG processorIndex = KeGetProcessorIndexFromNumber(&processorNumber);
    vpData->HostStackLayout.ProcessorIndex = processorIndex;

    DESCRIPTOR_TABLE_REGISTER gdtr, idtr;
    _sgdt(&gdtr);
    __sidt(&idtr);

    const PHYSICAL_ADDRESS guestVmcbPa = MmGetPhysicalAddress(&vpData->GuestVmcb);
    const PHYSICAL_ADDRESS hostVmcbPa = MmGetPhysicalAddress(&vpData->HostVmcb);
    const PHYSICAL_ADDRESS hostStateAreaPa = MmGetPhysicalAddress(&vpData->HostStateArea);
    const PHYSICAL_ADDRESS pml4BasePa = MmGetPhysicalAddress(sharedVpData->Pml4Entries);
    const PHYSICAL_ADDRESS msrpmPa = MmGetPhysicalAddress(sharedVpData->MsrPermissionsMap);

    //
    // Snapshot the live (host) state into the guest VMCB first, then
    // overwrite the fields below.  VMSAVE writes the current processor
    // state, so calling it after the programming would discard everything
    // that was just set up - including Rip, which must be the interrupted
    // guest instruction and not an address inside this function.
    //
    __svm_vmsave(guestVmcbPa.QuadPart);

    vpData->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMRUN;
    vpData->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMCALL;

    vpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_MSR_PROT;
    vpData->GuestVmcb.ControlArea.MsrpmBasePa = msrpmPa.QuadPart;

    vpData->GuestVmcb.ControlArea.GuestAsid = 1;

    vpData->GuestVmcb.ControlArea.NpEnable |= SVM_NP_ENABLE_NP_ENABLE;
    vpData->GuestVmcb.ControlArea.NCr3 = pml4BasePa.QuadPart;

    vpData->GuestVmcb.StateSaveArea.GdtrBase = gdtr.Base;
    vpData->GuestVmcb.StateSaveArea.GdtrLimit = gdtr.Limit;
    vpData->GuestVmcb.StateSaveArea.IdtrBase = idtr.Base;
    vpData->GuestVmcb.StateSaveArea.IdtrLimit = idtr.Limit;

    vpData->GuestVmcb.StateSaveArea.CsLimit = GetSegmentLimit(contextRecord->SegCs, gdtr.Base);
    vpData->GuestVmcb.StateSaveArea.DsLimit = GetSegmentLimit(contextRecord->SegDs, gdtr.Base);
    vpData->GuestVmcb.StateSaveArea.EsLimit = GetSegmentLimit(contextRecord->SegEs, gdtr.Base);
    vpData->GuestVmcb.StateSaveArea.SsLimit = GetSegmentLimit(contextRecord->SegSs, gdtr.Base);
    vpData->GuestVmcb.StateSaveArea.CsSelector = contextRecord->SegCs;
    vpData->GuestVmcb.StateSaveArea.DsSelector = contextRecord->SegDs;
    vpData->GuestVmcb.StateSaveArea.EsSelector = contextRecord->SegEs;
    vpData->GuestVmcb.StateSaveArea.SsSelector = contextRecord->SegSs;
    vpData->GuestVmcb.StateSaveArea.CsAttrib = GetSegmentAccessRights(contextRecord->SegCs, gdtr.Base);
    vpData->GuestVmcb.StateSaveArea.DsAttrib = GetSegmentAccessRights(contextRecord->SegDs, gdtr.Base);
    vpData->GuestVmcb.StateSaveArea.EsAttrib = GetSegmentAccessRights(contextRecord->SegEs, gdtr.Base);
    vpData->GuestVmcb.StateSaveArea.SsAttrib = GetSegmentAccessRights(contextRecord->SegSs, gdtr.Base);

    vpData->GuestVmcb.StateSaveArea.Efer = __readmsr(IA32_MSR_EFER);
    vpData->GuestVmcb.StateSaveArea.Cr0 = __readcr0();
    vpData->GuestVmcb.StateSaveArea.Cr2 = __readcr2();
    vpData->GuestVmcb.StateSaveArea.Cr3 = __readcr3();
    vpData->GuestVmcb.StateSaveArea.Cr4 = __readcr4();
    vpData->GuestVmcb.StateSaveArea.Rflags = contextRecord->EFlags;
    vpData->GuestVmcb.StateSaveArea.Rsp = contextRecord->Rsp;
    vpData->GuestVmcb.StateSaveArea.Rip = contextRecord->Rip;
    vpData->GuestVmcb.StateSaveArea.GPat = __readmsr(IA32_MSR_PAT);

    vpData->HostStackLayout.Reserved1 = MAXUINT64;
    vpData->HostStackLayout.SharedVpData = sharedVpData;
    vpData->HostStackLayout.Self = vpData;
    vpData->HostStackLayout.HostVmcbPa = hostVmcbPa.QuadPart;
    vpData->HostStackLayout.GuestVmcbPa = guestVmcbPa.QuadPart;

    __writemsr(SVM_MSR_VM_HSAVE_PA, hostStateAreaPa.QuadPart);

    __svm_vmsave(hostVmcbPa.QuadPart);
}

namespace
{
    //
    // Single writer (the virtualization thread) publishes the final status
    // and then wakes Entry().  KeSetEvent() is a full barrier, so once the
    // wait completes Entry() observes the status written here.
    //
    void SignalVirtualizationReady(const NTSTATUS status)
    {
        Global::VirtualizationStatus = status;
        KeSetEvent(&Global::VirtualizationReady, IO_NO_INCREMENT, FALSE);
    }
}

NTSTATUS SVM::VirtualizeProcessor(const PVOID context)
{
    HV::Log("VirtualizeProcessor: enter");

    const PCONTEXT contextRecord = static_cast<PCONTEXT>(ExAllocatePool(NonPagedPool, sizeof(CONTEXT)));
    if (!contextRecord)
        return STATUS_INSUFFICIENT_RESOURCES;

    const PVIRTUAL_PROCESSOR_DATA vpData = static_cast<PVIRTUAL_PROCESSOR_DATA>(Utils::AllocatePageAligned(sizeof(VIRTUAL_PROCESSOR_DATA)));
    if (!vpData)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlCaptureContext(contextRecord);

    if (!CheckAndSetInstalled())
    {
        HV::Log("VirtualizeProcessor: new CPU, preparing VMCB");

        const PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData = static_cast<PSHARED_VIRTUAL_PROCESSOR_DATA>(context);

        __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) | EFER_SVME);

        //
        // Publish this CPU's vpData so ProtectSelf() can set TlbControl on
        // its VMCB.  The slot is the system-wide processor index - the same
        // index space the registry was sized with, and the same value
        // PrepareForVirtualization() stores in HostStackLayout.ProcessorIndex.
        //
        PROCESSOR_NUMBER processorNumber;
        KeGetCurrentProcessorNumberEx(&processorNumber);
        const ULONG processorIndex = KeGetProcessorIndexFromNumber(&processorNumber);
        if (Global::VirtualizedCpus && processorIndex < Global::VirtualizedCpuCount)
            reinterpret_cast<PVIRTUAL_PROCESSOR_DATA*>(Global::VirtualizedCpus)[processorIndex] = vpData;

        PrepareForVirtualization(vpData, sharedVpData, contextRecord);

        HV::Log("VirtualizeProcessor: LaunchVM");

        LaunchVM(&vpData->HostStackLayout.GuestVmcbPa);

        KeBugCheck(MANUALLY_INITIATED_CRASH);
    }

    return STATUS_SUCCESS;
}

void SVM::VirtualizeAllProcessors(PVOID)
{
    HV::Log("VirtualizeAllProcessors: enter");

    const PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData = static_cast<PSHARED_VIRTUAL_PROCESSOR_DATA>(Utils::AllocatePageAligned(sizeof(SHARED_VIRTUAL_PROCESSOR_DATA)));
    if (!sharedVpData)
    {
        SignalVirtualizationReady(STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    sharedVpData->MsrPermissionsMap = Utils::AllocateContiguousMemory(Global::MsrPermissionsMapSize);
    if (!sharedVpData->MsrPermissionsMap)
    {
        SignalVirtualizationReady(STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    //
    // Per-CPU registry plus the matching "generation already flushed" array.
    // Both are indexed by the system-wide processor index, which is what
    // KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) counts and what
    // KeGetProcessorIndexFromNumber() returns in VirtualizeProcessor(), so
    // the allocation and the index agree even on multi-group machines
    // (KeGetCurrentProcessorNumber() is only group-relative).
    //
    // Both allocations live for the driver's lifetime on purpose: the
    // registry is read from the VMEXIT path and from ProtectSelf().
    //
    const ULONG processorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    Global::VirtualizedCpus = static_cast<PBYTE>(ExAllocatePool(NonPagedPool, processorCount * sizeof(PVIRTUAL_PROCESSOR_DATA)));
    sharedVpData->NptFlushSeen = static_cast<LONG*>(ExAllocatePool(NonPagedPool, processorCount * sizeof(LONG)));
    if (!Global::VirtualizedCpus || !sharedVpData->NptFlushSeen)
    {
        SignalVirtualizationReady(STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    RtlZeroMemory(Global::VirtualizedCpus, processorCount * sizeof(PVIRTUAL_PROCESSOR_DATA));
    RtlZeroMemory(sharedVpData->NptFlushSeen, processorCount * sizeof(LONG));
    Global::VirtualizedCpuCount = processorCount;

    BuildNestedPageTables(sharedVpData);
    BuildPermissionMap(sharedVpData->MsrPermissionsMap);

    const NTSTATUS status = Utils::ExecuteOnEachProcessor(VirtualizeProcessor, sharedVpData);

    //
    // ExecuteOnEachProcessor() only returns after the last CPU has executed
    // VMRUN: VirtualizeProcessor() never returns to it directly, it resumes
    // as a guest at the context captured by RtlCaptureContext() and walks the
    // remaining iterations from there, so every CPU has been virtualized by
    // the time the loop finishes.
    //
    // Report the outcome either way.  The old KeBugCheck on failure is gone
    // on purpose: Entry() is waiting on the event and must get an error back
    // instead of hanging (or taking the machine down) when a CPU could not be
    // virtualized.
    //
    SignalVirtualizationReady(status);
}