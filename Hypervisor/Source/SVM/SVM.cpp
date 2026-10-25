#include "../Core/Global.h"
#include "../Common/HVLogs.h"

NTSTATUS SVM::CheckSupport()
{
    //
    // 5-level paging (CR4.LA57) widens the guest's *linear* address space, but
    // the NPT built below is a 4-level tree: its PDPT/PD geometry assumes the
    // 48-bit guest-physical space and there is no 5-level walker here.  A
    // LA57 guest would translate GPAs the NPT cannot express, so refuse
    // cleanly before any allocation or VMRUN rather than half-work.  This is
    // a no-op on the target CPU, which does not implement LA57.
    //
    if ((__readcr4() & (1UL << 12)) != 0)
        return STATUS_NOT_SUPPORTED;

    int registers[4];

    //
    // If a hypervisor is already resident (EFER.SVME set by a previous run that
    // never cleaned up), the CPUs are already running as guests. LaunchVM-ing a
    // second time rewrites their host state save area and triple-faults, so
    // refuse cleanly instead of corrupting the machine and freezing it.
    //
    if (__readmsr(IA32_MSR_EFER) & EFER_SVME)
        return STATUS_HV_INVALID_DEVICE_STATE;

    //
    // CPUID leaf 0 puts the vendor string "AuthenticAMD" in the high registers:
    // EBX = "Auth", ECX = "enti", EDX = "AMD\0".  Match each register against its
    // own value; the previous build compared EDX against the ECX value and ECX
    // against a mangled literal, so every AMD CPU was rejected.
    //
    __cpuid(registers, CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING);
    if ((registers[1] != 0x68747541) // "Auth" (EBX)
        || (registers[2] != 0x444D4163) // "cAMD" (ECX)
        || (registers[3] != 0x69746E65)) // "enti" (EDX)
        return STATUS_HV_INVALID_DEVICE_ID;

    __cpuid(registers, CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX);
    if (!(registers[2] & CPUID_FN8000_0001_ECX_SVM))
        return STATUS_HV_CPUID_FEATURE_VALIDATION_ERROR;

    __cpuid(registers, CPUID_SVM_FEATURES);
    if (!(registers[3] & CPUID_FN8000_000A_EDX_NP))
        return STATUS_HV_CPUID_FEATURE_VALIDATION_ERROR;

    Global::Np1GBAvailable = (registers[3] & CPUID_FN8000_000A_EDX_NP_1GB) != 0;

    const ULONG64 vmcr = __readmsr(MSR_VM_CR);
    if (vmcr & VM_CR_SVMDIS)
        return STATUS_HV_INVALID_DEVICE_STATE;

    return STATUS_SUCCESS;
}

namespace SVM
{
namespace
{
    //
    // NPT geometry.  A 4-level NPT addresses 2^48 bytes of guest-physical
    // space: 512 PML4 entries * 512 PDPT entries * 512 PD entries * 2 MB.
    //
    constexpr ULONG64 NptEntryCount = 512;
    constexpr ULONG64 NptOneGB = PAGE_SIZE_1GB;
    constexpr ULONG64 NptGpaLimit = 1ULL << 48;

    //
    // Guest-physical range the 2 MB fallback maps 1:1.
    //
    // Mapping the whole 256 TB a 4-level NPT can address would take 262144 PD
    // pages - 1 GB of tables, and that single 1 GB contiguous request is
    // exactly what failed with HAL_MEMORY_ALLOCATION (0xAC) on this 24 GB
    // machine.  The guest only ever touches its RAM plus a bounded MMIO
    // window, so the range is sized from the kernel's own
    // PHYSICAL_MEMORY_RANGE list with a 1 TB floor: 1 TB covers the 32-bit
    // apertures and the 64-bit PCIe windows Windows hands out on a box of this
    // size, and costs 1024 PD pages (4 MB).  Addresses between the RAM end and
    // the floor are mapped too, so a device BAR that lands in that window does
    // not raise an NPF.
    //
    // The result is rounded up to a whole 1 GB (the PD granularity) and capped
    // at the 48-bit GPA limit.  MmGetPhysicalMemoryRanges() returns a
    // zero-terminated array and is safe to call at PASSIVE_LEVEL, which is
    // where the virtualization thread starts.
    //
    ULONG64 ComputeMappedGpaEnd()
    {
        constexpr ULONG64 minimumMappedEnd = 1ULL << 40; // 1 TB

        ULONG64 highestEnd = minimumMappedEnd;

        const PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
        if (ranges)
        {
            for (ULONG index = 0; ranges[index].NumberOfBytes.QuadPart != 0; index++)
            {
                const ULONG64 base = static_cast<ULONG64>(ranges[index].BaseAddress.QuadPart);
                const ULONG64 length = static_cast<ULONG64>(ranges[index].NumberOfBytes.QuadPart);
                const ULONG64 end = base + length;

                // A wrapping entry cannot describe a real range; skip it
                // rather than let it widen or collapse the mapping.
                if (end < base)
                    continue;

                if (end > highestEnd)
                    highestEnd = end;
            }
        }

        ULONG64 mappedEnd = (highestEnd + NptOneGB - 1) & ~(NptOneGB - 1);
        if (mappedEnd > NptGpaLimit)
            mappedEnd = NptGpaLimit;

        return mappedEnd;
    }

    //
    // Releases whatever part of the NPT exists and clears the pointers, so a
    // caller can only ever observe a complete tree or no tree at all.
    // pdPageCount is the number of sharedData->PdPages entries that may have
    // been filled in; pass 0 when only the upper levels were allocated.
    //
    void ReleaseNestedPageTables(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, const ULONG64 pdPageCount)
    {
        if (sharedData->PdPages)
        {
            for (ULONG64 index = 0; index < pdPageCount; index++)
            {
                if (sharedData->PdPages[index])
                {
                    MmFreeContiguousMemory(sharedData->PdPages[index]);
                    sharedData->PdPages[index] = nullptr;
                }
            }

            MmFreeContiguousMemory(sharedData->PdPages);
            sharedData->PdPages = nullptr;
        }

        if (sharedData->PdpEntries)
        {
            MmFreeContiguousMemory(sharedData->PdpEntries);
            sharedData->PdpEntries = nullptr;
        }

        if (sharedData->Pml4Entries)
        {
            MmFreeContiguousMemory(sharedData->Pml4Entries);
            sharedData->Pml4Entries = nullptr;
        }
    }
}
}

void SVM::BuildNestedPageTables(const PSHARED_VIRTUAL_PROCESSOR_DATA sharedData)
{
    //
    // Map guest-physical addresses 1:1 to host physical addresses.
    //
    // When the CPU advertises 1 GB nested pages (Global::Np1GBAvailable), the
    // NPT is PML4 -> PDPT (512 PDPTE_1GB, LargePage=1): a single 2 MB PDPT
    // array covers all 256 TB of GPA space with 1 GB large pages.
    //
    // On CPUs that expose NP but not NP_1GB (the Ryzen 7 4800H target), 1 GB
    // pages do not exist, so the tree gains the PD level: PML4 -> PDPT
    // (PDPTE_2MB, LargePage=0, pointing at PD pages) -> PD (512 PD_ENTRY_2MB,
    // LargePage=1).  The PD pages are allocated one page-aligned 4 KB page at
    // a time, one per mapped 1 GB, instead of as one flat 1 GB block - see
    // ComputeMappedGpaEnd() for the range and the reason.  A 2 MB PDPT array
    // is still one contiguous allocation, which is affordable.
    //
    // Every level is zeroed by AllocatePageAligned, so the entries the CPU
    // walks but this function does not fill stay not-present rather than
    // random.  PML4/PDPT entries beyond the mapped range are left not-present
    // on purpose: nothing the guest can reach lives there.
    //
    // Any allocation failure releases the partial tree and nulls the fields;
    // VirtualizeAllProcessors() turns that into
    // STATUS_INSUFFICIENT_RESOURCES instead of running on a half-built NPT.
    //
    sharedData->Pml4Entries = static_cast<PML4E_64*>(Utils::AllocatePageAligned(PAGE_SIZE));
    if (!sharedData->Pml4Entries)
        return;

    if (Global::Np1GBAvailable)
    {
        sharedData->PdpEntries = static_cast<PDPTE_1GB(*)[512]>(Utils::AllocatePageAligned(sizeof(PDPTE_1GB) * NptEntryCount * NptEntryCount));
        if (!sharedData->PdpEntries)
        {
            ReleaseNestedPageTables(sharedData, 0);
            return;
        }

        for (ULONG64 pml4Index = 0; pml4Index < NptEntryCount; pml4Index++)
        {
            const ULONG64 pdpBasePa = MmGetPhysicalAddress(&sharedData->PdpEntries[pml4Index]).QuadPart;
            sharedData->Pml4Entries[pml4Index].Present = 1;
            sharedData->Pml4Entries[pml4Index].Write = 1;
            sharedData->Pml4Entries[pml4Index].Supervisor = 1;
            sharedData->Pml4Entries[pml4Index].PageFrameNumber = pdpBasePa >> PAGE_SHIFT;

            for (ULONG64 pdpIndex = 0; pdpIndex < NptEntryCount; pdpIndex++)
            {
                const ULONG64 translationPa = (pml4Index * 512ULL + pdpIndex);
                sharedData->PdpEntries[pml4Index][pdpIndex].Present = 1;
                sharedData->PdpEntries[pml4Index][pdpIndex].Write = 1;
                sharedData->PdpEntries[pml4Index][pdpIndex].Supervisor = 1;
                sharedData->PdpEntries[pml4Index][pdpIndex].LargePage = 1;
                sharedData->PdpEntries[pml4Index][pdpIndex].PageFrameNumber = translationPa;
            }
        }

        return;
    }

    //
    // 2 MB fallback.  mappedEnd is always a multiple of 1 GB and at least
    // 1 TB, so pdPageCount is in [1024, 262144] and every PML4 index it
    // implies is below 512.
    //
    const ULONG64 mappedEnd = ComputeMappedGpaEnd();
    const ULONG64 pdPageCount = mappedEnd / NptOneGB;

    Hypervisor::LogNum("NPT: 2MB path, mapped bytes", mappedEnd);
    Hypervisor::LogNum("NPT: 2MB path, PD pages", pdPageCount);

    sharedData->PdpEntries = static_cast<PDPTE_1GB(*)[512]>(Utils::AllocatePageAligned(sizeof(PDPTE_2MB) * NptEntryCount * NptEntryCount));
    if (!sharedData->PdpEntries)
    {
        ReleaseNestedPageTables(sharedData, 0);
        return;
    }

    sharedData->PdPages = static_cast<PD_ENTRY_2MB**>(Utils::AllocatePageAligned(sizeof(PD_ENTRY_2MB*) * pdPageCount));
    if (!sharedData->PdPages)
    {
        ReleaseNestedPageTables(sharedData, 0);
        return;
    }

    PDPTE_2MB* const pdptEntries = reinterpret_cast<PDPTE_2MB*>(sharedData->PdpEntries);

    for (ULONG64 region = 0; region < pdPageCount; region++)
    {
        //
        // One PML4 entry covers 512 GB, i.e. 512 consecutive 1 GB regions,
        // and the matching 4 KB PDPT page holds their 512 PDPTE_2MB entries.
        // The PDPT array is contiguous, so the page for a PML4 index starts
        // at entry pml4Index * 512.
        //
        const ULONG64 pml4Index = region / NptEntryCount;

        if ((region % NptEntryCount) == 0)
        {
            const ULONG64 pdptPagePa = MmGetPhysicalAddress(&pdptEntries[pml4Index * NptEntryCount]).QuadPart;
            sharedData->Pml4Entries[pml4Index].Present = 1;
            sharedData->Pml4Entries[pml4Index].Write = 1;
            sharedData->Pml4Entries[pml4Index].Supervisor = 1;
            sharedData->Pml4Entries[pml4Index].PageFrameNumber = pdptPagePa >> PAGE_SHIFT;
        }

        PD_ENTRY_2MB* const pdPage = static_cast<PD_ENTRY_2MB*>(Utils::AllocatePageAligned(PAGE_SIZE));
        if (!pdPage)
        {
            ReleaseNestedPageTables(sharedData, region);
            return;
        }

        sharedData->PdPages[region] = pdPage;

        PDPTE_2MB& pdpte = pdptEntries[region];
        pdpte.Present = 1;
        pdpte.Write = 1;
        pdpte.Supervisor = 1;
        pdpte.LargePage = 0;
        pdpte.PageFrameNumber = MmGetPhysicalAddress(pdPage).QuadPart >> PAGE_SHIFT;

        //
        // 512 2 MB large pages, mapping this 1 GB region 1:1.  PageFrameNumber
        // is the 2 MB page number, so it runs from region * 512 to
        // region * 512 + 511; 27 bits cover the whole 48-bit GPA space.
        //
        for (ULONG64 pdIndex = 0; pdIndex < NptEntryCount; pdIndex++)
        {
            PD_ENTRY_2MB& pde = pdPage[pdIndex];
            pde.Present = 1;
            pde.Write = 1;
            pde.Supervisor = 1;
            pde.LargePage = 1;
            pde.PageFrameNumber = region * NptEntryCount + pdIndex;
        }
    }
}

#if HYPERVISOR_ENABLE_SELF_HIDE
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
    // allowSplit == false makes the function a pure lookup: it never touches
    // the pool, so a caller that only wants to inspect the tree (the #NPF
    // diagnostic path) cannot consume the fixed supply of split tables.
    //
    PT_ENTRY_4KB* GetOrSplitPageTable(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, const ULONG64 pml4Index, const ULONG64 pdpIndex, const ULONG64 pdIndex, const bool allowSplit)
    {
        const ULONG64 pdBase = (pml4Index * 512ULL + pdpIndex) * PAGE_SIZE_1GB;

        //
        // Validate every level before following it.  An NPF for a GPA outside
        // the mapped range (an MMIO BAR above the 2 MB fallback's ceiling)
        // lands on a zeroed PML4/PDPT entry, and following that would
        // dereference physical page 0 as if it were a page table - the #NPF
        // handler would then read, and possibly write, an arbitrary 8-byte
        // location.  A not-present upper level means "no leaf here", which is
        // exactly what the caller must be told.
        //
        if (!sharedData->Pml4Entries[pml4Index].Present)
            return nullptr;

        PDPTE_1GB* pdpte = &sharedData->PdpEntries[pml4Index][pdpIndex];
        if (!pdpte->Present)
            return nullptr;

        if (pdpte->LargePage)
        {
            if (!allowSplit)
                return nullptr;

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

            //
            // Build the split entry from scratch instead of copying the
            // large-page encoding and patching it: the 1 GB entry's Dirty,
            // Global and Pat bits are either reserved or mean something else
            // in a table pointer, and the old copy left them set.
            //
            PDPTE_2MB splitEntry = {};
            splitEntry.Present = 1;
            splitEntry.Write = 1;
            splitEntry.Supervisor = 1;
            splitEntry.LargePage = 0;
            splitEntry.PageFrameNumber = MmGetPhysicalAddress(newPdTable).QuadPart >> PAGE_SHIFT;
            splitEntry.ExecuteDisable = pdpte->ExecuteDisable;

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
        if (!pde->Present)
            return nullptr;

        if (pde->LargePage)
        {
            if (!allowSplit)
                return nullptr;

            PT_ENTRY_4KB* newPtTable = static_cast<PT_ENTRY_4KB*>(Utils::GetPreallocatedPool(sizeof(PT_ENTRY_4KB) * 512));
            if (!newPtTable)
                return nullptr;

            //
            // The PD entry here is a 2 MB large page, so its bit 63 is NX.
            // Carry it down to every 4 KB leaf: dropping it would make an NX
            // page executable in the NPT after the split.
            //
            const PD_ENTRY_2MB* const largeEntry = reinterpret_cast<const PD_ENTRY_2MB*>(pde);

            const ULONG64 ptBase = pdBase + pdIndex * PAGE_SIZE_2MB;
            for (ULONG64 ptEntry = 0; ptEntry < 512; ptEntry++)
            {
                newPtTable[ptEntry].Present = 1;
                newPtTable[ptEntry].Write = 1;
                newPtTable[ptEntry].Supervisor = 1;
                newPtTable[ptEntry].NoExecute = largeEntry->NoExecute;
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
            splitPde.ExecuteDisable = pde->ExecuteDisable;

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

SVM::PT_ENTRY_4KB* SVM::GetPageTableEntry(const SVM::PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, const ULONG64 gpa, const bool allowSplit)
{
#if HYPERVISOR_ENABLE_SELF_HIDE
    //
    // The NPT is a 4-level tree, so only a 48-bit GPA has an index in it.
    // A wider ExitInfo2 value would index Pml4Entries past its 4 KB page.
    //
    if (!sharedData || gpa >= NptGpaLimit)
        return nullptr;

    return GetOrSplitPageTable(
        sharedData,
        gpa >> PML4_PAGE_SHIFT,
        (gpa >> PDP_PAGE_SHIFT) & INDEX_MASK,
        (gpa >> PD_PAGE_SHIFT) & INDEX_MASK,
        allowSplit);
#else
    UNREFERENCED_PARAMETER(sharedData);
    UNREFERENCED_PARAMETER(gpa);
    UNREFERENCED_PARAMETER(allowSplit);

    return nullptr;
#endif
}

void SVM::TrackForRehide(const PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, SVM::PT_ENTRY_4KB* entry)
{
#if HYPERVISOR_ENABLE_SELF_HIDE
    if (!entry || !sharedData)
        return;

    //
    // Best-effort, race-tolerant: a clobbered or overflowed slot simply leaves
    // its page mapped (a small stealth loss), never a correctness failure.
    //
    const LONG slot = InterlockedIncrement(&sharedData->NptRehideIndex) & (NPT_REHIDE_CAPACITY - 1);
    sharedData->NptRehide[slot] = entry;
    sharedData->NptRehideRestoreExit[slot] = sharedData->NptExitCounter;

    //
    // Sticky restore.  A page that has to be restored this often is in active
    // use; re-hiding it would feed the #NPF path forever.  Stop the cycle for
    // good once the limit is reached - the NPT then stays fully present and
    // the #NPF handler has nothing left to resolve.
    //
    if (InterlockedIncrement(&sharedData->NptRestoreCount) >= NPT_RESTORE_LIMIT)
        InterlockedExchange(&sharedData->NptRehideEnabled, FALSE);
#else
    UNREFERENCED_PARAMETER(sharedData);
    UNREFERENCED_PARAMETER(entry);
#endif
}

NTSTATUS SVM::HideRange(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, const ULONG64 virtualBase, const SIZE_T size, const ULONG64 textBase, const SIZE_T textSize)
{
#if HYPERVISOR_ENABLE_SELF_HIDE
    Hypervisor::LogNum("HideRange: enter, size", size);

    const ULONG64 pageMask = ~(static_cast<ULONG64>(PAGE_SIZE) - 1);
    const ULONG64 blankPagePhysical = MmGetPhysicalAddress(Global::BlankPage).QuadPart & pageMask;

    //
    // Executable skip range.  Hiding .text guarantees a permanent #NPF
    // supply: the driver's notify callback and log thread run that code in
    // guest mode, so every one of their instruction fetches faults.  The
    // caller supplies the executable range and those pages are left mapped.
    //
    // Round *outward* here (opposite of the hide range below): a page that
    // holds even one executable byte must not be hidden, so the skip starts
    // at the page containing textBase and ends at the page containing the
    // last executable byte.  A zero base or size means "no executable range
    // known" and skips nothing (legacy full-image hide).
    //
    const bool skipExecutable = (textBase != 0 && textSize != 0);
    const ULONG64 textFirst = textBase & pageMask;
    const ULONG64 textEnd = (textBase + textSize + PAGE_SIZE - 1) & pageMask;

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
    // A *page-aligned* base is already fully owned by the caller, so it must
    // not be rounded up: (base + PAGE_SIZE - 1) & pageMask skipped the first
    // page of every page-aligned image, which is exactly the image header.
    //
    const ULONG64 firstPage = ((virtualBase & (PAGE_SIZE - 1)) == 0)
        ? (virtualBase & pageMask)
        : ((virtualBase + PAGE_SIZE - 1) & pageMask);
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
        if (skipExecutable && pageVirtual >= textFirst && pageVirtual < textEnd)
            continue;

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
            (pagePhysical >> PD_PAGE_SHIFT) & INDEX_MASK,
            true);
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
        // access raises a nested page fault that the #NPF handler resolves by
        // setting Present again (a transparent restore: no #PF is injected,
        // so the guest never observes it).  Blanking the PFN to the shared
        // BlankPage would instead make reads return zeros, which the guest
        // executes as garbage and hangs the machine.
        //
        InterlockedExchange64(reinterpret_cast<volatile LONGLONG*>(&pageTableEntry->AsUInt64),
            pageTableEntry->AsUInt64 & ~1ULL);
        found = true;

        //
        // Record the leaf entry so DisableSelfHide() can put it back without
        // walking the tree or allocating: the PFN survived the hide, so a
        // restore is one atomic OR of bit 0.  Dedupe by pointer (overlapping
        // ranges reach the same page twice) and cap at the array size.  The
        // slot is written before the count is published, so a reader that
        // observes the count also observes the pointer.
        //
        const LONG recordedCount = sharedData->HiddenPteCount;
        bool alreadyRecorded = false;
        for (LONG index = 0; index < recordedCount && index < static_cast<LONG>(ARRAYSIZE(sharedData->HiddenPtes)); index++)
        {
            if (sharedData->HiddenPtes[index] == pageTableEntry)
            {
                alreadyRecorded = true;
                break;
            }
        }

        if (!alreadyRecorded)
        {
            const LONG index = InterlockedIncrement(&sharedData->HiddenPteCount) - 1;
            if (index < static_cast<LONG>(ARRAYSIZE(sharedData->HiddenPtes)))
                sharedData->HiddenPtes[index] = pageTableEntry;
            else
                InterlockedDecrement(&sharedData->HiddenPteCount);
        }
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

    Hypervisor::Log("HideRange: done");

    return STATUS_SUCCESS;
#else
    //
    // Self-hide is disabled (HYPERVISOR_ENABLE_SELF_HIDE == 0, see Global.h): every
    // NPT entry keeps its real mapping, so guest-mode access to the hidden
    // ranges keeps working.  The command still reports success to the client.
    //
    UNREFERENCED_PARAMETER(sharedData);
    UNREFERENCED_PARAMETER(virtualBase);
    UNREFERENCED_PARAMETER(size);
    UNREFERENCED_PARAMETER(textBase);
    UNREFERENCED_PARAMETER(textSize);

    return STATUS_SUCCESS;
#endif
}

NTSTATUS SVM::ProtectSelf(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData, const ULONG64 textBase, const SIZE_T textSize)
{
#if HYPERVISOR_ENABLE_SELF_HIDE
    Hypervisor::Log("ProtectSelf: enter");

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

    Hypervisor::LogNum("ProtectSelf: HideRange base, size", driverSize);

    //
    // Arm the re-hide cycle only now that the range is known to be valid, and
    // start the restore budget from zero.  HideRange() records every leaf it
    // clears in HiddenPtes[], which is what lets DisableSelfHide() undo the
    // whole hide later without allocating.
    //
    sharedData->NptRestoreCount = 0;
    InterlockedExchange(&sharedData->NptRehideEnabled, TRUE);

    const NTSTATUS result = HideRange(sharedData, driverVirtualBase, driverSize, textBase, textSize);

    Hypervisor::LogNum("ProtectSelf: HideRange result", result);

    if (!NT_SUCCESS(result))
        InterlockedExchange(&alreadyProtected, 0);

    return result;
#else
    UNREFERENCED_PARAMETER(sharedData);
    UNREFERENCED_PARAMETER(textBase);
    UNREFERENCED_PARAMETER(textSize);

    return STATUS_SUCCESS;
#endif
}

void SVM::DisableSelfHide(PSHARED_VIRTUAL_PROCESSOR_DATA sharedData)
{
#if HYPERVISOR_ENABLE_SELF_HIDE
    if (!sharedData)
        return;

    //
    // Fail open.  Clearing the flag first stops ProtectSelf()-time hiding
    // from being re-armed and makes HandleExit() skip the revert scan, so
    // nothing re-hides a page behind the restores below.
    //
    // The early-out covers the machine that never hid anything (no image
    // range, or the caller never asked): the #NPF diagnostic path calls this
    // on every fault it cannot attribute, and with nothing recorded there is
    // nothing to restore - skipping the generation bump keeps those faults
    // from arming a full flush on every VMCB.  When pages *were* recorded the
    // restore below is idempotent, so a repeated call is harmless (just not
    // free); the 1000-fault tripwire bounds it.
    //
    const LONG wasEnabled = InterlockedExchange(&sharedData->NptRehideEnabled, FALSE);
    if (wasEnabled == FALSE && sharedData->HiddenPteCount == 0)
        return;

    //
    // Restore every page HideRange() hid.  No allocation and no page-table
    // walk: the entry still holds the real PFN, so setting bit 0 is the whole
    // restore.  HiddenPteCount is read once; slots are published before the
    // count, so every slot below the count is a valid pointer (or null while
    // another CPU is mid-publish, which is skipped).
    //
    const LONG hiddenCount = sharedData->HiddenPteCount;
    for (LONG index = 0; index < hiddenCount && index < static_cast<LONG>(ARRAYSIZE(sharedData->HiddenPtes)); index++)
    {
        PT_ENTRY_4KB* const entry = sharedData->HiddenPtes[index];
        if (!entry)
            continue;

        InterlockedExchange64(reinterpret_cast<volatile LONGLONG*>(&entry->AsUInt64), entry->AsUInt64 | 1);
    }

    for (ULONG index = 0; index < ARRAYSIZE(sharedData->NpfStaleStrikes); index++)
        InterlockedExchange(&sharedData->NpfStaleStrikes[index], 0);

    //
    // Publish the new state exactly like HideRange(): the generation bump is
    // the release that orders it after the Present stores, and every
    // published VMCB gets TlbControl = 1 so the CPU re-walks the NPT at its
    // next VMRUN.  Without this a CPU could keep translating through stale
    // not-present entries and refault a page that is already restored.
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

    static volatile LONG disableLogged = 0;
    if (InterlockedCompareExchange(&disableLogged, 1, 0) == 0)
    {
        Hypervisor::LogNum("DisableSelfHide: restored pages", static_cast<unsigned long long>(hiddenCount));
    }
#else
    UNREFERENCED_PARAMETER(sharedData);
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

    const ULONG vmCrOffset = THIRD_MSRPM_OFFSET + (MSR_VM_CR - THIRD_MSR_RANGE_BASE) * BITS_PER_MSR;
    const ULONG vmHsavePaOffset = THIRD_MSRPM_OFFSET + (MSR_VM_HSAVE_PA - THIRD_MSR_RANGE_BASE) * BITS_PER_MSR;

    RtlSetBits(&bitmapHeader, vmCrOffset, 2);
    RtlSetBits(&bitmapHeader, vmHsavePaOffset, 2);
}

int SVM::CheckAndSetInstalled()
{
    //
    // Track per-CPU state with a dynamically-sized array: any AMD system
    // works regardless of core count (8 cores / 16 threads, or up to 512
    // logical CPUs).  The maximum configured count is used so a hot-added
    // processor still has a slot.
    //
    static PBYTE installedCpus = nullptr;
    static SIZE_T installedCpusCapacity = 0;

    if (!installedCpus)
    {
        ULONG processorCount = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
        if (processorCount == 0)
            processorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        if (processorCount == 0)
            return -1;

        installedCpus = static_cast<PBYTE>(ExAllocatePool(NonPagedPool, processorCount));
        if (!installedCpus)
            return -1;

        RtlZeroMemory(installedCpus, processorCount);
        installedCpusCapacity = processorCount;
    }

    //
    // KeGetCurrentProcessorNumber() is relative to the current processor
    // group; KeGetProcessorIndexFromNumber() maps it to the system-wide
    // index that KeQueryActiveProcessorCountEx counts.
    //
    PROCESSOR_NUMBER processorNumber;
    KeGetCurrentProcessorNumberEx(&processorNumber);
    const ULONG processorIndex = KeGetProcessorIndexFromNumber(&processorNumber);
    if (processorIndex >= installedCpusCapacity)
        return -1;

    if (installedCpus[processorIndex])
        return 1;

    installedCpus[processorIndex] = 1;
    return 0;
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

    vpData->GuestVmcb.ControlArea.InterceptMisc2 |= INTERCEPT_MISC2_VMRUN;
    vpData->GuestVmcb.ControlArea.InterceptMisc2 |= INTERCEPT_MISC2_VMCALL;
    vpData->GuestVmcb.ControlArea.InterceptMisc2 |= INTERCEPT_MISC2_VMLOAD;
    vpData->GuestVmcb.ControlArea.InterceptMisc2 |= INTERCEPT_MISC2_VMSAVE;
    vpData->GuestVmcb.ControlArea.InterceptMisc2 |= INTERCEPT_MISC2_STGI;
    vpData->GuestVmcb.ControlArea.InterceptMisc2 |= INTERCEPT_MISC2_CLGI;
    vpData->GuestVmcb.ControlArea.InterceptMisc2 |= INTERCEPT_MISC2_SKINIT;

    vpData->GuestVmcb.ControlArea.InterceptMisc1 |= INTERCEPT_MISC1_MSR_PROT;
    vpData->GuestVmcb.ControlArea.InterceptMisc1 |= INTERCEPT_MISC1_CPUID;
    vpData->GuestVmcb.ControlArea.MsrpmBasePa = msrpmPa.QuadPart;

    vpData->GuestVmcb.ControlArea.GuestAsid = 1;

    vpData->GuestVmcb.ControlArea.NpEnable |= NP_ENABLE;
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

    __writemsr(MSR_VM_HSAVE_PA, hostStateAreaPa.QuadPart);

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
    Hypervisor::Log("VirtualizeProcessor: enter");

    const PCONTEXT contextRecord = static_cast<PCONTEXT>(ExAllocatePool(NonPagedPool, sizeof(CONTEXT)));
    if (!contextRecord)
        return STATUS_INSUFFICIENT_RESOURCES;

    const PVIRTUAL_PROCESSOR_DATA vpData = static_cast<PVIRTUAL_PROCESSOR_DATA>(Utils::AllocatePageAligned(sizeof(VIRTUAL_PROCESSOR_DATA)));
    if (!vpData)
    {
        ExFreePool(contextRecord);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Capture BEFORE the install check: the captured RIP becomes the guest
    // VMCB's first RIP, so the first VMRUN resumes *here* in guest mode.
    // The re-executed CheckAndSetInstalled() then reports this CPU as
    // already installed and returns to ExecuteOnEachProcessor(), which
    // walks the remaining CPUs.  If the check sits ahead of the capture,
    // the guest instead re-runs the whole virtualization sequence and its
    // VMSAVE is intercepted -> #UD in guest kernel code -> bugcheck.
    //
    RtlCaptureContext(contextRecord);

    const int installState = CheckAndSetInstalled();
    if (installState < 0)
    {
        Hypervisor::Log("VirtualizeProcessor: CPU bookkeeping allocation failed");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (installState != 0)
        return STATUS_SUCCESS;

    Hypervisor::Log("VirtualizeProcessor: new CPU, preparing VMCB");

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

    Hypervisor::Log("VirtualizeProcessor: LaunchVM");

    LaunchVM(&vpData->HostStackLayout.GuestVmcbPa);

    KeBugCheck(MANUALLY_INITIATED_CRASH);
}

void SVM::VirtualizeAllProcessors(PVOID)
{
    Hypervisor::Log("VirtualizeAllProcessors: enter");

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
    if (processorCount == 0)
    {
        SignalVirtualizationReady(STATUS_INVALID_PARAMETER);
        return;
    }

    Global::VirtualizedCpus = static_cast<PBYTE>(ExAllocatePool(NonPagedPool, processorCount * sizeof(PVIRTUAL_PROCESSOR_DATA)));
    sharedVpData->NptFlushSeen = static_cast<LONG*>(ExAllocatePool(NonPagedPool, processorCount * sizeof(LONG)));
    if (!Global::VirtualizedCpus || !sharedVpData->NptFlushSeen)
    {
        if (Global::VirtualizedCpus)
        {
            ExFreePool(Global::VirtualizedCpus);
            Global::VirtualizedCpus = nullptr;
        }

        if (sharedVpData->NptFlushSeen)
        {
            ExFreePool(sharedVpData->NptFlushSeen);
            sharedVpData->NptFlushSeen = nullptr;
        }

        SignalVirtualizationReady(STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    RtlZeroMemory(Global::VirtualizedCpus, processorCount * sizeof(PVIRTUAL_PROCESSOR_DATA));
    RtlZeroMemory(sharedVpData->NptFlushSeen, processorCount * sizeof(LONG));
    Global::VirtualizedCpuCount = processorCount;

    //
    // BuildNestedPageTables() nulls every field it could not complete, so a
    // failure here is a partially built tree.  Detecting it is the whole
    // point of the null contract: VMRUN with a half-built NPT raises an NPF
    // on the first missing page and there is no recovery path.
    //
    // PdPages only exists on the 2 MB fallback (NP without NP_1GB), so it is
    // only required when that path was taken.
    //
    BuildNestedPageTables(sharedVpData);
    if (!sharedVpData->Pml4Entries || !sharedVpData->PdpEntries ||
        (!Global::Np1GBAvailable && !sharedVpData->PdPages))
    {
        SignalVirtualizationReady(STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

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