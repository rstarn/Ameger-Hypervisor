#include "../Global.h"
#include "../HVLog.h"

constexpr UINT32 PageCount = 64;
static Memory::PAGE_INFO PageList[PageCount];

ULONG64 Memory::GetDirectoryBase(const PEPROCESS process)
{
    /*
     * The pointer is validated before it gets here: HandleGetDirectoryBase
     * only accepts an EPROCESS that is present in the active process list,
     * and every other caller passes a kernel-owned process object.
     *
     * resolved at boot by Utils::GetOffsets() from the running kernel
     * image; falls back to zero (unresolved) when the pattern scan fails.
     */
    if (!process || Global::Offsets::DirectoryTableBase == 0)
        return 0;

    return *reinterpret_cast<ULONG64*>(reinterpret_cast<PBYTE>(process) + Global::Offsets::DirectoryTableBase);
}

ULONG64 Memory::VirtualToPhysical(const ULONG64 virtualAddress)
{
    return MmGetPhysicalAddress(reinterpret_cast<PVOID>(virtualAddress)).QuadPart;
}

ULONG64 Memory::PhysicalToVirtual(const ULONG64 physicalAddress)
{
    PHYSICAL_ADDRESS physical;
    physical.QuadPart = physicalAddress;
    return reinterpret_cast<ULONG64>(MmGetVirtualForPhysical(physical));
}

/*
 * Walks the target address space's page tables by reading the table entries
 * through the remapped scratch page instead of swapping CR3 on the current
 * processor. Unlike the old __writecr3 approach this never dereferences a
 * virtual address that is not mapped in the *current* address space, which
 * is what made reads of unswapped/unmapped pages freeze or crash the system
 * (issue #12). Large pages (1 GB / 2 MB) are resolved as well, which the old
 * VirtualToPhysical path silently refused.
 */
ULONG64 Memory::ResolveProcessPhysicalAddress(const UINT32 pageIndex, const ULONG64 directoryBase, const ULONG64 address)
{
    /*
     * The page index is only used as scratch space for the temporary
     * ReadPhysicalAddress mappings below; any free page works. The table
     * entries are re-read from memory after every remap, so the single
     * scratch page can be reused for the whole walk.
     */
    const UINT32 page = pageIndex;

    VIRTUAL_ADDRESS virtualAddress;
    virtualAddress.Value = address;

    PTE_CR3 cr3;
    cr3.Value = directoryBase;

    /*
     * Every address below comes from the guest: the directory base itself
     * and each table pointer read out of a guest-controlled entry.  An
     * aligned CR3 can still point at an MMIO hole or an unbacked GPA, and
     * remapping such a page machine-checks or hangs the host, so the 4 KB
     * page containing each table address is checked against the cached RAM
     * ranges before it is read.  A table entry never crosses its page
     * (index * 8 stays inside the 4 KB the PFN describes), so validating
     * the page covers the whole read.
     */
    const ULONG64 pml4Page = PFN_TO_PAGE(cr3.Pml4);
    if (!Utils::IsPhysicalRangeValid(pml4Page, PAGE_SIZE))
        return 0;

    PML4E pml4e;
    ULONG64 pml4eAddress = pml4Page + virtualAddress.Pml4Index * sizeof(PML4E);
    ReadPhysicalAddress(page, pml4eAddress, &pml4e, sizeof(PML4E));
    if (!pml4e.Present)
        return 0;

    //
    // Every level must be user accessible.  The copy path only accepts user
    // addresses, so a translation that goes through a supervisor entry is not
    // a translation of the address the caller named - and a guest-supplied
    // directory base pointing at a page of hand-built PTEs would otherwise be
    // able to name any physical page, including a kernel stack, as "user".
    //
    if (!pml4e.User)
        return 0;

    const ULONG64 pdptPage = PFN_TO_PAGE(pml4e.Pdpt);
    if (!Utils::IsPhysicalRangeValid(pdptPage, PAGE_SIZE))
        return 0;

    PDPTE pdpte;
    ULONG64 pdpteAddress = pdptPage + virtualAddress.PdptIndex * sizeof(PDPTE);
    ReadPhysicalAddress(page, pdpteAddress, &pdpte, sizeof(PDPTE));
    if (!pdpte.Present)
        return 0;

    if (!pdpte.User)
        return 0;

    // If 1GB page
    if (pdpte.PageSize)
        return PFN_TO_PAGE(pdpte.Pd) + virtualAddress.Offset1gb;

    const ULONG64 pdPage = PFN_TO_PAGE(pdpte.Pd);
    if (!Utils::IsPhysicalRangeValid(pdPage, PAGE_SIZE))
        return 0;

    PDE pde;
    ULONG64 pdeAddress = pdPage + virtualAddress.PdIndex * sizeof(PDE);
    ReadPhysicalAddress(page, pdeAddress, &pde, sizeof(PDE));
    if (!pde.Present)
        return 0;

    if (!pde.User)
        return 0;

    // If 2MB page
    if (pde.PageSize)
        return PFN_TO_PAGE(pde.Pt) + virtualAddress.Offset2mb;

    const ULONG64 ptPage = PFN_TO_PAGE(pde.Pt);
    if (!Utils::IsPhysicalRangeValid(ptPage, PAGE_SIZE))
        return 0;

    PTE pte;
    ULONG64 pteAddress = ptPage + virtualAddress.PtIndex * sizeof(PTE);
    ReadPhysicalAddress(page, pteAddress, &pte, sizeof(PTE));
    if (!pte.Present)
        return 0;

    if (!pte.User)
        return 0;

    return PFN_TO_PAGE(pte.PageFrame) + virtualAddress.Offset4kb;
}

/*
 * Some anti-cheats protect a process by making its kernel-side directory
 * base (EPROCESS + DirectoryTableBase, resolved dynamically) diverge from the CR3 value that is actually loaded
 * while the process runs. Such a directory base walks to nothing and every
 * read fails with STATUS_NOT_FOUND (see the discussion on PR #13). The
 * caller can pass the CR3 observed on the CPU (e.g. captured via a CR3 write
 * intercept) as directoryTableBase; it is tried first and the kernel-side
 * directory base acts as the fallback.
 */
ULONG64 Memory::ResolveProcessPhysicalAddressEx(const UINT32 pageIndex, const ULONG64 directoryBase, const ULONG64 directoryTableBase, const ULONG64 address)
{
    /*
     * When a CR3 observed on the CPU is available and differs from the
     * kernel-side directory base, it describes the address space the process
     * is actually running in. Try it first, so a stale or deliberately
     * altered directory base (which may still walk into some other address
     * space) cannot produce translations for pages the process does not
     * really have mapped at the moment.
     */
    if (directoryTableBase && directoryTableBase != directoryBase)
    {
        const ULONG64 preferred = ResolveProcessPhysicalAddress(pageIndex, directoryTableBase, address);
        if (preferred)
            return preferred;
    }

    return ResolveProcessPhysicalAddress(pageIndex, directoryBase, address);
}

Memory::PTE* Memory::GetPte(const ULONG64 address, const ULONG64 directoryBase)
{
    VIRTUAL_ADDRESS virtualAddress;
    virtualAddress.Value = address;

    PTE_CR3 cr3;
    cr3.Value = directoryBase;

    PML4E* pml4 = reinterpret_cast<PML4E*>(PhysicalToVirtual(PFN_TO_PAGE(cr3.Pml4)));
    const PML4E* pml4e = (pml4 + virtualAddress.Pml4Index);
    if (!pml4e->Present)
        return nullptr;

    PDPTE* pdpt = reinterpret_cast<PDPTE*>(PhysicalToVirtual(PFN_TO_PAGE(pml4e->Pdpt)));
    const PDPTE* pdpte = pdpte = (pdpt + virtualAddress.PdptIndex);
    if (!pdpte->Present)
        return nullptr;

    // sanity check 1GB page
    if (pdpte->PageSize)
        return nullptr;

    PDE* pd = reinterpret_cast<PDE*>(PhysicalToVirtual(PFN_TO_PAGE(pdpte->Pd)));
    const PDE* pde = pde = (pd + virtualAddress.PdIndex);
    if (!pde->Present)
        return nullptr;

    // sanity check 2MB page
    if (pde->PageSize)
        return nullptr;

    PTE* pt = reinterpret_cast<PTE*>(PhysicalToVirtual(PFN_TO_PAGE(pde->Pt)));
    PTE* pte = (pt + virtualAddress.PtIndex);
    if (!pte->Present)
        return nullptr;

    return pte;
}

bool Memory::PreparePage(PAGE_INFO* targetPage)
{
    PHYSICAL_ADDRESS maxAddress;
    maxAddress.QuadPart = MAXULONG64;

    targetPage->VirtualAddress = MmAllocateContiguousMemory(PAGE_SIZE, maxAddress);
    if (!targetPage->VirtualAddress)
        return false;

    targetPage->CopyBuffer = ExAllocatePool(NonPagedPool, Shared::MAX_RW_SIZE);
    if (!targetPage->CopyBuffer)
        return false;

    targetPage->PageEntry = GetPte(reinterpret_cast<ULONG64>(targetPage->VirtualAddress), __readcr3());
    if (!targetPage->PageEntry)
        return false;

    return true;
}

bool Memory::PreparePages()
{
    for (UINT32 i = 0; i < PageCount; i++)
    {
        if (!PreparePage(&PageList[i]))
            return false;
    }

    return true;
}

PVOID Memory::OverwritePage(const UINT32 pageIndex, const ULONG64 physicalAddress)
{
    const ULONG pageOffset = physicalAddress % PAGE_SIZE;
    const ULONG64 pageStartPhysical = physicalAddress - pageOffset;

    PAGE_INFO* pageInfo = &PageList[pageIndex];
    pageInfo->PreviousPageFrame = pageInfo->PageEntry->PageFrame;
    pageInfo->PageEntry->PageFrame = PAGE_TO_PFN(pageStartPhysical);
    __invlpg(pageInfo->VirtualAddress);

    return reinterpret_cast<PVOID>(reinterpret_cast<ULONG64>(pageInfo->VirtualAddress) + pageOffset);
}

void Memory::RestorePage(const UINT32 pageIndex)
{
    const PAGE_INFO* pageInfo = &PageList[pageIndex];
    pageInfo->PageEntry->PageFrame = pageInfo->PreviousPageFrame;
    __invlpg(pageInfo->VirtualAddress);
}

bool Memory::ReadPhysicalAddress(const UINT32 pageIndex, const ULONG64 targetAddress, const PVOID buffer, const SIZE_T size)
{
    /*
     * The address is either a table address derived from a guest-supplied
     * directory base or a page resolved through guest-controlled entries.
     * Remapping a page that is not backed by RAM (MMIO hole, PCIe window,
     * unbacked GPA) machine-checks or hangs the host, so the complete range
     * is validated against the cached RAM ranges first.  Failure is reported
     * to the caller; nothing here bugchecks.
     */
    if (!Utils::IsPhysicalRangeValid(targetAddress, size))
        return false;

    const PVOID virtualAddress = OverwritePage(pageIndex, targetAddress);
    memcpy(buffer, virtualAddress, size);
    RestorePage(pageIndex);

    return true;
}

bool Memory::WritePhysicalAddress(const UINT32 pageIndex, const ULONG64 targetAddress, const PVOID buffer, const SIZE_T size)
{
    // See ReadPhysicalAddress: a non-RAM target must never be mapped, and on
    // the copy path this is the guest-declared destination.
    if (!Utils::IsPhysicalRangeValid(targetAddress, size))
        return false;

    const PVOID virtualAddress = OverwritePage(pageIndex, targetAddress);
    memcpy(virtualAddress, buffer, size);
    RestorePage(pageIndex);

    return true;
}

NTSTATUS Memory::ReadProcessMemoryEx(const UINT32 pageIndex, const ULONG64 directoryBase, const ULONG64 directoryTableBase, const ULONG64 address, PVOID buffer, const SIZE_T size, SIZE_T* bytesRead)
{
    /*
     * pageIndex is HostStackLayout.ProcessorIndex, i.e. the system-wide
     * processor number, and it selects a slot in the fixed PageList.
     * Bound it before it is used as an array index.
     */
    if (pageIndex >= PageCount)
        return STATUS_INVALID_PARAMETER;

    SIZE_T currentOffset = 0;
    SIZE_T totalSize = size;
    while (totalSize)
    {
        const ULONG64 currentPhysicalAddress = ResolveProcessPhysicalAddressEx(pageIndex, directoryBase, directoryTableBase, address + currentOffset);
        if (!currentPhysicalAddress)
            return STATUS_NOT_FOUND;

        const ULONG64 readSize = min(PAGE_SIZE - (currentPhysicalAddress & 0xFFF), totalSize);

        if (!ReadPhysicalAddress(pageIndex, currentPhysicalAddress, reinterpret_cast<PVOID>(reinterpret_cast<ULONG64>(buffer) + currentOffset), readSize))
            return STATUS_INVALID_ADDRESS;

        totalSize -= readSize;
        currentOffset += readSize;
    }

    *bytesRead = currentOffset;

    return STATUS_SUCCESS;
}

NTSTATUS Memory::WriteProcessMemoryEx(const UINT32 pageIndex, const ULONG64 directoryBase, const ULONG64 directoryTableBase, const ULONG64 address, PVOID buffer, const SIZE_T size, SIZE_T* bytesWritten)
{
    if (pageIndex >= PageCount)
        return STATUS_INVALID_PARAMETER;

    SIZE_T currentOffset = 0;
    SIZE_T totalSize = size;
    while (totalSize)
    {
        const ULONG64 currentPhysicalAddress = ResolveProcessPhysicalAddressEx(pageIndex, directoryBase, directoryTableBase, address + currentOffset);
        if (!currentPhysicalAddress)
            return STATUS_NOT_FOUND;

        const ULONG64 writeSize = min(PAGE_SIZE - (currentPhysicalAddress & 0xFFF), totalSize);

        //
        // Re-walk the same virtual address immediately before the store.  The
        // guest owns the page tables the first walk read: it can remap the
        // address between that resolve and the memcpy below, which would turn
        // a validated user page into an arbitrary physical write (a classic
        // TOCTOU on a double-walk).  Only an identical PFN is accepted; a
        // changed - or now supervisor, or unmapped - entry aborts the copy.
        //
        const ULONG64 revalidatedPhysicalAddress = ResolveProcessPhysicalAddressEx(pageIndex, directoryBase, directoryTableBase, address + currentOffset);
        if ((revalidatedPhysicalAddress >> PAGE_SHIFT) != (currentPhysicalAddress >> PAGE_SHIFT))
            return STATUS_NOT_FOUND;

        if (!WritePhysicalAddress(pageIndex, currentPhysicalAddress, reinterpret_cast<PVOID>(reinterpret_cast<ULONG64>(buffer) + currentOffset), writeSize))
            return STATUS_INVALID_ADDRESS;

        totalSize -= writeSize;
        currentOffset += writeSize;
    }

    *bytesWritten = currentOffset;

    return STATUS_SUCCESS;
}

NTSTATUS Memory::CopyProcessMemoryEx(const UINT32 pageIndex, const ULONG64 sourceDirectoryBase, const ULONG64 sourceAddress, const ULONG64 targetDirectoryBase, const ULONG64 targetAddress, const ULONG64 currentDirectoryBase, const ULONG64 currentDirectoryTableBase, const SIZE_T bufferSize)
{
    //
    // The copy stages the whole request in one scratch page sized
    // Shared::MAX_RW_SIZE, so anything larger would overflow it.  The handler
    // caps the request as well, but the bound belongs here too: this function
    // is the one that owns the buffer.
    //
    if (bufferSize == 0 || bufferSize > Shared::MAX_RW_SIZE)
        return STATUS_INVALID_PARAMETER;

    if (pageIndex >= PageCount)
        return STATUS_INVALID_PARAMETER;

    if (!Utils::ValidUsermodeAddress(sourceAddress))
        return STATUS_INVALID_ADDRESS;

    if (!Utils::ValidUsermodeAddress(targetAddress))
        return STATUS_INVALID_ADDRESS;

    /*
     * Both directory bases come straight from the guest control block.  A
     * zero, misaligned or out-of-range CR3 makes the page walk read page
     * table entries from arbitrary physical memory, and on the target side
     * WritePhysicalAddress would then memcpy up to 64 KB into it.  A valid
     * directory base is 4 KB aligned and fits the 52-bit physical address
     * space, so anything else is rejected before the walk.
     *
     * Alignment alone is not enough: any aligned RAM page filled with
     * hand-built PTEs walks to arbitrary physical memory.  A directory base
     * that does not belong to a live process is refused, so only address
     * spaces the kernel itself built can be named.
     */
    if (sourceDirectoryBase == 0 || (sourceDirectoryBase & 0xFFF) != 0 ||
        sourceDirectoryBase > 0x000FFFFFFFFFF000ULL ||
        !Utils::IsValidDirectoryBase(sourceDirectoryBase))
        return STATUS_INVALID_ADDRESS;

    if (targetDirectoryBase == 0 || (targetDirectoryBase & 0xFFF) != 0 ||
        targetDirectoryBase > 0x000FFFFFFFFFF000ULL ||
        !Utils::IsValidDirectoryBase(targetDirectoryBase))
        return STATUS_INVALID_ADDRESS;

    /*
     * Validating only the base address lets a large size cross
     * MmHighestUserAddress (or wrap around); the complete range has to stay
     * inside user space on both sides.
     */
    if (bufferSize > Global::HighestUserAddress - sourceAddress)
        return STATUS_INVALID_ADDRESS;

    if (bufferSize > Global::HighestUserAddress - targetAddress)
        return STATUS_INVALID_ADDRESS;

    /*
     * currentDirectoryTableBase is the CR3 captured from the guest state
     * save area on VMEXIT, i.e. the directory base of the process that
     * issued the VMMCALL. It is only meaningful for the side of the copy
     * whose directory base the client declared as its own
     * (currentDirectoryBase); the other side belongs to a remote process
     * and is resolved from its kernel-side directory base alone.
     */
    const ULONG64 sourceDirectoryTableBase = sourceDirectoryBase == currentDirectoryBase ? currentDirectoryTableBase : 0;
    const ULONG64 targetDirectoryTableBase = targetDirectoryBase == currentDirectoryBase ? currentDirectoryTableBase : 0;

    const PAGE_INFO* pageInfo = &PageList[pageIndex];

    /*
     * Per-page copy.  The walk only resolves RESIDENT pages (present PTEs at
     * every level): a page that is paged out or committed-but-never-touched
     * (demand zero) has no translation.  Failing the whole request over one
     * such page would make large-region transfers unreliable, so a
     * non-resident chunk is skipped instead - reads of a demand-zero page
     * would be zeros anyway, and skipping the destination bytes leaves them
     * untouched rather than writing zeros over them.  The control-block read
     * in HandleCopyProcessMemory stays strict: the caller's own stack is
     * always resident.
     */
    SIZE_T offset = 0;
    SIZE_T skippedChunks = 0;

    while (offset < bufferSize)
    {
        const ULONG64 remaining = bufferSize - offset;
        const ULONG64 sourceChunkAddress = sourceAddress + offset;
        const ULONG64 targetChunkAddress = targetAddress + offset;

        //
        // Source: resolve, then read up to the source page boundary.
        //
        const ULONG64 sourcePhysical = ResolveProcessPhysicalAddressEx(pageIndex, sourceDirectoryBase, sourceDirectoryTableBase, sourceChunkAddress);
        if (!sourcePhysical)
        {
            offset += min(PAGE_SIZE - (sourceChunkAddress & 0xFFF), remaining);
            skippedChunks++;
            continue;
        }

        const ULONG64 sourceRemainder = min(PAGE_SIZE - (sourcePhysical & 0xFFF), remaining);

        //
        // Destination: resolve, then clamp the chunk to the destination page
        // boundary so the write below can never run past the page the
        // scratch mapping covers.
        //
        const ULONG64 targetPhysical = ResolveProcessPhysicalAddressEx(pageIndex, targetDirectoryBase, targetDirectoryTableBase, targetChunkAddress);
        if (!targetPhysical)
        {
            offset += min(sourceRemainder, remaining);
            skippedChunks++;
            continue;
        }

        const ULONG64 chunkSize = min(sourceRemainder, PAGE_SIZE - (targetPhysical & 0xFFF));

        if (!ReadPhysicalAddress(pageIndex, sourcePhysical, reinterpret_cast<PBYTE>(pageInfo->CopyBuffer) + offset, chunkSize))
        {
            offset += chunkSize;
            skippedChunks++;
            continue;
        }

        //
        // Re-walk the same destination address immediately before the store.
        // The guest owns the page tables the first walk read: it can remap
        // the address between that resolve and the memcpy below, which would
        // turn a validated user page into an arbitrary physical write (a
        // classic TOCTOU on a double-walk).  Only an identical PFN is
        // accepted; a changed - or now unmapped - entry skips the chunk.
        //
        const ULONG64 revalidatedPhysical = ResolveProcessPhysicalAddressEx(pageIndex, targetDirectoryBase, targetDirectoryTableBase, targetChunkAddress);
        if ((revalidatedPhysical >> PAGE_SHIFT) != (targetPhysical >> PAGE_SHIFT))
        {
            offset += chunkSize;
            skippedChunks++;
            continue;
        }

        if (!WritePhysicalAddress(pageIndex, targetPhysical, reinterpret_cast<PBYTE>(pageInfo->CopyBuffer) + offset, chunkSize))
        {
            offset += chunkSize;
            skippedChunks++;
            continue;
        }

        offset += chunkSize;
    }

    if (skippedChunks)
        HV::LogNum("CopyProcessMemoryEx: skipped non-resident chunks", skippedChunks);

    return STATUS_SUCCESS;
}