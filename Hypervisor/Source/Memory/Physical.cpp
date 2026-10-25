#include "../Core/Global.h"

static Memory::PAGE_INFO* PageList = nullptr;
static UINT32 PageListCount = 0;

namespace
{
    void ReleasePageInfo(Memory::PAGE_INFO* page)
    {
        if (!page)
            return;

        if (page->CopyBuffer)
        {
            ExFreePool(page->CopyBuffer);
            page->CopyBuffer = nullptr;
        }

        if (page->VirtualAddress)
        {
            MmFreeContiguousMemory(page->VirtualAddress);
            page->VirtualAddress = nullptr;
        }

        page->PageEntry = nullptr;
    }
}

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
    if (pageIndex >= PageListCount || directoryBase == 0 || (directoryBase & 0xFFF) != 0)
        return 0;

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
    const ULONG64 pml4eAddress = pml4Page + virtualAddress.Pml4Index * sizeof(PML4E);
    if (!ReadPhysicalAddress(page, pml4eAddress, &pml4e, sizeof(PML4E)))
        return 0;

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
    const ULONG64 pdpteAddress = pdptPage + virtualAddress.PdptIndex * sizeof(PDPTE);
    if (!ReadPhysicalAddress(page, pdpteAddress, &pdpte, sizeof(PDPTE)))
        return 0;

    if (!pdpte.Present || !pdpte.User)
        return 0;

    /*
     * In a large-page entry bit 12 is PAT, not part of the physical address
     * (1 GB: address bits 51:30, PAT at 12; 2 MB: address bits 51:21, PAT at
     * 12).  Pd/Pt span bits 51:12, so PFN_TO_PAGE() folds that PAT bit into
     * the frame and would return an address 4 KB past the real page.
     */
    // If 1GB page
    if (pdpte.PageSize)
        return (PFN_TO_PAGE(pdpte.Pd) & ~(1ULL << PAGE_SHIFT)) + virtualAddress.Offset1gb;

    const ULONG64 pdPage = PFN_TO_PAGE(pdpte.Pd);
    if (!Utils::IsPhysicalRangeValid(pdPage, PAGE_SIZE))
        return 0;

    PDE pde;
    const ULONG64 pdeAddress = pdPage + virtualAddress.PdIndex * sizeof(PDE);
    if (!ReadPhysicalAddress(page, pdeAddress, &pde, sizeof(PDE)))
        return 0;

    if (!pde.Present || !pde.User)
        return 0;

    // If 2MB page
    if (pde.PageSize)
        return (PFN_TO_PAGE(pde.Pt) & ~(1ULL << PAGE_SHIFT)) + virtualAddress.Offset2mb;

    const ULONG64 ptPage = PFN_TO_PAGE(pde.Pt);
    if (!Utils::IsPhysicalRangeValid(ptPage, PAGE_SIZE))
        return 0;

    PTE pte;
    const ULONG64 pteAddress = ptPage + virtualAddress.PtIndex * sizeof(PTE);
    if (!ReadPhysicalAddress(page, pteAddress, &pte, sizeof(PTE)))
        return 0;

    if (!pte.Present || !pte.User)
        return 0;

    return PFN_TO_PAGE(pte.PageFrame) + virtualAddress.Offset4kb;
}

Memory::PTE* Memory::GetPte(const ULONG64 address, const ULONG64 directoryBase)
{
    VIRTUAL_ADDRESS virtualAddress;
    virtualAddress.Value = address;

    PTE_CR3 cr3;
    cr3.Value = directoryBase;

    PML4E* pml4 = reinterpret_cast<PML4E*>(PhysicalToVirtual(PFN_TO_PAGE(cr3.Pml4)));
    if (!pml4)
        return nullptr;

    const PML4E* pml4e = (pml4 + virtualAddress.Pml4Index);
    if (!pml4e->Present)
        return nullptr;

    PDPTE* pdpt = reinterpret_cast<PDPTE*>(PhysicalToVirtual(PFN_TO_PAGE(pml4e->Pdpt)));
    if (!pdpt)
        return nullptr;

    const PDPTE* pdpte = (pdpt + virtualAddress.PdptIndex);
    if (!pdpte->Present)
        return nullptr;

    // sanity check 1GB page
    if (pdpte->PageSize)
        return nullptr;

    PDE* pd = reinterpret_cast<PDE*>(PhysicalToVirtual(PFN_TO_PAGE(pdpte->Pd)));
    if (!pd)
        return nullptr;

    const PDE* pde = (pd + virtualAddress.PdIndex);
    if (!pde->Present)
        return nullptr;

    // sanity check 2MB page
    if (pde->PageSize)
        return nullptr;

    PTE* pt = reinterpret_cast<PTE*>(PhysicalToVirtual(PFN_TO_PAGE(pde->Pt)));
    if (!pt)
        return nullptr;

    PTE* pte = (pt + virtualAddress.PtIndex);
    if (!pte->Present)
        return nullptr;

    return pte;
}

bool Memory::PreparePage(PAGE_INFO* targetPage)
{
    RtlZeroMemory(targetPage, sizeof(*targetPage));

    PHYSICAL_ADDRESS maxAddress;
    maxAddress.QuadPart = MAXULONG64;

    targetPage->VirtualAddress = MmAllocateContiguousMemory(PAGE_SIZE, maxAddress);
    if (!targetPage->VirtualAddress)
        return false;

    targetPage->CopyBuffer = ExAllocatePool(NonPagedPool, Shared::MAX_RW_SIZE);
    if (!targetPage->CopyBuffer)
    {
        ReleasePageInfo(targetPage);
        return false;
    }

    targetPage->PageEntry = GetPte(reinterpret_cast<ULONG64>(targetPage->VirtualAddress), __readcr3());
    if (!targetPage->PageEntry)
    {
        ReleasePageInfo(targetPage);
        return false;
    }

    return true;
}

bool Memory::PreparePages()
{
    if (!PageList)
    {
        //
        // The processor index is system-wide and can exceed the active
        // processor count on a multi-group machine.  Size the scratch table
        // from the maximum configured processor count, not a hard-coded 64,
        // so every CPU has a slot for the driver's lifetime.
        //
        PageListCount = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
        if (PageListCount == 0)
            PageListCount = 64;

        PageList = static_cast<PAGE_INFO*>(ExAllocatePool(
            NonPagedPool, sizeof(PAGE_INFO) * PageListCount));
        if (!PageList)
            return false;

        RtlZeroMemory(PageList, sizeof(PAGE_INFO) * PageListCount);
    }

    for (UINT32 i = 0; i < PageListCount; i++)
    {
        if (!PreparePage(&PageList[i]))
        {
            for (UINT32 j = 0; j <= i; j++)
                ReleasePageInfo(&PageList[j]);

            return false;
        }
    }

    return true;
}

PVOID Memory::OverwritePage(const UINT32 pageIndex, const ULONG64 physicalAddress)
{
    if (pageIndex >= PageListCount || !PageList[pageIndex].PageEntry)
        return nullptr;

    const ULONG pageOffset = static_cast<ULONG>(physicalAddress & (PAGE_SIZE - 1));
    const ULONG64 pageStartPhysical = physicalAddress - pageOffset;

    PAGE_INFO* pageInfo = &PageList[pageIndex];
    pageInfo->PreviousPageFrame = pageInfo->PageEntry->PageFrame;
    pageInfo->PageEntry->PageFrame = PAGE_TO_PFN(pageStartPhysical);
    __invlpg(pageInfo->VirtualAddress);

    return reinterpret_cast<PVOID>(reinterpret_cast<ULONG64>(pageInfo->VirtualAddress) + pageOffset);
}

void Memory::RestorePage(const UINT32 pageIndex)
{
    if (pageIndex >= PageListCount || !PageList[pageIndex].PageEntry)
        return;

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
    if (pageIndex >= PageListCount || !buffer || size == 0 || size > PAGE_SIZE)
        return false;

    if (!Utils::IsPhysicalRangeValid(targetAddress, size))
        return false;

    const PVOID virtualAddress = OverwritePage(pageIndex, targetAddress);
    if (!virtualAddress)
        return false;

    memcpy(buffer, virtualAddress, size);
    RestorePage(pageIndex);

    return true;
}

bool Memory::WritePhysicalAddress(const UINT32 pageIndex, const ULONG64 targetAddress, const PVOID buffer, const SIZE_T size)
{
    // See ReadPhysicalAddress: a non-RAM target must never be mapped, and on
    // the copy path this is the guest-declared destination.
    if (pageIndex >= PageListCount || !buffer || size == 0 || size > PAGE_SIZE)
        return false;

    if (!Utils::IsPhysicalRangeValid(targetAddress, size))
        return false;

    const PVOID virtualAddress = OverwritePage(pageIndex, targetAddress);
    if (!virtualAddress)
        return false;

    memcpy(virtualAddress, buffer, size);
    RestorePage(pageIndex);

    return true;
}

NTSTATUS Memory::ReadProcessMemoryEx(const UINT32 pageIndex, const ULONG64 directoryBase, const ULONG64 address, PVOID buffer, const SIZE_T size, SIZE_T* bytesRead)
{
    if (pageIndex >= PageListCount || !buffer || !bytesRead || size == 0)
        return STATUS_INVALID_PARAMETER;

    SIZE_T currentOffset = 0;
    while (currentOffset < size)
    {
        const ULONG64 currentPhysicalAddress = ResolveProcessPhysicalAddress(pageIndex, directoryBase, address + currentOffset);
        if (!currentPhysicalAddress)
            return STATUS_NOT_FOUND;

        const ULONG64 readSize = min(PAGE_SIZE - (currentPhysicalAddress & 0xFFF), size - currentOffset);

        if (!ReadPhysicalAddress(pageIndex, currentPhysicalAddress, reinterpret_cast<PBYTE>(buffer) + currentOffset, static_cast<SIZE_T>(readSize)))
            return STATUS_INVALID_ADDRESS;

        currentOffset += static_cast<SIZE_T>(readSize);
    }

    *bytesRead = currentOffset;

    return STATUS_SUCCESS;
}

NTSTATUS Memory::WriteProcessMemoryEx(const UINT32 pageIndex, const ULONG64 directoryBase, const ULONG64 address, PVOID buffer, const SIZE_T size, SIZE_T* bytesWritten)
{
    if (pageIndex >= PageListCount || !buffer || !bytesWritten || size == 0)
        return STATUS_INVALID_PARAMETER;

    SIZE_T currentOffset = 0;
    while (currentOffset < size)
    {
        const ULONG64 currentPhysicalAddress = ResolveProcessPhysicalAddress(pageIndex, directoryBase, address + currentOffset);
        if (!currentPhysicalAddress)
            return STATUS_NOT_FOUND;

        const ULONG64 writeSize = min(PAGE_SIZE - (currentPhysicalAddress & 0xFFF), size - currentOffset);

        //
        // Re-walk the same virtual address immediately before the store.  The
        // guest owns the page tables the first walk read: it can remap the
        // address between that resolve and the memcpy below, which would turn
        // a validated user page into an arbitrary physical write (a classic
        // TOCTOU on a double-walk).  Only an identical PFN is accepted; a
        // changed - or now supervisor, or unmapped - entry aborts the copy.
        //
        const ULONG64 revalidatedPhysicalAddress = ResolveProcessPhysicalAddress(pageIndex, directoryBase, address + currentOffset);
        if ((revalidatedPhysicalAddress >> PAGE_SHIFT) != (currentPhysicalAddress >> PAGE_SHIFT))
            return STATUS_NOT_FOUND;

        if (!WritePhysicalAddress(pageIndex, currentPhysicalAddress, reinterpret_cast<PBYTE>(buffer) + currentOffset, static_cast<SIZE_T>(writeSize)))
            return STATUS_INVALID_ADDRESS;

        currentOffset += static_cast<SIZE_T>(writeSize);
    }

    *bytesWritten = currentOffset;

    return STATUS_SUCCESS;
}

NTSTATUS Memory::CopyProcessMemoryEx(const UINT32 pageIndex, const ULONG64 sourceDirectoryBase, const ULONG64 sourceAddress, const ULONG64 targetDirectoryBase, const ULONG64 targetAddress, const SIZE_T bufferSize)
{
    //
    // The copy stages the whole request in one scratch page sized
    // Shared::MAX_RW_SIZE, so anything larger would overflow it.  The handler
    // caps the request as well, but the bound belongs here too: this function
    // is the one that owns the buffer.
    //
    if (bufferSize == 0 || bufferSize > Shared::MAX_RW_SIZE)
        return STATUS_INVALID_PARAMETER;

    if (pageIndex >= PageListCount || !PageList[pageIndex].CopyBuffer)
        return STATUS_INVALID_PARAMETER;

    if (!Utils::ValidUsermodeAddress(sourceAddress) ||
        !Utils::ValidUsermodeAddress(targetAddress))
        return STATUS_INVALID_ADDRESS;

    /*
     * Both directory bases come from EPROCESS objects resolved by PID in the
     * handler, so they cannot be arbitrary guest-supplied pages.  Keep the
     * architectural sanity checks here as a second line of defence.
     */
    if (sourceDirectoryBase == 0 || (sourceDirectoryBase & 0xFFF) != 0 ||
        sourceDirectoryBase > 0x000FFFFFFFFFF000ULL)
        return STATUS_INVALID_ADDRESS;

    if (targetDirectoryBase == 0 || (targetDirectoryBase & 0xFFF) != 0 ||
        targetDirectoryBase > 0x000FFFFFFFFFF000ULL)
        return STATUS_INVALID_ADDRESS;

    /*
     * Validating only the base address lets a large size cross
     * MmHighestUserAddress (or wrap around); the complete range has to stay
     * inside user space on both sides.
     */
    if (bufferSize > Global::HighestUserAddress - sourceAddress ||
        bufferSize > Global::HighestUserAddress - targetAddress)
        return STATUS_INVALID_ADDRESS;

    const PAGE_INFO* pageInfo = &PageList[pageIndex];

    /*
     * Per-page copy.  Both translations must be resident: the copy path
     * resolves through physical page tables, and a non-resident page has no
     * PFN to read or write.  Fail the request instead of silently skipping
     * chunks - a caller that receives Success must be able to trust that all
     * bytes were transferred.
     */
    SIZE_T offset = 0;
    while (offset < bufferSize)
    {
        const ULONG64 remaining = bufferSize - offset;
        const ULONG64 sourceChunkAddress = sourceAddress + offset;
        const ULONG64 targetChunkAddress = targetAddress + offset;

        const ULONG64 sourcePhysical = ResolveProcessPhysicalAddress(pageIndex, sourceDirectoryBase, sourceChunkAddress);
        if (!sourcePhysical)
            return STATUS_NOT_FOUND;

        const ULONG64 targetPhysical = ResolveProcessPhysicalAddress(pageIndex, targetDirectoryBase, targetChunkAddress);
        if (!targetPhysical)
            return STATUS_NOT_FOUND;

        const ULONG64 chunkSize = min(
            min(PAGE_SIZE - (sourcePhysical & 0xFFF), PAGE_SIZE - (targetPhysical & 0xFFF)),
            remaining);

        if (!ReadPhysicalAddress(pageIndex, sourcePhysical,
            reinterpret_cast<PBYTE>(pageInfo->CopyBuffer) + offset, static_cast<SIZE_T>(chunkSize)))
            return STATUS_INVALID_ADDRESS;

        //
        // Re-walk the destination immediately before the store.  The guest
        // owns the page tables the first walk read: it can remap the address
        // between that resolve and the memcpy below, which would turn a
        // validated user page into an arbitrary physical write.  Only an
        // identical PFN is accepted.
        //
        const ULONG64 revalidatedPhysical = ResolveProcessPhysicalAddress(pageIndex, targetDirectoryBase, targetChunkAddress);
        if ((revalidatedPhysical >> PAGE_SHIFT) != (targetPhysical >> PAGE_SHIFT))
            return STATUS_NOT_FOUND;

        if (!WritePhysicalAddress(pageIndex, targetPhysical,
            reinterpret_cast<PBYTE>(pageInfo->CopyBuffer) + offset, static_cast<SIZE_T>(chunkSize)))
            return STATUS_INVALID_ADDRESS;

        offset += static_cast<SIZE_T>(chunkSize);
    }

    return STATUS_SUCCESS;
}
