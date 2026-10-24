#include "../Global.h"

constexpr UINT32 PageCount = 64;
static Memory::PAGE_INFO PageList[PageCount];

ULONG64 Memory::GetDirectoryBase(const PEPROCESS process)
{
    /*
     * Offset resolved at boot by Utils::GetOffsets() from the running
     * kernel image (PsGetProcessDirectoryBase pattern); falls back to the
     * 0x28 default when the pattern scan fails.
     */
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

    PML4E pml4e;
    ULONG64 pml4eAddress = PFN_TO_PAGE(cr3.Pml4) + virtualAddress.Pml4Index * sizeof(PML4E);
    ReadPhysicalAddress(page, pml4eAddress, &pml4e, sizeof(PML4E));
    if (!pml4e.Present)
        return 0;

    PDPTE pdpte;
    ULONG64 pdpteAddress = PFN_TO_PAGE(pml4e.Pdpt) + virtualAddress.PdptIndex * sizeof(PDPTE);
    ReadPhysicalAddress(page, pdpteAddress, &pdpte, sizeof(PDPTE));
    if (!pdpte.Present)
        return 0;

    // If 1GB page
    if (pdpte.PageSize)
        return PFN_TO_PAGE(pdpte.Pd) + virtualAddress.Offset1gb;

    PDE pde;
    ULONG64 pdeAddress = PFN_TO_PAGE(pdpte.Pd) + virtualAddress.PdIndex * sizeof(PDE);
    ReadPhysicalAddress(page, pdeAddress, &pde, sizeof(PDE));
    if (!pde.Present)
        return 0;

    // If 2MB page
    if (pde.PageSize)
        return PFN_TO_PAGE(pde.Pt) + virtualAddress.Offset2mb;

    PTE pte;
    ULONG64 pteAddress = PFN_TO_PAGE(pde.Pt) + virtualAddress.PtIndex * sizeof(PTE);
    ReadPhysicalAddress(page, pteAddress, &pte, sizeof(PTE));
    if (!pte.Present)
        return 0;

    return PFN_TO_PAGE(pte.PageFrame) + virtualAddress.Offset4kb;
}

/*
 * Some anti-cheats protect a process by making its kernel-side directory
 * base (EPROCESS + 0x28) diverge from the CR3 value that is actually loaded
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

void Memory::ReadPhysicalAddress(const UINT32 pageIndex, const ULONG64 targetAddress, const PVOID buffer, const SIZE_T size)
{
    const PVOID virtualAddress = OverwritePage(pageIndex, targetAddress);
    memcpy(buffer, virtualAddress, size);
    RestorePage(pageIndex);
}

void Memory::WritePhysicalAddress(const UINT32 pageIndex, const ULONG64 targetAddress, const PVOID buffer, const SIZE_T size)
{
    const PVOID virtualAddress = OverwritePage(pageIndex, targetAddress);
    memcpy(virtualAddress, buffer, size);
    RestorePage(pageIndex);
}

NTSTATUS Memory::ReadProcessMemoryEx(const UINT32 pageIndex, const ULONG64 directoryBase, const ULONG64 directoryTableBase, const ULONG64 address, PVOID buffer, const SIZE_T size, SIZE_T* bytesRead)
{
    SIZE_T currentOffset = 0;
    SIZE_T totalSize = size;
    while (totalSize)
    {
        const ULONG64 currentPhysicalAddress = ResolveProcessPhysicalAddressEx(pageIndex, directoryBase, directoryTableBase, address + currentOffset);
        if (!currentPhysicalAddress)
            return STATUS_NOT_FOUND;

        const ULONG64 readSize = min(PAGE_SIZE - (currentPhysicalAddress & 0xFFF), totalSize);

        ReadPhysicalAddress(pageIndex, currentPhysicalAddress, reinterpret_cast<PVOID>(reinterpret_cast<ULONG64>(buffer) + currentOffset), readSize);

        totalSize -= readSize;
        currentOffset += readSize;
    }

    *bytesRead = currentOffset;

    return STATUS_SUCCESS;
}

NTSTATUS Memory::WriteProcessMemoryEx(const UINT32 pageIndex, const ULONG64 directoryBase, const ULONG64 directoryTableBase, const ULONG64 address, PVOID buffer, const SIZE_T size, SIZE_T* bytesWritten)
{
    SIZE_T currentOffset = 0;
    SIZE_T totalSize = size;
    while (totalSize)
    {
        const ULONG64 currentPhysicalAddress = ResolveProcessPhysicalAddressEx(pageIndex, directoryBase, directoryTableBase, address + currentOffset);
        if (!currentPhysicalAddress)
            return STATUS_NOT_FOUND;

        const ULONG64 writeSize = min(PAGE_SIZE - (currentPhysicalAddress & 0xFFF), totalSize);

        WritePhysicalAddress(pageIndex, currentPhysicalAddress, reinterpret_cast<PVOID>(reinterpret_cast<ULONG64>(buffer) + currentOffset), writeSize);

        totalSize -= writeSize;
        currentOffset += writeSize;
    }

    *bytesWritten = currentOffset;

    return STATUS_SUCCESS;
}

NTSTATUS Memory::CopyProcessMemoryEx(const UINT32 pageIndex, const ULONG64 sourceDirectoryBase, const ULONG64 sourceAddress, const ULONG64 targetDirectoryBase, const ULONG64 targetAddress, const ULONG64 currentDirectoryBase, const ULONG64 currentDirectoryTableBase, const SIZE_T bufferSize)
{
    if (!Utils::ValidUsermodeAddress(sourceAddress))
        return STATUS_INVALID_ADDRESS;

    if (!Utils::ValidUsermodeAddress(targetAddress))
        return STATUS_INVALID_ADDRESS;

    /*
     * currentDirectoryTableBase is the CR3 captured from the guest state
     * save area on VMEXIT, i.e. the directory base of the process that
     * issued the VMMCALL. It is only meaningful for the side of the copy
     * whose directory base the client declared as its own
     * (currentDirectoryBase); the other side belongs to a remote process
     * and is resolved from its kernel-side directory base alone. Every
     * page is resolved immediately before it is accessed, so a fallback
     * switch between the two bases stays safe even for a copy spanning
     * many pages.
     */
    const ULONG64 sourceDirectoryTableBase = sourceDirectoryBase == currentDirectoryBase ? currentDirectoryTableBase : 0;
    const ULONG64 targetDirectoryTableBase = targetDirectoryBase == currentDirectoryBase ? currentDirectoryTableBase : 0;

    const PAGE_INFO* pageInfo = &PageList[pageIndex];

    SIZE_T bytes = 0;
    NTSTATUS status = ReadProcessMemoryEx(pageIndex, sourceDirectoryBase, sourceDirectoryTableBase, sourceAddress, pageInfo->CopyBuffer, bufferSize, &bytes);
    if (!NT_SUCCESS(status))
        return STATUS_ABANDONED;

    return WriteProcessMemoryEx(pageIndex, targetDirectoryBase, targetDirectoryTableBase, targetAddress, pageInfo->CopyBuffer, bufferSize, &bytes);
}