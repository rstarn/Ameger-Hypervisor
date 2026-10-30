//
// PortableExecutable.cpp - kernel-mode PE loader implementation.
//
// Reads a PE image (Hypervisor.sys) from a kernel NT path, maps it into
// NonPagedPool while preserving the PE headers, applies base relocations,
// resolves imports against ntoskrnl via MmGetSystemRoutineAddress, and
// invokes the image's entry point with a synthetic DRIVER_OBJECT.
//
#include <ntifs.h>
#include <ntimage.h>
#include <wdm.h>
#include "PortableExecutable.h"

//
// The kernel's ntimage.h does not define a 16-bit base-relocation entry
// type, so define the layout locally: upper 4 bits = relocation type,
// lower 12 bits = offset within the 64 KB page.
//
struct BASE_RELOCATION_ENTRY
{
    UINT16 Value;
};

//
// Minimal self-contained logging for the mapper (no Hypervisor:: logging,
// which lives in Hypervisor.sys).  Routes through DbgPrint so nothing in the
// mapper's own build is needed.
//
#define MAPPER_LOG(fmt, ...) DbgPrint("[Mapper] " fmt, ##__VA_ARGS__)

//
// Pool tag ('Thre') for every allocation the loader makes; shared with
// Main.cpp through the header constant PELOADER_POOL_TAG.
//

// Minimal, plausible service registry path for the mapped driver's service.
// Mirrors what the kernel would hand a normally-registered driver, so any
// registry access the mapped driver performs resolves against a real key.
static const wchar_t* const MAPPER_SERVICE_REGISTRY_PATH =
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MappedHv";

NTSTATUS PeLoaderReadFile(_In_ PCWSTR ImagePath, _Out_ PVOID* OutBuffer, _Out_ SIZE_T* OutSize)
{
    *OutBuffer = nullptr;
    *OutSize = 0;

    HANDLE fileHandle = 0;

    //
    // Open the file for synchronous read-only access.  FILE_OPEN_IF_EXISTS
    // (1) makes a missing file fail closed with STATUS_OBJECT_NAME_NOT_FOUND.
    //
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, ImagePath);
    // Macro expands to (p=attributes, n=object name, a=attributes, r=rootdir, s=security descriptor).
    InitializeObjectAttributes(&oa, &name, OBJ_KERNEL_HANDLE, NULL, NULL);

    IO_STATUS_BLOCK iob;
    //
    // 6-arg prototype: (FileHandle, DesiredAccess, ObjectAttributes,
    // IoStatusBlock, ShareAccess, OpenOptions).  Disposition and file
    // attributes are both encoded in OpenOptions (disposition in the low
    // bits, attributes in the high bits).
    //
    const ULONG openOptions = 0x4 /*FILE_OPEN_IF_EXISTS*/ | 0x80 /*FILE_ATTRIBUTE_NORMAL*/;
    NTSTATUS status = ZwOpenFile(&fileHandle,
                                 0x80000000 /*GENERIC_READ*/ | 0x10000000 /*SYNCHRONIZE*/,
                                 &oa, &iob,
                                 0x1 /*FILE_SHARE_READ*/, openOptions);
    if (!NT_SUCCESS(status))
        return status;

    //
    // Query the file size before allocating the read buffer.
    //
    FILE_STANDARD_INFORMATION fsi;
    // Prototype: (FileHandle, IoStatusBlock, FileInformation buffer, Length, Class).
    // Length is ULONG; sizeof(fsi) is size_t, so cast explicitly (avoids C4244 under /WX).
    status = ZwQueryInformationFile(fileHandle, &iob, &fsi, static_cast<ULONG>(sizeof(fsi)), FileStandardInformation);
    if (!NT_SUCCESS(status))
    {
        ZwClose(fileHandle);
        return status;
    }

    SIZE_T fileSize = static_cast<SIZE_T>(fsi.EndOfFile.QuadPart);
    if (fileSize == 0)
    {
        ZwClose(fileHandle);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // ZwReadFile takes a ULONG length, and the loader's size arithmetic below
    // is SIZE_T.  A file that does not fit in a ULONG (or a corrupt negative
    // EndOfFile) is not a driver image; reject it instead of truncating the
    // read and validating a half-loaded image.
    //
    if (fileSize > 0x7FFFFFFFull)
    {
        ZwClose(fileHandle);
        return STATUS_FILE_TOO_LARGE;
    }

    //
    // Allocate the buffer (tagged) and read the whole file into it.
    //
    PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, fileSize + PAGE_SIZE, PELOADER_POOL_TAG);
    if (!buffer)
    {
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Prototype: (FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
    // Buffer, Length, ByteOffset, Key).  Synchronous read from offset 0.
    //
    LARGE_INTEGER byteOffset;
    byteOffset.QuadPart = 0;
    // Length parameter is ULONG; fileSize is SIZE_T, so cast explicitly
    // to avoid the C4244 (SIZE_T -> ULONG) warning that /WX turns into C2220.
    status = ZwReadFile(fileHandle, NULL, NULL, NULL, &iob, buffer, static_cast<ULONG>(fileSize), &byteOffset, NULL);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(buffer, PELOADER_POOL_TAG);
        ZwClose(fileHandle);
        return status;
    }

    ZwClose(fileHandle);

    *OutBuffer = buffer;
    *OutSize = fileSize;
    return STATUS_SUCCESS;
}

NTSTATUS PeLoaderValidate(_In_ PVOID FileBuffer, _In_ SIZE_T FileSize)
{
    const BYTE* file = static_cast<const BYTE*>(FileBuffer);

    if (FileSize < sizeof(IMAGE_DOS_HEADER))
        return STATUS_INVALID_IMAGE_FORMAT;

    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return STATUS_INVALID_IMAGE_FORMAT;

    if (FileSize < static_cast<SIZE_T>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64))
        return STATUS_INVALID_IMAGE_FORMAT;

    const IMAGE_NT_HEADERS64* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(file + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return STATUS_INVALID_IMAGE_FORMAT;

    //
    // Only PE32+ (PE64) images are supported: the kernel's ntimage.h uses
    // the 0x20b magic for the 64-bit optional header.
    //
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC /*0x20b*/)
        return STATUS_INVALID_IMAGE_FORMAT;

    if (nt->OptionalHeader.SizeOfImage == 0)
        return STATUS_INVALID_IMAGE_FORMAT;

    if (nt->FileHeader.NumberOfSections == 0)
        return STATUS_INVALID_IMAGE_FORMAT;

    //
    // The section table is located through SizeOfOptionalHeader, which is
    // itself file-controlled: make sure the whole table lies inside the file
    // before any caller walks it.
    //
    const SIZE_T sectionTableOffset =
        static_cast<SIZE_T>(dos->e_lfanew) +
        FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +
        nt->FileHeader.SizeOfOptionalHeader;
    const SIZE_T sectionTableSize =
        static_cast<SIZE_T>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (sectionTableOffset > FileSize || sectionTableSize > FileSize - sectionTableOffset)
        return STATUS_INVALID_IMAGE_FORMAT;

    //
    // Require at least one .text section (matches the existing
    // GetDriverTextRange convention of comparing 8-byte names with _stricmp).
    //
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    bool hasText = false;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
    {
        if (_stricmp(reinterpret_cast<const char*>(section->Name), ".text") == 0)
        {
            hasText = true;
            break;
        }
    }
    if (!hasText)
        return STATUS_INVALID_IMAGE_FORMAT;

    return STATUS_SUCCESS;
}

NTSTATUS PeLoaderMapImage(_In_ PVOID FileBuffer, _In_ SIZE_T FileSize, _Out_ PVOID* OutMappedBase, _Out_ SIZE_T* OutImageSize)
{
    *OutMappedBase = nullptr;
    *OutImageSize = 0;

    const BYTE* file = static_cast<const BYTE*>(FileBuffer);
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file);
    const IMAGE_NT_HEADERS64* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(file + dos->e_lfanew);

    const IMAGE_OPTIONAL_HEADER64& opt = nt->OptionalHeader;
    const SIZE_T imageSize = static_cast<SIZE_T>(opt.SizeOfImage);

    //
    // Allocate the whole SizeOfImage region in NonPagedPool (tagged).
    //
    BYTE* mapped = static_cast<BYTE*>(ExAllocatePoolWithTag(NonPagedPool, imageSize, PELOADER_POOL_TAG));
    if (!mapped)
        return STATUS_INSUFFICIENT_RESOURCES;

    //
    // ExAllocatePoolWithTag returns uninitialised memory.  Everything the
    // image does not explicitly cover - the gap between SizeOfHeaders and the
    // first section, the space between a section's raw data and its
    // VirtualSize, and the tail up to SizeOfImage - is part of the loaded
    // image as far as the driver is concerned: .bss-style globals live there
    // and must read as zero.  Zeroing the whole allocation up front makes
    // every one of those regions deterministic and makes the per-section
    // padding below unnecessary.
    //
    RtlZeroMemory(mapped, imageSize);

    //
    // Preserve the PE headers verbatim: copy the first SizeOfHeaders bytes
    // (MZ / PE signature / Optional Header / Section Table) so the mapped base
    // keeps a valid, parseable header block.  Both bounds matter: the headers
    // must exist in the file and must fit inside the image we allocated.
    //
    const SIZE_T headersSize = static_cast<SIZE_T>(opt.SizeOfHeaders);
    if (FileSize < headersSize || headersSize > imageSize)
    {
        ExFreePoolWithTag(mapped, PELOADER_POOL_TAG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    memcpy(mapped, file, headersSize);

    //
    // Copy each section's raw data into its virtual location.  Every offset
    // and length comes from the file and is validated against both buffers
    // before the copy: a malformed SizeOfImage/VirtualAddress pair would
    // otherwise write past the pool allocation.
    //
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
    {
        const SIZE_T virtualSize = static_cast<SIZE_T>(section->Misc.VirtualSize);
        const SIZE_T rawSize = static_cast<SIZE_T>(section->SizeOfRawData);
        const SIZE_T copySize = rawSize < virtualSize ? rawSize : virtualSize;
        const SIZE_T srcOffset = static_cast<SIZE_T>(section->PointerToRawData);
        const SIZE_T dstOffset = static_cast<SIZE_T>(section->VirtualAddress);

        if (dstOffset > imageSize || virtualSize > imageSize - dstOffset)
        {
            ExFreePoolWithTag(mapped, PELOADER_POOL_TAG);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        if (copySize > FileSize || srcOffset > FileSize - copySize)
        {
            ExFreePoolWithTag(mapped, PELOADER_POOL_TAG);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        memcpy(mapped + dstOffset, file + srcOffset, copySize);
        //
        // The [VirtualAddress + SizeOfRawData, VirtualAddress + VirtualSize)
        // tail is already zero from the RtlZeroMemory above.
        //
    }

    *OutMappedBase = mapped;
    *OutImageSize = imageSize;
    return STATUS_SUCCESS;
}

NTSTATUS PeLoaderApplyRelocations(_In_ PVOID MappedBase)
{
    BYTE* image = static_cast<BYTE*>(MappedBase);
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    const IMAGE_NT_HEADERS64* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    const IMAGE_OPTIONAL_HEADER64& opt = nt->OptionalHeader;

    //
    // delta = MappedBase - preferred ImageBase.  A zero delta (mapped at the
    // preferred base) needs no relocations.
    //
    const UINT64 delta = reinterpret_cast<UINT64>(MappedBase) - opt.ImageBase;
    if (delta == 0)
        return STATUS_SUCCESS;

    //
    // Locate the .reloc section; its VirtualAddress is the first relocation
    // block (RVA).
    //
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    PIMAGE_SECTION_HEADER relocSection = nullptr;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
    {
        if (_stricmp(reinterpret_cast<const char*>(section->Name), ".reloc") == 0)
        {
            relocSection = section;
            break;
        }
    }
    if (!relocSection)
        return STATUS_SUCCESS; // No .reloc section: nothing to relocate.

    const SIZE_T imageSize = static_cast<SIZE_T>(opt.SizeOfImage);
    if (relocSection->VirtualAddress >= imageSize)
        return STATUS_INVALID_IMAGE_FORMAT;

    BYTE* relocTable = image + relocSection->VirtualAddress;
    const SIZE_T tableSize = (static_cast<SIZE_T>(relocSection->Misc.VirtualSize) < imageSize - relocSection->VirtualAddress)
        ? static_cast<SIZE_T>(relocSection->Misc.VirtualSize)
        : imageSize - relocSection->VirtualAddress;

    SIZE_T offset = 0;
    while (offset + sizeof(IMAGE_BASE_RELOCATION) <= tableSize)
    {
        IMAGE_BASE_RELOCATION* block =
            reinterpret_cast<IMAGE_BASE_RELOCATION*>(relocTable + offset);
        if (block->SizeOfBlock == 0 || block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
            offset + block->SizeOfBlock > tableSize)
            break; // Terminate at the final block.

        // The 16-bit entries follow the block header.
        BASE_RELOCATION_ENTRY* entries =
            reinterpret_cast<BASE_RELOCATION_ENTRY*>(
                reinterpret_cast<BYTE*>(block) + sizeof(IMAGE_BASE_RELOCATION));
        const SIZE_T entryCount =
            (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);

        for (SIZE_T e = 0; e < entryCount; e++)
        {
            const UINT32 relocType = (entries[e].Value >> 12) & 0xF;
            const UINT32 pageOffset = entries[e].Value & 0x0FFF;

            //
            // The target RVA and the width of the fixup both come from the
            // file.  Validate the complete store against SizeOfImage before
            // touching it: an out-of-image entry would otherwise rewrite
            // memory outside the mapped pool block.
            //
            SIZE_T width = 0;
            if (relocType == IMAGE_REL_BASED_HIGHLOW)
                width = sizeof(UINT32);
            else if (relocType == IMAGE_REL_BASED_DIR64)
                width = sizeof(UINT64);
            else
                continue; // ABSOLUTE or an unsupported type: leave untouched.

            const SIZE_T targetRva = static_cast<SIZE_T>(block->VirtualAddress) + pageOffset;
            if (targetRva > imageSize || width > imageSize - targetRva)
                return STATUS_INVALID_IMAGE_FORMAT;

            BYTE* target = image + targetRva;
            if (relocType == IMAGE_REL_BASED_HIGHLOW)
            {
                // 32-bit base relocation.
                *reinterpret_cast<UINT32*>(target) += static_cast<UINT32>(delta);
            }
            else
            {
                // 64-bit base relocation.
                *reinterpret_cast<UINT64*>(target) += delta;
            }
        }

        offset += block->SizeOfBlock;
    }

    return STATUS_SUCCESS;
}

NTSTATUS PeLoaderResolveImports(_In_ PVOID MappedBase)
{
    BYTE* image = static_cast<BYTE*>(MappedBase);
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    const IMAGE_NT_HEADERS64* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);

    const IMAGE_DATA_DIRECTORY& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0)
        return STATUS_SUCCESS; // No import directory: nothing to resolve.

    const SIZE_T imageSize = static_cast<SIZE_T>(nt->OptionalHeader.SizeOfImage);

    //
    // Every RVA below comes from the image itself.  A corrupt or truncated
    // file would otherwise make the loader read (and write, for the IAT) far
    // outside the mapped pool block, so each access is range-checked against
    // SizeOfImage before it is performed.
    //
    const auto fits = [imageSize](const SIZE_T rva, const SIZE_T length) -> bool
    {
        return rva <= imageSize && length <= imageSize - rva;
    };

    if (!fits(importDir.VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
        return STATUS_INVALID_IMAGE_FORMAT;

    const PCIMAGE_IMPORT_DESCRIPTOR descriptor =
        reinterpret_cast<PCIMAGE_IMPORT_DESCRIPTOR>(image + importDir.VirtualAddress);

    //
    // Walk import descriptors until the terminating null entry (Name == 0).
    // DataDirectory.Size bounds the walk when it is present; otherwise the
    // remainder of the image does.
    //
    const SIZE_T descriptorCount = (importDir.Size >= sizeof(IMAGE_IMPORT_DESCRIPTOR))
        ? importDir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)
        : (imageSize - importDir.VirtualAddress) / sizeof(IMAGE_IMPORT_DESCRIPTOR);

    for (SIZE_T d = 0; d < descriptorCount; d++)
    {
        if (!fits(importDir.VirtualAddress + d * sizeof(IMAGE_IMPORT_DESCRIPTOR), sizeof(IMAGE_IMPORT_DESCRIPTOR)))
            break;

        if (descriptor[d].Name == 0)
            break;

        //
        // OriginalFirstThunk and Characteristics share the descriptor's first
        // 4 bytes (a union). Read them as a raw ULONG at offset 0: the high
        // bit marks a by-ordinal import table; the low 31 bits are the RVA of
        // the first thunk (original import name table).
        //
        const ULONG firstThunkRaw = *reinterpret_cast<const ULONG*>(descriptor + d);
        const BOOL byOrdinal = (firstThunkRaw & 0x80000000) != 0;

        if (!fits(descriptor[d].Name, sizeof(IMAGE_IMPORT_BY_NAME)))
            return STATUS_INVALID_IMAGE_FORMAT;

        const PIMAGE_IMPORT_BY_NAME dllName =
            reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(image + descriptor[d].Name);
        const char* dllNameStr = dllName->Name;

        const SIZE_T nameTableRva = firstThunkRaw & 0x7fffffff;
        const SIZE_T iatRva = descriptor[d].FirstThunk;

        if (nameTableRva == 0 || iatRva == 0)
            continue;

        if (!fits(nameTableRva, sizeof(IMAGE_THUNK_DATA)) || !fits(iatRva, sizeof(IMAGE_THUNK_DATA)))
            return STATUS_INVALID_IMAGE_FORMAT;

        const PIMAGE_THUNK_DATA nameTable =
            reinterpret_cast<PIMAGE_THUNK_DATA>(image + nameTableRva);
        PIMAGE_THUNK_DATA iat = reinterpret_cast<PIMAGE_THUNK_DATA>(image + iatRva);

        for (SIZE_T k = 0; ; k++)
        {
            const SIZE_T thunkOffset = k * sizeof(IMAGE_THUNK_DATA);
            if (!fits(nameTableRva + thunkOffset, sizeof(IMAGE_THUNK_DATA)) ||
                !fits(iatRva + thunkOffset, sizeof(IMAGE_THUNK_DATA)))
                return STATUS_INVALID_IMAGE_FORMAT;

            const UINT64 thunkValue = nameTable[k].u1.Function;
            if (thunkValue == 0)
                break; // Terminating thunk.

            //
            // By-ordinal imports are rejected rather than guessed: the loader
            // cannot safely map an ordinal to a kernel routine.
            //
            if (byOrdinal || (thunkValue & IMAGE_ORDINAL_FLAG))
            {
                MAPPER_LOG("by-ordinal import in %s; refusing to guess", dllNameStr);
                return STATUS_NOT_SUPPORTED;
            }

            const SIZE_T importNameRva = static_cast<SIZE_T>(thunkValue);
            if (!fits(importNameRva, sizeof(IMAGE_IMPORT_BY_NAME)))
                return STATUS_INVALID_IMAGE_FORMAT;

            const PIMAGE_IMPORT_BY_NAME importByname =
                reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(image + importNameRva);

            // MmGetSystemRoutineAddress requires a UTF-16 (wide) routine name,
            // but IMAGE_IMPORT_BY_NAME.Name is a NUL-terminated ASCII (char)
            // name. Convert the ASCII name into a stack wide buffer, bounded
            // both by the buffer size and by the end of the image.
            wchar_t wideName[64];
            size_t nameLen = 0;
            while (nameLen < 63)
            {
                const SIZE_T charRva = importNameRva + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name) + nameLen;
                if (!fits(charRva, 1))
                    return STATUS_INVALID_IMAGE_FORMAT;

                const char c = importByname->Name[nameLen];
                if (c == '\0')
                    break;

                wideName[nameLen] = static_cast<wchar_t>(static_cast<unsigned char>(c));
                nameLen++;
            }
            wideName[nameLen] = 0;

            UNICODE_STRING routineName;
            RtlInitUnicodeString(&routineName, wideName);

            PVOID address = MmGetSystemRoutineAddress(&routineName);
            if (!address)
            {
                MAPPER_LOG("%s from %s not found in system", importByname->Name, dllNameStr);
                return STATUS_PROCEDURE_NOT_FOUND;
            }

            // Write the resolved kernel address into the IAT slot.
            iat[k].u1.AddressOfData = reinterpret_cast<UINT64>(address);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS PeLoaderInvokeEntry(_In_ PVOID MappedBase, _Out_ PDRIVER_OBJECT* OutDriverObject)
{
    *OutDriverObject = nullptr;

    BYTE* image = static_cast<BYTE*>(MappedBase);
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    const IMAGE_NT_HEADERS64* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    const IMAGE_OPTIONAL_HEADER64& opt = nt->OptionalHeader;

    //
    // Allocate the synthetic DRIVER_OBJECT from NonPagedPool (tagged), zero it,
    // and populate the fields the mapped driver's entry point actually reads:
    // Type (must equal IO_TYPE_DRIVER), DriverStart and DriverSize.
    //
    DRIVER_OBJECT* driverObject = static_cast<DRIVER_OBJECT*>(
        ExAllocatePoolWithTag(NonPagedPool, sizeof(DRIVER_OBJECT), PELOADER_POOL_TAG));
    if (!driverObject)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(driverObject, sizeof(DRIVER_OBJECT));
    driverObject->Type = IO_TYPE_DRIVER;
    driverObject->DriverStart = MappedBase;
    driverObject->DriverSize = static_cast<SIZE_T>(opt.SizeOfImage);

    *OutDriverObject = driverObject;

    //
    // Locate the entry point and invoke it with the DRIVER_OBJECT and the
    // service registry path.  The returned NTSTATUS (the mapped driver's
    // own status) is propagated to the caller.
    //
    const SIZE_T entryRva = static_cast<SIZE_T>(opt.AddressOfEntryPoint);
    if (entryRva == 0 || entryRva >= static_cast<SIZE_T>(opt.SizeOfImage))
        return STATUS_INVALID_PARAMETER;

    PDRIVER_INITIALIZE initialize =
        reinterpret_cast<PDRIVER_INITIALIZE>(image + entryRva);

    UNICODE_STRING registryPath;
    RtlInitUnicodeString(&registryPath, MAPPER_SERVICE_REGISTRY_PATH);

    return initialize(driverObject, &registryPath);
}
