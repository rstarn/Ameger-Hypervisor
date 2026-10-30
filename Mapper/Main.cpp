//
// Main.cpp - the Mapper driver's entry point and PE-loading flow.
//
// When the kernel loads Mapper.sys it calls Entry(), which reads
// Hypervisor.sys from disk, maps it (preserving the PE headers), applies
// relocations, resolves its imports against ntoskrnl, and invokes the
// hypervisor's entry point with a synthetic DRIVER_OBJECT.  The mapped image
// is deliberately left resident so it outlives Mapper.sys (Phase 3 handles
// the mapper's own removal).
//
#include <ntifs.h>
#include <wdm.h>
#include "Loader/PortableExecutable.h"

//
// Shared constants (MAGIC, COMM_CHECK, CommandId) are taken verbatim from the
// hypervisor's shared ABI header so the probe matches the exact register
// contract HandleVMCall expects. Including (not modifying) that header keeps
// the two ends of the VMMCALL interface byte-for-byte identical.
//
#include "../Hypervisor/Source/Common/Shared.h"

//
// Define the driver image path at the top so operators can adjust it without
// re-reading the source.  \??\ is the device namespace prefix that lets a
// kernel driver open a real filesystem path by its full device path.
//
#define MAPPED_DRIVER_PATH L"\\??\\C:\\hv.sys"

//
// Minimal self-contained logging for the mapper entry flow (no Hypervisor::
// logging, which lives in Hypervisor.sys).  Routes through DbgPrint.
//
#define MAPPER_MAIN_LOG(fmt, ...) DbgPrint("[Mapper] " fmt, ##__VA_ARGS__)

//
// Issues a VMMCALL matching the hypervisor's HandleVMCall register contract
// (HandleVMCall): RCX = Shared::MAGIC, RDX = CommandId, result in RAX.
// Replicates the client's 4-byte vmmcall shellcode (Client/Library/Hypervisor.h:112),
// now emitted by a MASM stub (Mapper/VMMCall.asm) placed in the
// driver's executable .text - this WDK's ntoskrnl.lib does not export
// MmProtectVirtualMemory (confirmed via dumpbin), so no reprotected pool
// buffer is needed.
//
extern "C" ULONG64 MapperVmmcallCheckPresenceStub();

static ULONG64 MapperVmmcallCheckPresence()
{
    //
    // The ASM stub sets RCX = MAGIC, RDX = CommandId (CheckPresence),
    // executes vmmcall, and returns the value the handler leaves in RAX
    // (COMM_CHECK when the hypervisor is active; when inactive the CPU
    // raises #UD (STATUS_ILLEGAL_INSTRUCTION), which the caller's __except
    // catches).
    //
    return MapperVmmcallCheckPresenceStub();
}

NTSTATUS Entry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    // The kernel hands Mapper.sys its own DRIVER_OBJECT and registry path;
    // the mapper does not need them - it builds a synthetic object for the
    // mapped Hypervisor image instead.
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    //
    // Idempotency: if the hypervisor is already active (detected via a
    // successful CheckPresence VMMCALL), Mapper must abort before reading the
    // image from disk. Without this guard, a second `sc start Mapper`
    // invocation would map a second Hypervisor instance to a fresh
    // NonPagedPool address, fail its CheckSupport (EFER.SVME already set by
    // the first instance), and leak the fresh allocation.
    //
    __try
    {
        const ULONG64 probeResult = MapperVmmcallCheckPresence();
        if (probeResult == Shared::COMM_CHECK)
        {
            MAPPER_MAIN_LOG("Hypervisor already active; skipping map");
            return STATUS_UNSUCCESSFUL;
        }
    }
    __except (GetExceptionCode() == STATUS_ILLEGAL_INSTRUCTION
              ? EXCEPTION_EXECUTE_HANDLER
              : EXCEPTION_CONTINUE_SEARCH)
    {
        // #UD means no hypervisor is running VMCALL - proceed normally.
        MAPPER_MAIN_LOG("No hypervisor active; proceeding with map");
    }

    PVOID fileBuffer = nullptr;
    SIZE_T fileSize = 0;
    PVOID mappedBase = nullptr;
    SIZE_T imageSize = 0;
    PDRIVER_OBJECT driverObject = nullptr;

    //
    // Step 2: read the driver image from disk into a pool buffer.
    //
    NTSTATUS status = PeLoaderReadFile(MAPPED_DRIVER_PATH, &fileBuffer, &fileSize);
    if (!NT_SUCCESS(status))
    {
        MAPPER_MAIN_LOG("read %s failed: 0x%08X", MAPPED_DRIVER_PATH, static_cast<UINT32>(status));
        return status;
    }

    //
    // Step 3: validate the PE image.  On failure, free the file buffer.
    //
    status = PeLoaderValidate(fileBuffer, fileSize);
    if (!NT_SUCCESS(status))
    {
        MAPPER_MAIN_LOG("validate failed: 0x%08X", static_cast<UINT32>(status));
        ExFreePoolWithTag(fileBuffer, PELOADER_POOL_TAG);
        return status;
    }

    //
    // Step 4: map the image.  On failure, free the file buffer (no image yet).
    //
    status = PeLoaderMapImage(fileBuffer, fileSize, &mappedBase, &imageSize);
    if (!NT_SUCCESS(status))
    {
        MAPPER_MAIN_LOG("map failed: 0x%08X", static_cast<UINT32>(status));
        ExFreePoolWithTag(fileBuffer, PELOADER_POOL_TAG);
        return status;
    }

    //
    // Step 5: apply base relocations.  On failure, free both the mapped image
    // and the file buffer so no partial-mapped state survives.
    //
    status = PeLoaderApplyRelocations(mappedBase);
    if (!NT_SUCCESS(status))
    {
        MAPPER_MAIN_LOG("relocations failed: 0x%08X", static_cast<UINT32>(status));
        ExFreePoolWithTag(mappedBase, PELOADER_POOL_TAG);
        ExFreePoolWithTag(fileBuffer, PELOADER_POOL_TAG);
        return status;
    }

    //
    // Step 6: resolve imports against ntoskrnl.  On failure, free the mapped
    // image and the file buffer.
    //
    status = PeLoaderResolveImports(mappedBase);
    if (!NT_SUCCESS(status))
    {
        MAPPER_MAIN_LOG("import resolution failed: 0x%08X", static_cast<UINT32>(status));
        ExFreePoolWithTag(mappedBase, PELOADER_POOL_TAG);
        ExFreePoolWithTag(fileBuffer, PELOADER_POOL_TAG);
        return status;
    }

    //
    // Step 7: allocate a synthetic DRIVER_OBJECT and invoke the mapped driver's
    // entry point.  On failure, free the driver object, the mapped image, and
    // the file buffer.
    //
    status = PeLoaderInvokeEntry(mappedBase, &driverObject);
    if (!NT_SUCCESS(status))
    {
        MAPPER_MAIN_LOG("entry invoke failed: 0x%08X", static_cast<UINT32>(status));
        if (driverObject)
            ExFreePoolWithTag(driverObject, PELOADER_POOL_TAG);
        ExFreePoolWithTag(mappedBase, PELOADER_POOL_TAG);
        ExFreePoolWithTag(fileBuffer, PELOADER_POOL_TAG);
        return status;
    }

    //
    // Step 8: free the file buffer.  The mapped image (and the synthetic
    // driver object) are left resident in NonPagedPool so they outlive
    // Mapper.sys if it is later unloaded.  We deliberately do NOT set a
    // DriverUnload that frees the mapped image.
    //
    ExFreePoolWithTag(fileBuffer, PELOADER_POOL_TAG);

    //
    // Step 9: the hypervisor is mapped, relocated, imported, and its entry
    // point has been invoked.  Mapper's job is done, so it deliberately fails
    // its own load: returning STATUS_UNSUCCESSFUL makes the SCM report the load
    // as failed, which makes the I/O manager free Mapper.sys's own
    // DRIVER_OBJECT and unload the mapper.  The mapped Hypervisor image and
    // the synthetic driver object (both tagged with the benign 'Thre' tag) are
    // deliberately NOT freed here so they outlive Mapper.sys.  Mapper registers
    // no DriverUnload, so nothing frees them on unload.
    //
    MAPPER_MAIN_LOG("Hypervisor mapped at %p and entry invoked; self-unloading", mappedBase);
    return STATUS_UNSUCCESSFUL;
}
