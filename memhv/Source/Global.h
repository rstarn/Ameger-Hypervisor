#pragma once

#include <ntifs.h>
#include <intrin.h>
#include <ntdef.h>
#include <minwindef.h>
#include <stddef.h>
#include <ntimage.h>

#include "Utils.h"
#include "Shared.h"

#include "Memory/Physical.h"

#include "SVM/Defines/SVM_Platform.h"
#include "SVM/Defines/SVM_NestedPaging.h"
#include "SVM/Defines/SVM_ControlArea.h"
#include "SVM/Defines/SVM_ProcessorData.h"
#include "SVM/SVM.h"
#include "SVM/Handlers/SVM_VMExit.h"

//
// SVM_ENABLE_SELF_HIDE
//
// Compile-time switch for SVM::ProtectSelf(), i.e. the client's "protect the
// hypervisor" step.  When enabled, HideRange() clears the Present bit of the
// nested page table entries backing the driver's own image, and the #NPF
// handler restores them transparently on guest access.
//
// DISABLED (0) since build 2026-10-25-e, by the operator's directive, after
// the crash dump 102526-12046-01 (bugcheck 0x11F, arg1='NPF1'): the hide
// itself works, but guest-mode threads that legitimately execute driver
// image code (the log flusher thread, the process-notify callback) fault on
// the hidden .text/.bss pages, and on real Zen 2 hardware the restore path
// failed to resolve the fault 1000 consecutive times - the CPU kept
// refaulting a page whose NPT entry the handler read as present - and the
// tripwire converted the livelock into a bugcheck.  Hiding pages the guest
// OS executes behind a nested-page-fault restore loop is inherently a
// livelock hazard; the driver's stealth therefore relies on what the mapper
// already provides (stripped PE header, unlinked from the loader lists,
// PiDDB/hash-cache cleanup) instead of NPT manipulation.
//
// While disabled, ProtectSelf()/HideRange() are no-op successes: the mapper's
// hide block runs, every command reports success, the NPT is never modified,
// and no nested page fault can occur (the identity map is fully present).
// The rest of the hypervisor - virtualization, the VMCALL interface and the
// physical memory copy path - is unaffected.
//
// If this is ever re-enabled, the NPF restore path must be redesigned first:
// (a) the diagnostic/unresolved path must not allocate split tables (it can
// exhaust the preallocated pool and permanently break every restore), and
// (b) the restore must be made robust against walk-cache disagreement
// (TLB_CONTROL flushes alone demonstrably did not guarantee the CPU's next
// walk observed the restored entry).
//
#define SVM_ENABLE_SELF_HIDE 0

namespace Global
{
    inline PVOID BlankPage = nullptr;
    inline PVOID PreallocatedPools[32];

    //
    // Image base and allocation size of this driver, recorded by Entry() from
    // the DRIVER_OBJECT it was entered with.  A normally loaded driver gets
    // the loader's object; a mapped one gets the object the mapper fabricates
    // with DriverStart = allocation base and DriverSize = allocation size.
    // DriverSize stays zero if Entry() had to fall back to __ImageBase and
    // the headers there are not a valid PE image.
    //
    inline ULONG64 DriverBase = 0;
    inline ULONG64 DriverSize = 0;

    //
    // Readiness handshake between Entry() and the system thread that runs
    // SVM::VirtualizeAllProcessors().  Entry() must not return before every
    // CPU has executed VMRUN: a VMMCALL issued on a CPU that is not in guest
    // mode raises #UD in user mode and kills the client.
    //
    // Entry() initializes the event before creating the thread, the thread
    // stores its final NTSTATUS in VirtualizationStatus and then signals.
    // Both live in the driver image, which the mapper keeps mapped and which
    // is non-paged.
    //
    inline KEVENT VirtualizationReady;
    inline NTSTATUS VirtualizationStatus = STATUS_PENDING;

    //
    // Per-CPU virtualization state, sized at runtime from the active
    // processor count (this machine: 16 logical CPUs).
    //
    // VirtualizedCpus is an array of PVIRTUAL_PROCESSOR_DATA indexed by the
    // system-wide processor index (KeGetProcessorIndexFromNumber), i.e. the
    // same index space KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS)
    // counts.  VirtualizeProcessor() publishes each CPU's vpData there and
    // ProtectSelf() walks the array to reach every VMCB.  Never freed: it
    // has to stay valid for the whole time the driver is resident.
    //
    inline PBYTE VirtualizedCpus = nullptr;
    inline ULONG VirtualizedCpuCount = 0;

    //
    // Size of the MSR permission map in bytes, computed at runtime from
    // CPUID Fn8000_000A on this CPU (AMD Ryzen 7 4800H / Zen 2).
    inline ULONG64 MsrPermissionsMapSize = 0;

    //
    // Dynamic MSR address ranges, computed from CPUID Fn8000_000A:
    //   EAX [51:32] - max offset in the MSR0-1 range (0x00000000 base)
    //   EAX [63:52] - max offset in the MSR2 range (0xC0000000 base)
    inline UINT32 MsrRange01Max = 0;
    inline UINT32 MsrRange2Max = 0;

    namespace Offsets
    {
        //
        // EPROCESS layout, resolved at boot from the running kernel image.
        // Defaults are zeroed so that any consumer that somehow runs before
        // GetOffsets() will fault immediately rather than silently trusting a
        // build-specific offset. Entry() refuses to continue if GetOffsets()
        // fails, so these are never actually relied upon on a supported system.
        inline ULONG64 ActiveProcessLinks = 0;
        inline ULONG64 UniqueProcessId = 0;
        inline ULONG64 DirectoryTableBase = 0;

        //
        // Runtime-validated flag: true once GetOffsets() has successfully
        // resolved all EPROCESS layout offsets dynamically.
        inline bool Resolved = false;
    }

    //
    // Highest valid user-mode address for this OS build, read at boot from
    // the kernel's MmHighestUserAddress. Win11 24H2 uses a 64-bit user space
    // split, so the user/kernel boundary is MmHighestUserAddress (≈
    // 0x7FFFFFFFFFFF), not the old 48-bit 0x7FFFFFFEFFFF. Both
    // Utils::ValidUsermodeAddress and SVM::IsInUserland key off this.
    inline ULONG64 HighestUserAddress = 0;

    //
    // Dynamically resolved at boot via MmGetSystemRoutineAddress (with an
    // export-table-parsing fallback). These replace the old hardcoded -6
    // (48-byte) offset into the OBJECT_HEADER for the PointerCount field,
    // which varied silently between Windows builds. When the function
    // pointers are available they are preferred; otherwise the
    // ReferenceCountOffset (discovered by pattern-scanning the kernel image)
    // is used as a fallback.
    inline PVOID pObfReferenceObject = nullptr;
    inline PVOID pObfDereferenceObject = nullptr;
    inline ULONG32 ReferenceCountOffset = 0;
    inline bool UseObFunctions = false;
}