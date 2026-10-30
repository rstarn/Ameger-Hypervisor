#pragma once

#include <ntifs.h>
#include <intrin.h>
#include <ntdef.h>
#include <minwindef.h>
#include <stddef.h>
#include <ntimage.h>

#include "../../Utilities/Utilities.h"
#include "../Common/Shared.h"

#include "../Memory/Physical.h"

#include "../Memory/Definitions.h"
#include "../SVM/Defines/NestedPaging.h"
#include "../SVM/Defines/ControlArea.h"
#include "../SVM/Defines/ProcessorData.h"
#include "../SVM/SVM.h"
#include "../SVM/Handlers/Exit/VMExit.h"

//
// HYPERVISOR_ENABLE_SELF_HIDE
//
// Compile-time switch for SVM::ProtectSelf(), i.e. the client's "protect the
// hypervisor" step.  When enabled, HideRange() clears the Present bit of the
// nested page table entries backing the driver's own image minus its
// executable sections, and the #NPF handler restores them transparently on
// guest access.
//
// The previous 0x11F 'NPF1' crash (dump 102526-12046-01) was caused by three
// independent defects in the restore path, not by the idea of hiding:
//
//   (a) Present-entry fixed point.  The #NPF path acted only when the leaf
//       entry was not-present.  Once it was present - a cross-vCPU restore
//       race, or a stale walk cache after a large-page split - every further
//       fault on that page took the "unresolved" branch, which only
//       incremented NpfUnresolvedRun and never flushed.  That is a fixed
//       point: the CPU refaults forever and the 1000-strike tripwire turns
//       the livelock into a bugcheck.
//   (b) Diagnostic-path pool burn.  GetOrSplitPageTable() split large pages
//       for every fault, including the diagnostic/unresolved ones, consuming
//       the fixed preallocated pool.  After ~32 unrelated NPFs the pool was
//       empty and genuine hidden pages could no longer be restored.
//   (c) Aligned-base first-page bug.  HideRange() computed
//       firstPage = (base + PAGE_SIZE - 1) & pageMask, so a page-aligned
//       image base skipped the first page of the image.
//
// The redesign therefore changes the policy in three ways:
//
//   - Data-only hiding.  Hiding executable .text guarantees a permanent NPF
//     supply, because the driver's own notify callback and log thread execute
//     it in guest mode.  ProtectSelf() takes the executable range from the
//     caller and HideRange() skips every page in it; only the data sections
//     are hidden.
//   - Unconditional flush.  Every #NPF that touches an NPT entry arms
//     TlbControl = 1 (a full TLB + NPT flush), including the already-present
//     case, and DisableSelfHide() publishes a new flush generation so the
//     other vCPUs arm the same flush at their next exit.  The diagnostic path
//     never splits large pages (allowSplit == false), so it cannot burn the
//     pool.
//   - Sticky restore / fail-open disable.  Restoring a page is allowed at
//     most NPT_RESTORE_LIMIT times globally; after that the re-hide flag is
//     cleared for good.  Any #NPF the handler cannot attribute to a hidden
//     page calls DisableSelfHide(), which restores every recorded page from
//     memory (no allocation) and leaves the NPT fully present.  Stealth can
//     degrade; the machine must not bugcheck.
//
#define HYPERVISOR_ENABLE_SELF_HIDE 1

//
// NPT design: one shared single-view root
//
// This driver has exactly one NPT design: a single shared root that maps
// guest-physical space 1:1, with HideRange() clearing the Present bit of the
// pages it hides and the #NPF handler restoring them inline.  The previous
// dual-view ("clean"/"dirty" root) experiment has been removed: it was
// structurally broken in several independent ways (the clean root encoded a
// 1 GB region index in a 2 MB entry's PFN field, the split base was computed
// with the wrong page size, HideRange() hid pages in the root the #NPF
// handler then switched *to*, so a hidden page faulted forever, and an
// out-of-range fault had no tripwire at all).  Keeping a second, unexercised
// page-table design in the exit path is a correctness hazard, not a feature.
//
// HYPERVISOR_STEALTH
//
// 1 (default): enable the CPUID/MSR stealth hardening (see Stealth.cpp).
// 0: every stealth handler becomes a no-op and the original handler
// behaviour is preserved.
//
#define HYPERVISOR_STEALTH 1

namespace Global
{
    inline PVOID BlankPage = nullptr;
    inline PVOID PreallocatedPools[64];

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

    //
    // Set by CheckSupport() from CPUID Fn8000_000A EDX.NP_1GB: true when 1 GB
    // nested pages are usable. BuildNestedPageTables() picks 1 GB large pages
    // when this is true and falls back to 2 MB pages otherwise, so CPUs that
    // expose NP but not NP_1GB can still virtualize.
    //
    inline bool Np1GBAvailable = false;

    //
    // Per-CPU tracked VM_CR (SVMDIS + guest-written LOCK).  Initialized to
    // (1 << 4) (SVMDIS set) at virtualize time; HandleMsrAccess() spoofs the
    // VM_CR read/write so the guest never sees SVM enabled and no write
    // reaches real hardware.  Indexed by the system-wide processor index,
    // clamped to VirtualizedCpuCount.
    //
    inline PULONG64 SpoofedVmCr = nullptr;

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