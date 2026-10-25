#pragma once

namespace SVM
{
    //
    // Transparent-hide tuning.  Hidden pages are made not-present in the NPT
    // and are restored inline by the #NPF handler the first time the guest
    // touches one.  Once a restored page has gone quiet for NPT_REHIDE_GRACE
    // VMEXITs it is reverted to not-present, so actively-used pages stay
    // mapped while the dormant bulk of a hidden image goes back to invisible.
    // All failure modes degrade to "the page stays mapped" (a minor stealth
    // loss) and never to a correctness failure.
    //
    constexpr ULONG NPT_REHIDE_CAPACITY = 64;    // tracked pages (power of two)
    constexpr LONG  NPT_REHIDE_GRACE = 4096;     // quiet VMEXITs before revert
    constexpr ULONG NPT_REHIDE_SCAN_INTERVAL = 4096; // VMEXITs between revert scans
    constexpr ULONG NPT_REHIDE_SCAN = 16;        // slots scanned per scan

    //
    // Fail-open limits.
    //
    // NPT_RESTORE_LIMIT: after this many restores TrackForRehide() stops the
    // re-hide cycle globally (sticky restore).  A hidden image that is
    // touched this often is in active use, and re-hiding it would only feed
    // the #NPF path forever.
    //
    // NPF_STALE_STRIKE_LIMIT: consecutive #NPF exits on a page whose entry is
    // already present.  The handler flushes unconditionally, so a few are
    // normal walk/TLB races; a long run means the CPU cannot make progress
    // and self-hide is disabled for the whole system.
    //
    constexpr LONG NPT_RESTORE_LIMIT = 32;
    constexpr LONG NPF_STALE_STRIKE_LIMIT = 32;

    typedef struct _APIC_BASE
    {
        union
        {
            UINT64 AsUInt64;
            struct
            {
                UINT64 Reserved1 : 8;           // [0:7]
                UINT64 BootstrapProcessor : 1;  // [8]
                UINT64 Reserved2 : 1;           // [9]
                UINT64 EnableX2ApicMode : 1;    // [10]
                UINT64 EnableXApicGlobal : 1;   // [11]
                UINT64 ApicBase : 24;           // [12:35]
            };
        };
    } APIC_BASE, * PAPIC_BASE;

    typedef struct _PML4_ENTRY_4KB
    {
        union
        {
            UINT64 AsUInt64;
            struct
            {
                UINT64 Present : 1;
                UINT64 Write : 1;
                UINT64 Supervisor : 1;
                UINT64 WriteThrough : 1;
                UINT64 CacheDisable : 1;
                UINT64 Accessed : 1;
                UINT64 Reserved1 : 3;
                UINT64 Avl : 3;
                UINT64 PageFrameNumber : 36;
                UINT64 Reserved2 : 15;
                UINT64 NoExecute : 1;
            };
        };
    } PML4_ENTRY_4KB, * PPML4_ENTRY_4KB,
        PDP_ENTRY_4KB, * PPDP_ENTRY_4KB,
        PT_ENTRY_4KB, * PPT_ENTRY_4KB;
    static_assert(sizeof(PML4_ENTRY_4KB) == 8, "size mismatch");

    typedef struct _PD_ENTRY_2MB
    {
        union
        {
            UINT64 AsUInt64;
            struct
            {
                UINT64 Present : 1;
                UINT64 Write : 1;
                UINT64 Supervisor : 1;
                UINT64 WriteThrough : 1;
                UINT64 CacheDisable : 1;
                UINT64 Accessed : 1;
                UINT64 Dirty : 1;
                UINT64 LargePage : 1;
                UINT64 Global : 1;
                UINT64 Avl : 3;
                UINT64 Pat : 1;
                UINT64 Reserved1 : 8;
                UINT64 PageFrameNumber : 27;
                UINT64 Reserved2 : 15;
                UINT64 NoExecute : 1;
            };
        };
    } PD_ENTRY_2MB, * PPD_ENTRY_2MB;
    static_assert(sizeof(PD_ENTRY_2MB) == 8, "PD_ENTRY_2MB size mismatch");

    typedef union
    {
        struct
        {
            UINT64 Present : 1;
            UINT64 Write : 1;
            UINT64 Supervisor : 1;
            UINT64 PageLevelWriteThrough : 1;
            UINT64 PageLevelCacheDisable : 1;
            UINT64 Accessed : 1;
            UINT64 Reserved1 : 1;
            UINT64 LargePage : 1;
            UINT64 Ignored1 : 3;
            UINT64 Restart : 1;
            UINT64 PageFrameNumber : 36;
            UINT64 Reserved2 : 4;
            UINT64 Ignored2 : 11;
            UINT64 ExecuteDisable : 1;
        };

        UINT64 AsUInt;
    } PDE_4KB;
    static_assert(sizeof(PDE_4KB) == 8, "PDE_4KB size mismatch");

    typedef union _PDPTE_1GB
    {
        struct
        {
            UINT64 Present : 1;
            UINT64 Write : 1;
            UINT64 Supervisor : 1;
            UINT64 PageLevelWriteThrough : 1;
            UINT64 PageLevelCacheDisable : 1;
            UINT64 Accessed : 1;
            UINT64 Dirty : 1;
            UINT64 LargePage : 1;
            UINT64 Global : 1;
            UINT64 Ignored1 : 2;
            UINT64 Restart : 1;
            UINT64 Pat : 1;
            UINT64 Reserved1 : 17;
            UINT64 PageFrameNumber : 18;
            UINT64 Reserved2 : 4;
            UINT64 Ignored2 : 7;
            UINT64 ProtectionKey : 4;
            UINT64 ExecuteDisable : 1;
        };
        UINT64 AsUInt;
    } PDPTE_1GB;
    static_assert(sizeof(PDPTE_1GB) == 8, "PDPTE_1GB size mismatch");

    typedef union
    {
        struct
        {
            UINT64 Present : 1;
            UINT64 Write : 1;
            UINT64 Supervisor : 1;
            UINT64 PageLevelWriteThrough : 1;
            UINT64 PageLevelCacheDisable : 1;
            UINT64 Accessed : 1;
            UINT64 Reserved1 : 1;
            UINT64 LargePage : 1;
            UINT64 Ignored1 : 3;
            UINT64 Restart : 1;
            UINT64 PageFrameNumber : 36;
            UINT64 Reserved2 : 4;
            UINT64 Ignored2 : 11;
            UINT64 ExecuteDisable : 1;
        };

        UINT64 AsUInt;
    } PDPTE_2MB;
    static_assert(sizeof(PDPTE_2MB) == 8, "PDPTE_2MB size mismatch");

    typedef union _PML4E_64
    {
        struct
        {
            UINT64 Present : 1;
            UINT64 Write : 1;
            UINT64 Supervisor : 1;
            UINT64 PageLevelWriteThrough : 1;
            UINT64 PageLevelCacheDisable : 1;
            UINT64 Accessed : 1;
            UINT64 Reserved1 : 1;
            UINT64 MustBeZero : 1;
            UINT64 Ignored1 : 3;
            UINT64 Restart : 1;
            UINT64 PageFrameNumber : 36;
            UINT64 Reserved2 : 4;
            UINT64 Ignored2 : 11;
            UINT64 ExecuteDisable : 1;
        };
        UINT64 AsUInt;
    } PML4E_64;
    static_assert(sizeof(PML4E_64) == 8, "PML4E_64 size mismatch");

#include <pshpack1.h>
    typedef struct _DESCRIPTOR_TABLE_REGISTER
    {
        UINT16 Limit;
        ULONG_PTR Base;
    } DESCRIPTOR_TABLE_REGISTER, * PDESCRIPTOR_TABLE_REGISTER;
    static_assert(sizeof(DESCRIPTOR_TABLE_REGISTER) == 10,
        "DESCRIPTOR_TABLE_REGISTER size mismatch");
#include <poppack.h>
}