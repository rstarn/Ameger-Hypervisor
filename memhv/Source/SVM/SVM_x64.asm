.const

KTRAP_FRAME_SIZE            equ     190h  ; verified: KTRAP_FRAME_LENGTH in Win11 24H2 SDK (10.0.26100.0\shared\ksamd64.inc)
MACHINE_FRAME_SIZE          equ     28h

.code

extern HandleExit : proc

PUSHAQ macro
        push    rax
        push    rcx
        push    rdx
        push    rbx
        push    -1
        push    rbp
        push    rsi
        push    rdi
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15
        endm

POPAQ macro
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx
        pop     rbx
        pop     rdx
        pop     rcx
        pop     rax
        endm

LaunchVM proc frame
        mov rsp, rcx

        ;
        ; Run the VMCB load and the exit handler with GIF=0 so that no
        ; interrupt can be delivered while the guest state is being
        ; installed.  VMRUN enters the guest with GIF=1, so STGI is issued
        ; immediately before it and CLGI right after it returns.
        ;
        clgi

        ;
        ; Interrupts are also masked at the RFLAGS level for the entire
        ; loop.  VMRUN saves the *current* host state (RFLAGS included)
        ; into the VM_HSAVE_PA area on every entry, so the host RFLAGS
        ; restored on every future #VMEXIT carry IF=0 as well: each exit
        ; handler runs with both GIF=0 and IF=0.  This closes the
        ; STGI -> VMRUN window.  A pending interrupt (blocked throughout
        ; the handler by GIF=0) would otherwise be recognized between
        ; those two instructions - in host mode, on this per-CPU host
        ; stack, while the "current thread" is the interrupted guest
        ; thread - and an interrupt-exit reschedule there would context
        ; switch that thread away with an RSP pointing into this host
        ; stack, corrupting the LaunchVM loop and parking this vCPU
        ; forever: a hard freeze with no bugcheck.
        ;
        ; The guest is unaffected: VMRUN loads the guest's own RFLAGS
        ; (IF=1), so guest interrupt delivery starts the moment the guest
        ; runs, and anything that arrived during the microsecond-long
        ; handler is delivered then.
        ;
        cli

SvLV10:
        mov rax, [rsp]
        vmload rax

        stgi
        vmrun rax
        clgi

        ;
        ; Complete the world switch.  Per the APM (#VMEXIT pseudo-code),
        ; the CPU reloads host CS/SS/DS/ES, GDTR/IDTR, CR0/CR3/CR4, EFER,
        ; RFLAGS, RIP, RSP, RAX and DR7 on exit - but NOT FS, GS, TR,
        ; LDTR, KERNEL_GS_BASE, the SYSENTER MSRs or the SYSCALL MSRs.
        ; Without the pair below, the C handler runs with the GUEST's
        ; values still loaded.  Every VMCALL this driver serves is issued
        ; from CPL3, where Windows holds GS_BASE = the caller's user TEB,
        ; so the first PCR-relative access in the handler (processor
        ; number, IRQL, the pool allocator - anything) reads a user-mode
        ; address through the host CR3, takes a host page fault whose own
        ; handler is equally GS-blind, and cascades into a shutdown: a
        ; hard freeze with no bugcheck, at the first VMMCALL.
        ;
        ; So: save the guest's live FS/GS/TR/SYSENTER/SYSCALL state into
        ; the guest VMCB (it was never stored by the exit itself), then
        ; load the host's from the host VMCB captured per CPU by
        ; PrepareForVirtualization().  The vmload at SvLV10 re-installs
        ; the guest's values before every VMRUN.
        ;
        mov rax, [rsp]
        vmsave rax
        mov rax, [rsp + 8]
        vmload rax

        ;
        ; #VMEXIT has already written the guest state into the VMCB and
        ; reloaded the host state from the VM_HSAVE_PA area, so there is
        ; nothing to VMSAVE here: doing so would overwrite the guest state
        ; with the host's segments/CRs/EFER/RFLAGS.
        ;
        .pushframe
        sub     rsp, KTRAP_FRAME_SIZE
        .allocstack KTRAP_FRAME_SIZE - MACHINE_FRAME_SIZE + 100h

        PUSHAQ

        mov rdx, rsp
        ;
        ; 8 * 18 = PUSHAQ (16 * 8 = 0x80) + the distance from
        ; HostStackLayout.GuestVmcbPa to HostStackLayout.Self (0x10), i.e.
        ; this loads HostStackLayout.Self (= PVIRTUAL_PROCESSOR_DATA).
        ;
        mov rcx, [rsp + 8 * 18 + KTRAP_FRAME_SIZE]

        sub rsp, 80h
        movaps xmmword ptr [rsp + 20h], xmm0
        movaps xmmword ptr [rsp + 30h], xmm1
        movaps xmmword ptr [rsp + 40h], xmm2
        movaps xmmword ptr [rsp + 50h], xmm3
        movaps xmmword ptr [rsp + 60h], xmm4
        movaps xmmword ptr [rsp + 70h], xmm5
        .endprolog

        call HandleExit

        movaps xmm5, xmmword ptr [rsp + 70h]
        movaps xmm4, xmmword ptr [rsp + 60h]
        movaps xmm3, xmmword ptr [rsp + 50h]
        movaps xmm2, xmmword ptr [rsp + 40h]
        movaps xmm1, xmmword ptr [rsp + 30h]
        movaps xmm0, xmmword ptr [rsp + 20h]
        add rsp, 80h

        test al, al
        POPAQ

        jnz SvLV20
        add rsp, KTRAP_FRAME_SIZE
        jmp SvLV10

SvLV20:
        mov rsp, rcx
        mov ecx, 'NNNN'
        jmp rbx
LaunchVM endp

        end
