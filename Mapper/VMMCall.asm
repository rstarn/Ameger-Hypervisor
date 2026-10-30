;
; vmmcall idempotency probe stub for Mapper.sys.
;
; Replicates the client's 4-byte shellcode (vmmcall; ret,
; Client/Library/Hypervisor.h:112) and matches the hypervisor's
; HandleVMCall register contract (SVM::HandleVMCall): RCX = MAGIC,
; RDX = CommandId.  When the hypervisor is active, vmmcall raises a
; #VMEXIT that the hypervisor handles (leaving RAX = COMM_CHECK); when
; the hypervisor is inactive, vmmcall raises #UD
; (STATUS_ILLEGAL_INSTRUCTION), which the caller's __except catches.
;
; The stub lives in the driver's executable .text section, so no
; MmProtectVirtualMemory is needed (that API is not exported by this
; WDK's ntoskrnl.lib).
;
.code

MapperVmmcallCheckPresenceStub proc
    mov rcx, 0feed3h      ; Shared::MAGIC = 0xFEED3
    mov rdx, 1            ; Shared::CommandId::CheckPresence
    db 0Fh, 01h, 0D9h, 0C3h   ; vmmcall; ret
MapperVmmcallCheckPresenceStub endp

    end
