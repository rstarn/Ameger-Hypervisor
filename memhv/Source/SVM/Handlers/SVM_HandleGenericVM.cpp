#include "../../Global.h" // IWYU pragma: keep

void SVM::HandleGenericSVM(const PVIRTUAL_PROCESSOR_DATA vpData, const PGUEST_CONTEXT guestContext)
{
    UNREFERENCED_PARAMETER(guestContext);

    /*
     * PR #15: VMRUN/VMLOAD/VMSAVE issued by anything other than the
     * hypervisor itself is not supported in the current context and must
     * fault with #UD (AMD APM 24593, page 20).
     */
    InjectUndefinedOpcodeException(vpData);
}