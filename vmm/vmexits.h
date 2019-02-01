

#include <inc/trap.h>
bool handle_interrupt_window(struct Trapframe *tf, struct VmxGuestInfo *ginfo, uint32_t host_vector);
bool handle_interrupts(struct Trapframe *tf, struct VmxGuestInfo *ginfo, uint32_t host_vector);
bool handle_nmi(struct Trapframe *tf, struct VmxGuestInfo *ginfo, uint64_t *eptrt, uint32_t intr_info);
bool handle_eptviolation(uint64_t *eptrt, struct VmxGuestInfo *ginfo);
bool handle_rdmsr(struct Trapframe *tf, struct VmxGuestInfo *ginfo);
bool handle_wrmsr(struct Trapframe *tf, struct VmxGuestInfo *ginfo);
bool handle_ioinstr(struct Trapframe *tf, struct VmxGuestInfo *ginfo);
bool handle_cpuid(struct Trapframe *tf, struct VmxGuestInfo *ginfo);
bool handle_mov_cr(struct Trapframe *tf, struct VmxGuestInfo *gInfo, uint64_t *eptrt);
bool handle_vmcall(struct Trapframe *tf, struct VmxGuestInfo *gInfo, uint64_t *eptrt );
bool handle_invlpg(struct Trapframe *tf, struct VmxGuestInfo *gInfo, uint64_t *eptrt);
