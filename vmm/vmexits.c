

#include <vmm/vmx.h>
#include <inc/error.h>
#include <vmm/vmexits.h>
#include <vmm/ept.h>
#include <inc/x86.h>
#include <inc/assert.h>
#include <inc/mmu.h>
#include <kern/pmap.h>
#include <kern/console.h>
#include <kern/kclock.h>
#include <kern/multiboot.h>
#include <inc/string.h>
#include <inc/stdio.h>
#include <inc/vmx.h>
#include <inc/mmu.h>
#include <kern/syscall.h>
#include <kern/env.h>
#include <kern/cpu.h>

bool
insert_ept_entry (uint64_t *eptrt, uint64_t gpa, struct VmxGuestInfo *ginfo);
void free_spt_level(pml4e_t* sptrt, int level);
void free_rmap_level(pml4e_t* rmap, int level);

uint64_t *eptrt_;

static int vmdisk_number = 0;	//this number assign to the vm
int 
vmx_get_vmdisk_number() {
	return vmdisk_number;
}

void
vmx_incr_vmdisk_number() {
	vmdisk_number++;
}
bool
find_msr_in_region(uint32_t msr_idx, uintptr_t *area, int area_sz, struct vmx_msr_entry **msr_entry) {
	struct vmx_msr_entry *entry = (struct vmx_msr_entry *)area;
	int i;
	for(i=0; i<area_sz; ++i) {
		if(entry->msr_index == msr_idx) {
			*msr_entry = entry;
			return true;
		}
	}
	return false;
}


bool
handle_interrupt_window(struct Trapframe *tf, struct VmxGuestInfo *ginfo, uint32_t host_vector) {
	uint64_t rflags;
	uint32_t procbased_ctls_or;
	
	procbased_ctls_or = vmcs_read32( VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS );
            
        //disable the interrupt window exiting
        procbased_ctls_or &= ~(VMCS_PROC_BASED_VMEXEC_CTL_INTRWINEXIT); 
        
        vmcs_write32( VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS, 
		      procbased_ctls_or);
        //write back the host_vector, which can insert a virtual interrupt            
	vmcs_write32( VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO , host_vector);
	return true;
}

#define IS_P(x) ((uint64_t)x & PTE_P)

void
FOR_EACH_PTE(struct VmxGuestInfo *ginfo, uint64_t *eptrt, uint64_t *ptrt,
    void (*func1)(struct VmxGuestInfo *, uint64_t *, pte_t *, void *, pte_t *, int),
    void (*func2)(struct VmxGuestInfo *, void *), int func_choice,
    int perm, uint64_t ___i, uint64_t __i, uint64_t _i) {
    int64_t i4;
    pte_t *pte, *gpte;
    for (i4 = 0; i4 < (1 << 9); i4++) {
        gpte = (pte_t *)ptrt[i4];
        if (IS_P(gpte)) {
            ept_gpa2hva(eptrt, (void *) gpte, (void **) &pte);
            if (func_choice == 1) {
                func1(ginfo, eptrt, pte, PGADDR(___i, __i, _i, i4, 0), gpte, perm & PGOFF(gpte));
            }
        }
    }
}

void
FOR_EACH_PDE(struct VmxGuestInfo *ginfo, uint64_t *eptrt, uint64_t *pdrt,
    void (*func1)(struct VmxGuestInfo *, uint64_t *, pte_t *, void *, pte_t *, int),
    void (*func2)(struct VmxGuestInfo *, void *), int func_choice,
    int perm, uint64_t __i, uint64_t _i) {
    uint64_t i3;
    pde_t *ptrt, *gpde;
    for (i3 = 0; i3 < (1 << 9); i3++) {
        gpde = (pde_t *)pdrt[i3];
        if (IS_P(gpde)) {
            ept_gpa2hva(eptrt, (void *) gpde, (void **) &ptrt);
            if (func_choice == 2) {
                //cprintf("pdrt: %lx \n", gpde);
                func2(ginfo, gpde);
            }
            FOR_EACH_PTE(ginfo, eptrt, ptrt, func1, func2, func_choice, perm & PGOFF(gpde), __i, _i, i3);
        }
    }
}

void
FOR_EACH_PDPE(struct VmxGuestInfo *ginfo, uint64_t *eptrt, uint64_t *pdprt,
    void (*func1)(struct VmxGuestInfo *, uint64_t *, pte_t *, void *, pte_t *, int),
    void (*func2)(struct VmxGuestInfo *, void *), int func_choice,
    int perm, uint64_t _i) {
    uint64_t i2;
    pdpe_t *pdrt, *gpdpe;
    for (i2 = 0; i2 < (1 << 9); i2++) {
        gpdpe = (pdpe_t *)pdprt[i2];
        if (IS_P(gpdpe)) {
            ept_gpa2hva(eptrt, (void *) gpdpe, (void **) &pdrt);
            if (func_choice == 2) {
                //cprintf("pdpe: %lx\n", gpdpe);
                func2(ginfo, gpdpe);
            }
            FOR_EACH_PDE(ginfo, eptrt, pdrt, func1, func2, func_choice, perm & PGOFF(gpdpe), _i, i2);
        }
    }
}

void
FOR_EACH_PML4E(struct VmxGuestInfo *ginfo, uint64_t *eptrt, uint64_t *pml4rt,
    void (*func1)(struct VmxGuestInfo *, uint64_t *, pte_t *, void *, pte_t *, int),
    void (*func2)(struct VmxGuestInfo *, void *), int func_choice) {
    uint64_t i1;
    pml4e_t *pdprt, *gpml4e;
    for (i1 = 0; i1 < (1 << 9); i1++) {
        gpml4e = (pml4e_t *)pml4rt[i1];
        if (IS_P(gpml4e)) {
            ept_gpa2hva(eptrt, (void *) gpml4e, (void **) &pdprt);
            if (func_choice == 2) {
                //cprintf("pml4e: %lx\n", gpml4e);
                func2(ginfo, gpml4e);
            }
            FOR_EACH_PDPE(ginfo, eptrt, pdprt, func1, func2, func_choice, PGOFF(gpml4e), i1);
        }
    }
}

void *
gva2hva(struct VmxGuestInfo *ginfo, uint64_t *eptrt, void *gva, void **_gpa) {
    void *guest_cr3 = (void *)ginfo->gcr3; // gpa
    pml4e_t *pml4e; // hva
    pdpe_t *pdpe, gpdpe;
    pde_t *pde, gpde;
    pte_t *pte, gpte;
    void *va;
    void *gpa;
    ept_gpa2hva(eptrt, (void *) guest_cr3, (void **) &pml4e);

    gpdpe = pml4e[PML4(gva)];
    if (gpdpe & PTE_P) {
        ept_gpa2hva(eptrt, (void *) gpdpe, (void **) &pdpe);
        gpde = pdpe[PDPE(gva)];
        if (gpde & PTE_P) {
            ept_gpa2hva(eptrt, (void *) gpde, (void **) &pde);
            gpte = pde[PDX(gva)];
            if (gpte & PTE_P) {
                ept_gpa2hva(eptrt, (void *) gpte, (void **) &pte);
                gpa = (void *)pte[PTX(gva)];
                if ((uint64_t) gpa & PTE_P) {
    //cprintf("%lx -> PML4E: %lx (%lx) || PDPE: %lx (%lx) || PDE: %lx (%lx) || PTE: %lx (%lx)\n",
    //        gva, pml4e, guest_cr3, pdpe, gpdpe, pde, gpde, pte, gpte);
                    ept_gpa2hva(eptrt, (void *) gpa, (void **) &va);
                    //cprintf("Got GPA: %lx VA: %lx\n", gpa, va);
                    if (_gpa) *_gpa = gpa;
                    return (void *)va;
                }
            }
        }
    }
    return NULL;
}


// Set gpa in guest of ginfo as write protect
void
write_protect(struct VmxGuestInfo *ginfo, void *gpa) {
    pml4e_t *sptrt;
    void *gva;
    pte_t *spte; // spt entry that contains gva for

    sptrt = (pml4e_t *)KADDR(vmcs_read64(VMCS_GUEST_CR3)); // hva

    // Get gva from gpa with rmap
    gva = (void *) gpa2gva(ginfo, (void *)PTE_ADDR(gpa));
    //cprintf("write protect: GVA: %lx GPA: %lx\n", gva, gpa);

    // Find the entry for gva in SPT
    spte = pml4e_walk(sptrt, gva, 0);

    // Remove write permission from the entry
    *spte = *spte & ~PTE_W;
    void *gpa_hva;
    ept_gpa2hva(eptrt_, (void *) PTE_ADDR(gpa), (void **) &gpa_hva);
    assert (PTE_ADDR(*pml4e_walk(sptrt, (void *)PTE_ADDR(gva), 0)) == PADDR((uint64_t)gpa_hva));
}


// based on eptrt, add rmap: gpa -> gva
//                 add spt: gva -> hpa
void
add_pte(struct VmxGuestInfo *ginfo, uint64_t *eptrt, pte_t *pte,
        void *gva, pte_t *gpte, int perm) {
    pml4e_t *sptrt = (pml4e_t *)KADDR(vmcs_read64(VMCS_GUEST_CR3)); // hva
    pml4e_t *rmap = (pml4e_t *) ginfo->rmap;
    if (pte) {
        physaddr_t hpa = (physaddr_t) PADDR(pte);
        //cprintf("Map %lx -> %lx -> %lx (%d)\n", gva, gpte, hpa, perm);
        page_insert(sptrt, pa2page(hpa), (void *)PTE_ADDR(gva), perm);
        if ((void *)*pml4e_walk(sptrt, (void *)PTE_ADDR(gva), 0) != (void *)(hpa | perm)) {
            //cprintf("add_pte fail: Actual: %lx Expect: %lx Perm: %lx HVA: %lx GVA: %lx\n", PTE_ADDR(*pml4e_walk(sptrt, (void *)PTE_ADDR(gva), 0)), hpa, perm, pte, PTE_ADDR(gva));
            panic("fail\n");
        }
        if (perm & PTE_W) { // build a reverse map: i.e. gpa -> gva
            //cprintf("Add reversemap %lx -> %lx %lx\n", gpte, gva, perm);
            rmap_insert(rmap, (void *)PTE_ADDR(gpte),
                    (void *)PTE_ADDR(gva), perm);
            gpa2gva(ginfo, (void *)PTE_ADDR(gpte)) == PTE_ADDR(gva);
        }
    }
}

bool vmx_setup_sptrt(struct VmxGuestInfo *gInfo, uint64_t gcr3) {
    assert(gInfo->mmode == MODE_SPT);
    struct PageInfo *sptrt_page = page_alloc(ALLOC_ZERO);
    if (!sptrt_page) return false;
    sptrt_page->pp_ref++;
    struct PageInfo *rmap_page = page_alloc(ALLOC_ZERO);
    if (!rmap_page) {
        page_decref(sptrt_page);
        return false;
    }
    rmap_page->pp_ref++;
    gInfo->gcr3 = gcr3;
    gInfo->rmap = page2kva(rmap_page);
    vmcs_write64(VMCS_GUEST_CR3, (uint64_t) page2pa(sptrt_page));
    return true;
}

bool
build_spt(struct VmxGuestInfo *gInfo, uint64_t *eptrt) {
    struct PageInfo *new_page;
    pml4e_t *pml4e;
    tlbflush();
    if (vmx_setup_sptrt(gInfo, vmcs_read64(VMCS_GUEST_CR3))) {
        eptrt_ = eptrt;
        ept_gpa2hva(eptrt, (void *) gInfo->gcr3, (void **) &pml4e);
        //cprintf("pass 1: %lx\n", pml4e);
        {FOR_EACH_PML4E(gInfo, eptrt, pml4e, add_pte, write_protect, 1);}
        //cprintf("pass 2: %lx\n", pml4e);
        {FOR_EACH_PML4E(gInfo, eptrt, pml4e, add_pte, write_protect, 2);}
        write_protect(gInfo, (void *)gInfo->gcr3);
    }
    return true;
}

bool rebuild_spt(struct VmxGuestInfo *gInfo, uint64_t *eptrt, uint64_t ncr3) {
    #ifdef PERF_TEST
    static int counter = 0;
    cprintf("Counter rebuild_spt: %d\n", ++counter);
    #endif
    pml4e_t *sptrt = (pml4e_t *)KADDR(vmcs_read64(VMCS_GUEST_CR3)); // hva
    free_spt_level(sptrt, 3);
    free_rmap_level(gInfo->rmap, 3);
    // free the spt root page
    page_decref(pa2page(PADDR(sptrt)));
    page_decref(pa2page(PADDR(gInfo->rmap)));
    // flush tlb
    vmcs_write64(VMCS_GUEST_CR3, ncr3);
    return build_spt(gInfo, eptrt);
}

bool
handle_pf(struct Trapframe *tf, struct VmxGuestInfo *ginfo, uint64_t *eptrt) {
    uint64_t fault_addr = vmcs_read64(VMCS_VMEXIT_QUALIFICATION);
    uint64_t gpa = 0;
    void *va;
    pte_t *spte;
    void *fault_addr_hva = gva2hva(ginfo, eptrt, (void *)PTE_ADDR(fault_addr), (void **)&gpa);
    pml4e_t *sptrt = (pml4e_t *)KADDR(vmcs_read64(VMCS_GUEST_CR3)); // hva
    //cprintf("%lx -> %lx -> %lx\n", fault_addr, gpa, fault_addr_hva);
    if (fault_addr_hva) {
        spte = pml4e_walk(sptrt, (void *)PTE_ADDR(fault_addr), 0);
        //cprintf("%lx -> %lx -> %lx -> %lx\n", fault_addr, gpa, fault_addr_hva, *spte);
        if (*spte && PGOFF(gpa) != PGOFF(*spte)) {
            //cprintf("FADDR: %lx FADDR_HVA: %lx GPA: %lx SPTE: %lx rip: %lx\n", fault_addr, fault_addr_hva, gpa, *spte, tf->tf_rip);
            vmcs_write32( VMCS_32BIT_CONTROL_EXCEPTION_BITMAP,
                    (1 << T_PGFLT) | (1 << T_ILLOP) );
            int fault_insn_len = vmcs_read32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH);
            uint64_t fault_ninsn_gva = tf->tf_rip + fault_insn_len;
            char *fault_ninsn = (char *)gva2hva(ginfo, eptrt, (void *)fault_ninsn_gva, NULL) + PGOFF(fault_ninsn_gva);
            ginfo->nchar[0] = ((char *)fault_ninsn)[0];
            ginfo->nchar[1] = ((char *)fault_ninsn)[1];
            ginfo->fault_ninsn = fault_ninsn;
            // Push int 0x3
            ((char *)fault_ninsn)[0] = 0x0f;
            ((char *)fault_ninsn)[1] = 0x0b;
            *spte = (*spte) | PTE_W;
            invlpg((void *)PTE_ADDR(*spte));
            return true;
        } // ELSE: true fault
    } else if (!fault_addr_hva && !gpa) {
        // True fault: 24.8.3 VM-Entry Controls for Event Injection
        uint32_t intr = (T_PGFLT) | // Pagefault
                        (3 * (1 << 8)) | // Hardware exception
                        (1 << 11) | // Deliver error code
                        0x80000000; // Valid
        uint32_t error_code = vmcs_read32( VMCS_32BIT_VMEXIT_INTERRUPTION_ERR_CODE );
        vmcs_write32( VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO, intr );
        vmcs_write32( VMCS_32BIT_CONTROL_VMENTRY_EXCEPTION_ERR_CODE, error_code );
        //cprintf("inject pgfault: %lx errorcode:%d\n", fault_addr, error_code);
        tf->tf_err = fault_addr;
        return true;
    } else if (gpa < 0xA0000 || (gpa >= 0x100000 && gpa < ginfo->phys_sz)) {
        //cprintf("add gpa %lx to ept\n", gpa);
        insert_ept_entry(eptrt, gpa, ginfo);
        return rebuild_spt(ginfo, eptrt, ginfo->gcr3);
    }
    return false;
}

bool
handle_pf_singlestep_done(struct Trapframe *tf,
        struct VmxGuestInfo *ginfo, uint64_t *eptrt) {
    //cprintf("digest single stepping\n");
    ginfo->fault_ninsn[0] = ginfo->nchar[0];
    ginfo->fault_ninsn[1] = ginfo->nchar[1];
    ginfo->fault_ninsn = NULL;
    vmcs_write32( VMCS_32BIT_CONTROL_EXCEPTION_BITMAP, (1 << T_PGFLT) );
    return rebuild_spt(ginfo, eptrt, ginfo->gcr3);
}

bool
handle_nmi(struct Trapframe *tf, struct VmxGuestInfo *ginfo, uint64_t *eptrt,
           uint32_t intr_info) {
    uint32_t vector = intr_info & 0xff;
    switch (vector) {
        case T_ILLOP: return handle_pf_singlestep_done(tf, ginfo, eptrt);
        case T_PGFLT: return handle_pf(tf, ginfo, eptrt);
        default:
            return false;
    }
}

bool
handle_interrupts(struct Trapframe *tf, struct VmxGuestInfo *ginfo, uint32_t host_vector) {
	uint64_t rflags;
	uint32_t procbased_ctls_or;
	rflags = vmcs_read64(VMCS_GUEST_RFLAGS);
	
	if ( !(rflags & (0x1 << 9)) ) {	//we have to wait the interrupt window open
		//get the interrupt info
		
		procbased_ctls_or = vmcs_read32( VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS);
            
		//disable the interrupt window exiting
		procbased_ctls_or |= VMCS_PROC_BASED_VMEXEC_CTL_INTRWINEXIT; 
		
		vmcs_write32( VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS, 
			      procbased_ctls_or);
	}
	else {	//revector the host vector to the guest vector
		
		vmcs_write32( VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO , host_vector);
	}
	
	
	
	return true;
}

bool
handle_rdmsr(struct Trapframe *tf, struct VmxGuestInfo *ginfo) {
	uint64_t msr = tf->tf_regs.reg_rcx;
	if(msr == EFER_MSR) {
		// TODO: setup msr_bitmap to ignore EFER_MSR
		uint64_t val;
		struct vmx_msr_entry *entry;
		bool r = find_msr_in_region(msr, ginfo->msr_guest_area, ginfo->msr_count, &entry);
		assert(r);
		val = entry->msr_value;

		tf->tf_regs.reg_rdx = val << 32;
		tf->tf_regs.reg_rax = val & 0xFFFFFFFF;

		tf->tf_rip += vmcs_read32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH);
		return true;
	}

	return false;
}

bool 
handle_wrmsr(struct Trapframe *tf, struct VmxGuestInfo *ginfo) {
	uint64_t msr = tf->tf_regs.reg_rcx;
	if(msr == EFER_MSR) {

		uint64_t cur_val, new_val;
		struct vmx_msr_entry *entry;
		bool r = 
			find_msr_in_region(msr, ginfo->msr_guest_area, ginfo->msr_count, &entry);
		assert(r);
		cur_val = entry->msr_value;

		new_val = (tf->tf_regs.reg_rdx << 32)|tf->tf_regs.reg_rax;
		if(BIT(cur_val, EFER_LME) == 0 && BIT(new_val, EFER_LME) == 1) {
			// Long mode enable.
			uint32_t entry_ctls = vmcs_read32( VMCS_32BIT_CONTROL_VMENTRY_CONTROLS );
			vmcs_write32( VMCS_32BIT_CONTROL_VMENTRY_CONTROLS, 
				      entry_ctls );

		}

		entry->msr_value = new_val;
		tf->tf_rip += vmcs_read32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH);
		return true;
	}

	return false;
}


bool
insert_ept_entry (uint64_t *eptrt, uint64_t gpa, struct VmxGuestInfo *ginfo) {
	int r;
	if(gpa < 0xA0000 || (gpa >= 0x100000 && gpa < ginfo->phys_sz)) 

	{
		// Allocate a new page to the guest.
		struct PageInfo *p = page_alloc(0);
		if(!p) {
			cprintf("vmm: handle_eptviolation: Failed to allocate a page for guest---out of memory.\n");
			return false;
		}
		p->pp_ref += 1;
		r = ept_map_hva2gpa(eptrt, 
				    page2kva(p), (void *)ROUNDDOWN(gpa, PGSIZE), __EPTE_FULL, 0);
		assert(r >= 0);

		//cprintf("EPT violation for gpa:%x mapped KVA:%x @ %lx(%d)\n", gpa, page2kva(p), vmcs_read64(VMCS_GUEST_RIP), vmcs_read32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH));
		return true;
	} else if (gpa >= CGA_BUF && gpa < CGA_BUF + PGSIZE) {
		// FIXME: This give direct access to VGA MMIO region.
		r = ept_map_hva2gpa(eptrt, 
				    (void *)(KERNBASE + CGA_BUF), (void *)CGA_BUF, __EPTE_FULL, 0);
		assert(r >= 0);
		return true;
	}
	cprintf("vmm: handle_eptviolation: Case 2, gpa %x >= %x\n", gpa, ginfo->phys_sz);
    return false;
}

bool
handle_eptviolation(uint64_t *eptrt, struct VmxGuestInfo *ginfo) {
	uint64_t gpa = vmcs_read64(VMCS_64BIT_GUEST_PHYSICAL_ADDR);
    return insert_ept_entry(eptrt, gpa, ginfo);
}

bool
handle_ioinstr(struct Trapframe *tf, struct VmxGuestInfo *ginfo) {
	static int port_iortc;
	
	uint64_t qualification = vmcs_read64(VMCS_VMEXIT_QUALIFICATION);
	int port_number = (qualification >> 16) & 0xFFFF;
	bool is_in = BIT(qualification, 3);
	bool handled = false;
	
	// handle reading physical memory from the CMOS.
	if(port_number == IO_RTC) {
		if(!is_in) {
			port_iortc = tf->tf_regs.reg_rax;
			handled = true;
		}
	} else if (port_number == IO_RTC + 1) {
		if(is_in) {
			if(port_iortc == NVRAM_BASELO) {
				tf->tf_regs.reg_rax = 640 & 0xFF;
				handled = true;
			} else if (port_iortc == NVRAM_BASEHI) {
				tf->tf_regs.reg_rax = (640 >> 8) & 0xFF;
				handled = true;
			} else if (port_iortc == NVRAM_EXTLO) {
				tf->tf_regs.reg_rax = ((ginfo->phys_sz / 1024) - 1024) & 0xFF;
				handled = true;
			} else if (port_iortc == NVRAM_EXTHI) {
				tf->tf_regs.reg_rax = (((ginfo->phys_sz / 1024) - 1024) >> 8) & 0xFF;
				handled = true;
			}
		}
		
	} 

	if(handled) {
		tf->tf_rip += vmcs_read32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH);
		return true;
	} else {
		cprintf("%x %x\n", qualification, port_iortc);
		return false;    
	}
}

// Emulate a cpuid instruction.
// It is sufficient to issue the cpuid instruction here and collect the return value.
// You can store the output of the instruction in Trapframe tf,
//  but you should hide the presence of vmx from the guest if processor features are requested.
// 
// Return true if the exit is handled properly, false if the VM should be terminated.
//
// Finally, you need to increment the program counter in the trap frame.
// 
// Hint: The TA's solution does not hard-code the length of the cpuid instruction.
bool
handle_cpuid(struct Trapframe *tf, struct VmxGuestInfo *ginfo)
{
	/* Your code here */
	uint32_t eax, ebx, ecx, edx;
    uint32_t ineax = tf->tf_regs.reg_rax & 0xffffffff;
    if (ineax == 1) {
        cpuid( ineax, &eax, &ebx, &ecx, &edx );
        tf->tf_regs.reg_rcx = ecx & (~(1 << 5));
    } else {
        cpuid( ineax, &eax, &ebx, &ecx, &edx );
        tf->tf_regs.reg_rcx = ecx;
    }
    tf->tf_regs.reg_rax = eax;
    tf->tf_regs.reg_rbx = ebx;
    tf->tf_regs.reg_rdx = edx;
    tf->tf_rip += vmcs_read32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH);
    return true;
}

void setup_e820_mmap_entry(memory_map_t *mmap, uint64_t base_addr,
                           uint64_t end_addr, int type) {
    uint64_t length = end_addr - base_addr;
    mmap->size = 20;
    mmap->base_addr_low = base_addr & 0xffffffff;
    mmap->base_addr_high = (base_addr >> 32) & 0xffffffff;
    mmap->length_low = length & 0xffffffff;
    mmap->length_high = (length >> 32) & 0xffffffff;
    mmap->type = type;
}

envid_t get_fs_fs(void) {
    static envid_t fs_fs = -1;
    if (fs_fs != -1) return fs_fs;
    else {
        int i = 0;
        for(; i < NENV && envs[i].env_type != ENV_TYPE_FS; i++);
        fs_fs = envs[i].env_id;
    }
    return fs_fs;
}

void vmx_switch_ept(struct Trapframe *tf, struct VmxGuestInfo *gInfo,
        uint64_t *eptrt) {
    // Set proc-based controls.
    uint32_t procbased_ctls_or, procbased_ctls_and;
    vmx_read_capability_msr( IA32_VMX_PROCBASED_CTLS, 
            &procbased_ctls_and, &procbased_ctls_or );
    // Make sure there are secondary controls.
    assert( BIT( procbased_ctls_and, 31 ) == 0x1 ); 

    procbased_ctls_or |= VMCS_PROC_BASED_VMEXEC_CTL_ACTIVESECCTL; 
    procbased_ctls_or |= VMCS_PROC_BASED_VMEXEC_CTL_HLTEXIT;
    procbased_ctls_or |= VMCS_PROC_BASED_VMEXEC_CTL_USEIOBMP;
    /* CR3 accesses and invlpg don't need to cause VM Exits when EPT
       enabled */
    procbased_ctls_or &= ~( VMCS_PROC_BASED_VMEXEC_CTL_CR3LOADEXIT |
            VMCS_PROC_BASED_VMEXEC_CTL_CR3STOREXIT | 
            VMCS_PROC_BASED_VMEXEC_CTL_INVLPGEXIT );

    vmcs_write32( VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS, 
            procbased_ctls_or & procbased_ctls_and );

    // Set Proc based secondary controls.
    uint32_t procbased_ctls2_or, procbased_ctls2_and;
    vmx_read_capability_msr( IA32_VMX_PROCBASED_CTLS2, 
            &procbased_ctls2_and, &procbased_ctls2_or );

    // Enable EPT.
    procbased_ctls2_or |= VMCS_SECONDARY_VMEXEC_CTL_ENABLE_EPT;
    procbased_ctls2_or |= VMCS_SECONDARY_VMEXEC_CTL_UNRESTRICTED_GUEST;
    vmcs_write32( VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS, 
            procbased_ctls2_or & procbased_ctls2_and );

    uint64_t ept_ptr = (uint64_t) eptrt | ( ( EPT_LEVELS - 1 ) << 3 );
    vmcs_write64( VMCS_64BIT_CONTROL_EPTPTR, ept_ptr 
            | VMX_EPT_DEFAULT_MT
            | (VMX_EPT_DEFAULT_GAW << VMX_EPT_GAW_EPTP_SHIFT) );
}

void vmx_switch_spt(struct Trapframe *tf, struct VmxGuestInfo *gInfo,
        uint64_t *eptrt) {
    // Set proc-based controls.
    uint32_t procbased_ctls_or, procbased_ctls_and;
    vmx_read_capability_msr( IA32_VMX_PROCBASED_CTLS, 
            &procbased_ctls_and, &procbased_ctls_or );

    // Make sure there are secondary controls.
    assert( BIT( procbased_ctls_and, 31 ) == 0x1 ); 

    procbased_ctls_or |= VMCS_PROC_BASED_VMEXEC_CTL_ACTIVESECCTL; 
    procbased_ctls_or |= VMCS_PROC_BASED_VMEXEC_CTL_HLTEXIT;
    procbased_ctls_or |= VMCS_PROC_BASED_VMEXEC_CTL_USEIOBMP;

    /* CR3 accesses and invlpg need to cause VM Exits when SPT enabled */
    procbased_ctls_or |= VMCS_PROC_BASED_VMEXEC_CTL_CR3LOADEXIT |
                         VMCS_PROC_BASED_VMEXEC_CTL_CR3STOREXIT |
                         VMCS_PROC_BASED_VMEXEC_CTL_INVLPGEXIT;

    vmcs_write32( VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS, 
            procbased_ctls_or & procbased_ctls_and );

    // Set Proc based secondary controls.
    uint32_t procbased_ctls2_or, procbased_ctls2_and;
    vmx_read_capability_msr( IA32_VMX_PROCBASED_CTLS2, 
            &procbased_ctls2_and, &procbased_ctls2_or );

    // Disable EPT.
    procbased_ctls2_or &= ~( VMCS_SECONDARY_VMEXEC_CTL_ENABLE_EPT |
                             VMCS_SECONDARY_VMEXEC_CTL_UNRESTRICTED_GUEST);
    vmcs_write32( VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS,
            procbased_ctls2_or & procbased_ctls2_and );
    vmcs_write32( VMCS_32BIT_CONTROL_EXCEPTION_BITMAP, (1 << T_PGFLT) );
}


bool
handle_ipc_send(struct Trapframe *tf, struct VmxGuestInfo *gInfo, uint64_t *eptrt) {
    envid_t to_env = tf->tf_regs.reg_rbx;
    uint32_t val = tf->tf_regs.reg_rcx;
    void *pg = (void *)tf->tf_regs.reg_rdx;
    int perm = tf->tf_regs.reg_rsi;
    void *host_va;
    if (to_env == VMX_HOST_FS_ENV) {
        to_env = get_fs_fs();
        ept_gpa2hva(eptrt, pg, &host_va);
        tf->tf_regs.reg_rax = syscall(SYS_ipc_try_send, to_env,
                                      val, (uint64_t) host_va, perm, 0);
    } else {
        tf->tf_regs.reg_rax = -E_BAD_ENV;
    }
    return true;
}

bool
handle_ipc_recv(struct Trapframe *tf, struct VmxGuestInfo *gInfo, uint64_t *eptrt) {
    void *dst = (void *)tf->tf_regs.reg_rbx;
    tf->tf_rip += vmcs_read32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH);
    tf->tf_regs.reg_rax = syscall(SYS_ipc_recv, (uint64_t) dst, 0, 0, 0, 0);
    return true;
}
// Handle vmcall traps from the guest.
// We currently support 3 traps: read the virtual e820 map, 
//   and use host-level IPC (send andrecv).
//
// Return true if the exit is handled properly, false if the VM should be terminated.
//
// Finally, you need to increment the program counter in the trap frame.
// 
// Hint: The TA's solution does not hard-code the length of the cpuid instruction.//

bool
handle_vmcall(struct Trapframe *tf, struct VmxGuestInfo *gInfo, uint64_t *eptrt)
{
	bool handled = false;
	multiboot_info_t *mbinfo;
    memory_map_t* mmap;
    void *mbinfo_host_va;
	int perm, r;
	void *gpa_pg, *hva_pg;
	envid_t to_env;
	uint32_t val;
	// phys address of the multiboot map in the guest.
	uint64_t multiboot_map_addr = 0x6000;
    MemoryMode mmode;
    uint64_t guest_cr3;
    
    struct PageInfo *new_page;

	switch(tf->tf_regs.reg_rax) {
	case VMX_VMCALL_MBMAP:
		// Craft a multiboot (e820) memory map for the guest.
		//
		// Create three  memory mapping segments: 640k of low mem, the I/O hole (unusable), and 
		//   high memory (phys_size - 1024k).
		//
		// Once the map is ready, find the kernel virtual address of the guest page (if present),
		//   or allocate one and map it at the multiboot_map_addr (0x6000).
		// Copy the mbinfo and memory_map_t (segment descriptions) into the guest page, and return
		//   a pointer to this region in rbx (as a guest physical address).
		/* Your code here */

        ept_gpa2hva(eptrt, (void *)multiboot_map_addr, &mbinfo_host_va);
        if (mbinfo_host_va == NULL) {
            struct PageInfo *p = page_alloc(0);
            if(!p) {
                cprintf("vmm: handle_vmcall: Failed to allocate a page for guest---out of memory.\n");
                return false;
            }
            p->pp_ref++;
            r = ept_map_hva2gpa(eptrt,
                    page2kva(p), (void *)multiboot_map_addr, __EPTE_FULL, 0);
            assert (r >= 0);
            mbinfo_host_va = page2kva(p);
        }
        mbinfo = (multiboot_info_t *) mbinfo_host_va;
        memset((void *)mbinfo, 0, sizeof(multiboot_info_t));
        mbinfo->flags = MB_FLAG_MMAP;
        mbinfo->mmap_length = 3 * sizeof(memory_map_t);
        mbinfo->mmap_addr = multiboot_map_addr + sizeof(multiboot_info_t);
        mmap =  (memory_map_t *)(mbinfo_host_va + sizeof(multiboot_info_t));
        // 640k of low mem
        setup_e820_mmap_entry(mmap, 0, IOPHYSMEM, MB_TYPE_USABLE);
        // IO Hole
        mmap++;
        setup_e820_mmap_entry(mmap, IOPHYSMEM, EXTPHYSMEM, MB_TYPE_RESERVED);
        // High Mem
        mmap++;
        setup_e820_mmap_entry(mmap, EXTPHYSMEM, gInfo->phys_sz, MB_TYPE_USABLE);
        tf->tf_regs.reg_rbx = multiboot_map_addr;
		handled = true;

		break;
	case VMX_VMCALL_IPCSEND:
		// Issue the sys_ipc_send call to the host.
		// 
		// If the requested environment is the HOST FS, this call should
		//  do this translation.
		//
		// The input should be a guest physical address; you will need to convert
		//  this to a host virtual address for the IPC to work properly.
		/* Your code here */

        handled = handle_ipc_send(tf, gInfo, eptrt);

		break;

	case VMX_VMCALL_IPCRECV:
		// Issue the sys_ipc_recv call for the guest.
		// NB: because recv can call schedule, clobbering the VMCS, 
		// you should go ahead and increment rip before this call.
		/* Your code here */

        handled = handle_ipc_recv(tf, gInfo, eptrt);

		break;
	case VMX_VMCALL_LAPICEOI:
		lapic_eoi();
		handled = true;
		break;
	case VMX_VMCALL_BACKTOHOST:
		cprintf("Now back to the host, VM halt in the background, run vmmanager to resume the VM.\n");
		curenv->env_status = ENV_NOT_RUNNABLE;	//mark the guest not runable
		ENV_CREATE(user_sh, ENV_TYPE_USER);	//create a new host shell
		handled = true;
		break;	
	case VMX_VMCALL_GETDISKIMGNUM:	//alloc a number to guest
		tf->tf_regs.reg_rax = vmdisk_number;
		handled = true;
		break;
    case VMX_VMCALL_SWITCH_MMODE: // switch the memory mode
        mmode = tf->tf_regs.reg_rdx;
        if (gInfo->mmode != mmode) {
            switch (mmode) {
                case MODE_EPT:
                    gInfo->mmode = mmode;
                    vmx_switch_ept(tf, gInfo, eptrt);
                    //TODO
                    break;
                case MODE_SPT:
                    gInfo->mmode = mmode;
                    vmx_switch_spt(tf, gInfo, eptrt);
                    handled = build_spt(gInfo, eptrt);
                    break;
                default:
                    panic("Illegal mode");
            }
        }
        tf->tf_regs.reg_rax = 0;
        handled = true;
	}
	if(handled) {
		/* Advance the program counter by the length of the vmcall instruction. 
		 * 
		 * Hint: The TA solution does not hard-code the length of the vmcall instruction.
		 */
		/* Your code here */
        tf->tf_rip += vmcs_read32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH);
	}
	return handled;
}


uint64_t *decode_register(struct Trapframe *tf, int r) {
    switch (r) {
        case 0:  return &tf->tf_regs.reg_rax;
        case 1:  return &tf->tf_regs.reg_rcx;
        case 2:  return &tf->tf_regs.reg_rdx;
        case 3:  return &tf->tf_regs.reg_rbx;
        case 4:  return &tf->tf_rsp;
        case 5:  return &tf->tf_regs.reg_rbp;
        case 6:  return &tf->tf_regs.reg_rsi;
        case 7:  return &tf->tf_regs.reg_rdi;
        case 8:  return &tf->tf_regs.reg_r8;
        case 9:  return &tf->tf_regs.reg_r9;
        case 10: return &tf->tf_regs.reg_r10;
        case 11: return &tf->tf_regs.reg_r11;
        case 12: return &tf->tf_regs.reg_r12;
        case 13: return &tf->tf_regs.reg_r13;
        case 14: return &tf->tf_regs.reg_r14;
        case 15: return &tf->tf_regs.reg_r15;
        default: panic("Never reach");
    }
}


void free_spt_level(pml4e_t* sptrt, int level) {
    pml4e_t* dir = sptrt;
    physaddr_t hpa;
    int i;

    for(i=0; i<NPTENTRIES; ++i) {
        if(level) {
            if(dir[i] & PTE_P) {
                hpa = PTE_ADDR(dir[i]);
                free_spt_level((pml4e_t*) KADDR(hpa), level-1);
                page_decref(pa2page(hpa));
            }
        } else { // Last level - no more recursive calls
            if(dir[i] & PTE_P) {
                hpa = PTE_ADDR(dir[i]);
                page_decref(pa2page(hpa));
            }
        }
    }
    return;
}

void free_rmap_level(pml4e_t* sptrt, int level) {
    pml4e_t* dir = sptrt;
    physaddr_t hpa;
    int i;

    for(i=0; i<NPTENTRIES; ++i) {
        if(level) {
            if(dir[i] & PTE_P) {
                hpa = PTE_ADDR(dir[i]);
                free_rmap_level((pml4e_t*) KADDR(hpa), level-1);
                page_decref(pa2page(hpa));
            }
        }
    }
    return;
}


 /* 11:8 - general purpose register operand */
#define VMX_REG_ACCESS_GPR(eq)  (((eq) >> 8) & 0xf)
#define VMX_CR_REASON_MASK 0x3f
bool
handle_mov_cr(struct Trapframe *tf, struct VmxGuestInfo *gInfo, uint64_t *eptrt)
{
    uint32_t reason = vmcs_readl(VMCS_VMEXIT_QUALIFICATION);
    uint32_t gpr = VMX_REG_ACCESS_GPR(reason);
    uint64_t *src = decode_register(tf, gpr);
    physaddr_t new_cr3;
    struct PageInfo *new_page;
    pml4e_t *sptrt;

    //cprintf("mov_cr_reason: %lx @ %lx\n", reason, tf->tf_rip);
    switch (reason & VMX_CR_REASON_MASK) {
        case VMEXIT_CR3_WRITE:
            // get gcr3 and translated to gpa and then write it to value
            *src = (uint64_t) gInfo->gcr3;
            break;
        case VMEXIT_CR3_READ:
            // free spt that was currently being used
            // cprintf("CR3 change!: %lx\n", *src);
            rebuild_spt(gInfo, eptrt, *src);
            break;
        default:
            return 0;
    }
    tf->tf_rip += vmcs_read32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH);
    return 1;
}

bool
handle_invlpg(struct Trapframe *tf, struct VmxGuestInfo *gInfo, uint64_t *eptrt) {
    uint64_t gaddr = vmcs_read64(VMCS_VMEXIT_QUALIFICATION);
    uint64_t haddr;
    ept_gpa2hva(eptrt, (void *) gaddr, (void **) &haddr);
    invlpg((void *)haddr);
    tf->tf_rip += vmcs_read32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH);
    return true;
}
