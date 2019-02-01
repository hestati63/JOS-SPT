#include <inc/lib.h>
#include <inc/vmx.h>
#include <inc/elf.h>
#include <inc/ept.h>
#include <inc/stdio.h>

#define GUEST_KERN "/vmm/kernel"
#define GUEST_BOOT "/vmm/boot"

#define JOS_ENTRY 0x7000

static void *do_alloc() {
    static void *va = (void *)USTACKTOP - 2 * PGSIZE;
    while (sys_page_alloc(sys_getenvid(), va,  PTE_P|PTE_U|PTE_W) < 0) {
        va -= PGSIZE;
    }
    void *ret = va;
    va -= PGSIZE;
    return ret;
}
// Map a region of file fd into the guest at guest physical address gpa.
// The file region to map should start at fileoffset and be length filesz.
// The region to map in the guest should be memsz.  The region can span multiple pages.
//
// Return 0 on success, <0 on failure.
//
static int
map_in_guest( envid_t guest, uintptr_t gpa, size_t memsz,
              int fd, size_t filesz, off_t fileoffset ) {
    /* Your code here */
    int res = 0;
    size_t pos = 0;
    envid_t me = sys_getenvid();
    seek(fd, fileoffset);
    for (pos = 0; pos < memsz; pos += PGSIZE) {
        void *hva = do_alloc();
        if (pos < filesz)
            read (fd, hva, filesz - pos > PGSIZE ? PGSIZE : filesz - pos);
        if ((res = sys_ept_map(me, hva, guest, (void *) gpa + pos, __EPTE_READ | __EPTE_WRITE | __EPTE_EXEC)) < 0)
            return res;
    }
    return 0;
}

static int read_and_verify(int fd, void *buf, int size) {
    return (read(fd, buf, size) != size) ? -1 : 0;
}

// Read the ELF headers of kernel file specified by fname,
// mapping all valid segments into guest physical memory as appropriate.
//
// Return 0 on success, <0 on error
//
// Hint: compare with ELF parsing in env.c, and use map_in_guest for each segment.
static int
copy_guest_kern_gpa( envid_t guest, char* fname ) {

	/* Your code here */
    int res = 0, i;
    struct Elf elf;
    struct Proghdr ph;

    int kern = open(fname, O_RDONLY);
    if (kern < 0) {
        cprintf("open %s for read: %e\n", fname, kern);
        return -E_NO_SYS;
    }

    if (read_and_verify(kern, &elf, sizeof(struct Elf)) < 0) {
        res = -E_NO_SYS;
        goto CLEAN_AND_EXIT;
    }

    if (elf.e_magic == ELF_MAGIC) {
        for (i = 0; i < elf.e_phnum; i++) {
            seek(kern, elf.e_phoff + i * sizeof(struct Proghdr));
            if (read_and_verify(kern, &ph, sizeof(struct Proghdr)) < 0) {
                res = -E_NO_SYS;
                goto CLEAN_AND_EXIT;
            }

            if (ph.p_type == ELF_PROG_LOAD) {
                if (map_in_guest(guest, ph.p_pa, ph.p_memsz, kern, ph.p_filesz, ph.p_offset) < 0) {
                    cprintf("map_in_guest fail\n");
                    res = -E_NO_SYS;
                    goto CLEAN_AND_EXIT;
                }
            }
        }
    } else {
        cprintf("Invalid Binary\n");
        res = -E_NO_SYS;
        goto CLEAN_AND_EXIT;
    }
CLEAN_AND_EXIT:
    close(kern);
    return res;
}

void
umain(int argc, char **argv) {

	int ret;
	envid_t guest;
	char filename_buffer[50];	//buffer to save the path 
	int vmdisk_number;
	int r;
	if ((ret = sys_env_mkguest( GUEST_MEM_SZ, JOS_ENTRY )) < 0) {
		cprintf("Error creating a guest OS env: %e\n", ret );
		exit();
	}
	guest = ret;

	// Copy the guest kernel code into guest phys mem.
	if((ret = copy_guest_kern_gpa(guest, GUEST_KERN)) < 0) {
		cprintf("Error copying page into the guest - %d\n.", ret);
		exit();
	}

	// Now copy the bootloader.
	int fd;
	if ((fd = open( GUEST_BOOT, O_RDONLY)) < 0 ) {
		cprintf("open %s for read: %e\n", GUEST_BOOT, fd );
		exit();
	}

	// sizeof(bootloader) < 512.
	if ((ret = map_in_guest(guest, JOS_ENTRY, 512, fd, 512, 0)) < 0) {
		cprintf("Error mapping bootloader into the guest - %d\n.", ret);
		exit();
	}

#ifndef VMM_GUEST	
	sys_vmx_incr_vmdisk_number();	//increase the vmdisk number
	//create a new guest disk image

	vmdisk_number = sys_vmx_get_vmdisk_number();
	snprintf(filename_buffer, 50, "/vmm/fs%d.img", vmdisk_number);

	cprintf("Creating a new virtual HDD at /vmm/fs%d.img\n", vmdisk_number);
	r = copy("vmm/clean-fs.img", filename_buffer);

	if (r < 0) {
		cprintf("Create new virtual HDD failed: %e\n", r);
		exit();
	}

	cprintf("Create VHD finished\n");
#endif

	// Mark the guest as runnable.
	sys_env_set_status(guest, ENV_RUNNABLE);
	wait(guest);
}


