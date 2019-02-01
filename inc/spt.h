#ifndef JOS_INC_SPT_H
#define JOS_INC_SPT_H

#define __SPTE_READ	0x01
#define __SPTE_WRITE	0x02
#define __SPTE_EXEC	0x04
#define __SPTE_IPAT	0x40
#define __SPTE_SZ	0x80
#define __SPTE_A	0x100
#define __SPTE_D	0x200
#define __SPTE_TYPE(n)	(((n) & 0x7) << 3)

enum {
	 SPTE_TYPE_UC = 0, /* uncachable */
	 SPTE_TYPE_WC = 1, /* write combining */
	 SPTE_TYPE_WT = 4, /* write through */
	 SPTE_TYPE_WP = 5, /* write protected */
	 SPTE_TYPE_WB = 6, /* write back */
};

#define __SPTE_NONE	0
#define __SPTE_FULL	(__SPTE_READ | __SPTE_WRITE | __SPTE_EXEC)

#endif