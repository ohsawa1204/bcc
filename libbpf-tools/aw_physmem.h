/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __AW_PHYSMEM_H
#define __AW_PHYSMEM_H

#define ARGSIZE  128
#define TASK_COMM_LEN 16
//#define ENABLE_TIMESTATMP
//#define HOOK_HANDLE_MM_FAULT
//#define ENABLE_CALLSTACK
//#define VMRSS_DEBUG
#define GEN_RAW_BINARY

#if defined ENABLE_TIMESTATMP || defined HOOK_HANDLE_MM_FAULT || defined ENABLE_CALLSTACK || defined VMRSS_DEBUG
#undef GEN_RAW_BINARY
#endif

#define UNMAP_FLAG          (1 << 31)
#define ZAP_FLAG            (1 << 30)
#define EXEC_FLAG           (1 << 29)
#define FIRST_UNMAP_FLAG    (1 << 28)
#define MARKER              (1 << 20)
#define END                 (1 << 19)

struct pte_event {
	__u32 flags;
	__u64 vaddr, vaddr2;
	#ifdef ENABLE_TIMESTATMP
	__u64 ts;
	#endif
	#ifdef HOOK_HANDLE_MM_FAULT
	__u8 major;
	__u64 delta;
	#endif
	#ifdef ENABLE_CALLSTACK
	__u32 stack_id;
	#endif
	#ifdef VMRSS_DEBUG
	__u64 count[4];
	#endif
};

struct event {
	pid_t pid;
	struct pte_event pte_event;
};

#endif /* __AW_PHYSMEM_H */
