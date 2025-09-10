// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "aw_physmem.h"

//#define HOOK_SET_PTE_RANGE

static char ros2_str[] = "/opt/ros/humble/bin/ros2";
//static char ros2_str[] = "/home/takashiosawa/work/tools/bcc/libbpf-tools/test/hoge";
static int ros2_str_len = sizeof(ros2_str) - 1;

const volatile bool ignore_failed = true;

static const struct event empty_event = {};

#ifdef ENABLE_TIMESTATMP
static __u64 start_ts;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, pid_t);
	__type(value, struct event);
} target_processes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct mm_struct *);
	__type(value, struct event);
} target_mms SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32);
	__type(key, pid_t);
	__type(value, struct mm_struct *);
} unmap_pid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

#ifdef ENABLE_CALLSTACK
#define PERF_MAX_STACK_DEPTH 30
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, 10000);
} stack_traces SEC(".maps");
#endif

static __always_inline bool strmatch(char *s1, char *s2, size_t len)
{
	for (int i = 0; i < len; i++) {
		if (s1[i] != s2[i])
			return false;
	}
	return true;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct syscall_trace_enter* ctx)
{
	u64 id;
	pid_t pid;
	int ret;
	struct event *event;
	static bool ros2_launch_executed = false;

	if (!ros2_launch_executed) {
		char args[ARGSIZE];
		ret = bpf_probe_read_user_str(args, ARGSIZE, (const char*)ctx->args[0]);
		if (ret < 0)
			return 0;
		if (strmatch(args, ros2_str, ros2_str_len)) {
			ros2_launch_executed = true;
			#ifdef ENABLE_TIMESTATMP
			start_ts = bpf_ktime_get_ns();
			#endif
		} else
			return 0;
	} else {
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		id = bpf_get_current_pid_tgid();
		pid_t ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
		if (!bpf_map_lookup_elem(&target_processes, &ppid))
			return 0;
	}

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	if (bpf_map_update_elem(&target_processes, &pid, &empty_event, BPF_NOEXIST))
		return 0;
	event = bpf_map_lookup_elem(&target_processes, &pid);
	if (!event)
		return 0;

	event->pid = pid;
	event->pte_event.vaddr = 0xe;
	event->pte_event.vaddr2 = 0xc;
	event->pte_event.flags = EXEC_FLAG;

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct syscall_trace_exit* ctx)
{
	u64 id;
	pid_t pid;
	int ret;
	struct event *event, *event_mm;
	struct task_struct *task;
	struct mm_struct *mm;

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	event = bpf_map_lookup_elem(&target_processes, &pid);
	if (!event)
		return 0;
	ret = ctx->ret;
	if (ignore_failed && ret < 0) {
		bpf_map_delete_elem(&target_processes, &pid);
		return 0;
	}

	#ifdef VMRSS_DEBUG
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct mm_rss_stat mm_rss_stat = BPF_CORE_READ(task, mm, rss_stat);
	event->pte_event.count[0] = *(__u64 *)&mm_rss_stat.count[0];
	event->pte_event.count[1] = *(__u64 *)&mm_rss_stat.count[1];
	struct task_rss_stat task_rss_stat = BPF_CORE_READ(task, rss_stat);
	event->pte_event.count[2] = task_rss_stat.count[0];
	event->pte_event.count[3] = task_rss_stat.count[1];
	#endif

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

	task = (struct task_struct *)bpf_get_current_task();
	mm = (struct mm_struct *)BPF_CORE_READ(task, mm);
	if (bpf_map_update_elem(&target_mms, &mm, &empty_event, BPF_ANY))
		return 0;
	event_mm = bpf_map_lookup_elem(&target_mms, &mm);
	if (!event_mm)
		return 0;
	*event_mm = *event;

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int tracepoint__syscalls__sys_enter_exit(struct syscall_trace_enter* ctx)
{
	u64 id;
	pid_t pid;
	struct task_struct *task;
	struct mm_struct *mm;

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	if (bpf_map_lookup_elem(&target_processes, &pid))
		bpf_map_delete_elem(&target_processes, &pid);

	task = (struct task_struct *)bpf_get_current_task();
	mm = (struct mm_struct *)BPF_CORE_READ(task, mm);
	if (bpf_map_lookup_elem(&target_mms, &mm))
		bpf_map_delete_elem(&target_mms, &mm);
	return 0;
}

#ifdef HOOK_HANDLE_MM_FAULT
SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(handle_mm_fault_entry, struct vm_area_struct *vma, unsigned long address, unsigned int flags, struct pt_regs *regs) {
	u64 id;
	pid_t pid, tgid, ppid;
	struct event *event;
	struct task_struct *task;

	id = bpf_get_current_pid_tgid();
	tgid = id >> 32;
	pid = (pid_t)id;
	if (!bpf_map_lookup_elem(&target_processes, &tgid)) {
		task = (struct task_struct *)bpf_get_current_task();
		ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
		if (!bpf_map_lookup_elem(&target_processes, &ppid))
			return 0;
	}

	event = bpf_map_lookup_elem(&target_processes, &pid);
	if (!event) {
		if (bpf_map_update_elem(&target_processes, &pid, &empty_event, BPF_NOEXIST))
			return 0;
		event = bpf_map_lookup_elem(&target_processes, &pid);
		if (!event)
			return 0;
		event->pid = pid;
	}

	event->pte_event.vaddr = address;
	event->pte_event.vaddr2 = 0;
	event->pte_event.flags = flags;
	event->pte_event.delta = bpf_ktime_get_ns();

	#ifdef VMRSS_DEBUG
	task = (struct task_struct *)bpf_get_current_task();
	struct mm_rss_stat mm_rss_stat = BPF_CORE_READ(task, mm, rss_stat);
	event->pte_event.count[0] = *(__u64 *)&mm_rss_stat.count[0];
	event->pte_event.count[1] = *(__u64 *)&mm_rss_stat.count[1];
	struct task_rss_stat task_rss_stat = BPF_CORE_READ(task, rss_stat);
	event->pte_event.count[2] = task_rss_stat.count[0];
	event->pte_event.count[3] = task_rss_stat.count[1];
	#endif

	#ifdef ENABLE_CALLSTACK
	__u32 kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
	event->pte_event.stack_id = kern_stack_id;
	#endif

	#ifdef ENABLE_TIMESTATMP
	event->pte_event.ts = bpf_ktime_get_ns() - start_ts;
	#endif

	return 0;
}

SEC("kretprobe/handle_mm_fault")
int BPF_KRETPROBE(handle_mm_fault_exit, long ret) {
	u64 id;
	pid_t pid;
	struct event *event;

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;

	event = bpf_map_lookup_elem(&target_processes, &pid);
	if (!event)
		return 0;

	event->pte_event.delta = bpf_ktime_get_ns() - event->pte_event.delta;
	event->pte_event.major = (ret & VM_FAULT_MAJOR) ? 1 : 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

	return 0;
}

#else /* !HOOK_HANDLE_MM_FAULT */

#ifdef HOOK_SET_PTE_RANGE
SEC("kprobe/set_pte_range")
int BPF_KPROBE(set_pte_range_entry, struct vm_fault *vmf, struct folio *folio, struct page *page, unsigned int nr, unsigned long addr) {
	u64 id;
	pid_t pid, tgid, ppid;
	struct event *event;
	struct task_struct *task;

	id = bpf_get_current_pid_tgid();
	tgid = id >> 32;
	pid = (pid_t)id;
	if (!bpf_map_lookup_elem(&target_processes, &tgid)) {
		task = (struct task_struct *)bpf_get_current_task();
		ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
		if (!bpf_map_lookup_elem(&target_processes, &ppid))
			return 0;
	}

	event = bpf_map_lookup_elem(&target_processes, &pid);
	if (!event) {
		if (bpf_map_update_elem(&target_processes, &pid, &empty_event, BPF_NOEXIST))
			return 0;
		event = bpf_map_lookup_elem(&target_processes, &pid);
		if (!event)
			return 0;
		event->pid = pid;
	}

	event->pte_event.flags = BPF_CORE_READ(vmf, flags);
	#if 0
	if (event->pte_event.flags & (FAULT_FLAG_WRITE | FAULT_FLAG_MKWRITE))
		return 0;
	#endif
	event->pte_event.vaddr = addr;
	event->pte_event.vaddr2 = 0;

	#ifdef VMRSS_DEBUG
	task = (struct task_struct *)bpf_get_current_task();
	struct mm_rss_stat mm_rss_stat = BPF_CORE_READ(task, mm, rss_stat);
	event->pte_event.count[0] = *(__u64 *)&mm_rss_stat.count[0];
	event->pte_event.count[1] = *(__u64 *)&mm_rss_stat.count[1];
	struct task_rss_stat task_rss_stat = BPF_CORE_READ(task, rss_stat);
	event->pte_event.count[2] = task_rss_stat.count[0];
	event->pte_event.count[3] = task_rss_stat.count[1];
	#endif

	#ifdef ENABLE_CALLSTACK
	__u32 kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
	event->pte_event.stack_id = kern_stack_id;
	#endif

	#ifdef ENABLE_TIMESTATMP
	event->pte_event.ts = bpf_ktime_get_ns() - start_ts;
	#endif

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

	return 0;
}
#else /* !HOOK_SET_PTE_RANGE */
SEC("kprobe/do_set_pte")
int BPF_KPROBE(do_set_pte_entry, struct vm_fault *vmf, struct page *page, unsigned long addr) {
	u64 id;
	pid_t pid, tgid, ppid;
	struct event *event;
	struct task_struct *task;

	id = bpf_get_current_pid_tgid();
	tgid = id >> 32;
	pid = (pid_t)id;
	if (!bpf_map_lookup_elem(&target_processes, &tgid)) {
		task = (struct task_struct *)bpf_get_current_task();
		ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
		if (!bpf_map_lookup_elem(&target_processes, &ppid))
			return 0;
	}

	event = bpf_map_lookup_elem(&target_processes, &pid);
	if (!event) {
		if (bpf_map_update_elem(&target_processes, &pid, &empty_event, BPF_NOEXIST))
			return 0;
		event = bpf_map_lookup_elem(&target_processes, &pid);
		if (!event)
			return 0;
		event->pid = pid;
	}

	event->pte_event.flags = BPF_CORE_READ(vmf, flags);
	#if 0
	if (event->pte_event.flags & (FAULT_FLAG_WRITE | FAULT_FLAG_MKWRITE))
		return 0;
	#endif
	event->pte_event.vaddr = addr;
	event->pte_event.vaddr2 = 0;

	#ifdef VMRSS_DEBUG
	task = (struct task_struct *)bpf_get_current_task();
	struct mm_rss_stat mm_rss_stat = BPF_CORE_READ(task, mm, rss_stat);
	event->pte_event.count[0] = *(__u64 *)&mm_rss_stat.count[0];
	event->pte_event.count[1] = *(__u64 *)&mm_rss_stat.count[1];
	struct task_rss_stat task_rss_stat = BPF_CORE_READ(task, rss_stat);
	event->pte_event.count[2] = task_rss_stat.count[0];
	event->pte_event.count[3] = task_rss_stat.count[1];
	#endif

	#ifdef ENABLE_CALLSTACK
	__u32 kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
	event->pte_event.stack_id = kern_stack_id;
	#endif

	#ifdef ENABLE_TIMESTATMP
	event->pte_event.ts = bpf_ktime_get_ns() - start_ts;
	#endif

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

	return 0;
}
#endif /* !HOOK_SET_PTE_RANGE */

SEC("kprobe/do_anonymous_page")
int BPF_KPROBE(do_anonymous_page_entry, struct vm_fault *vmf) {
	u64 id;
	pid_t pid, tgid, ppid;
	struct event *event;
	struct task_struct *task;

	id = bpf_get_current_pid_tgid();
	tgid = id >> 32;
	pid = (pid_t)id;
	if (!bpf_map_lookup_elem(&target_processes, &tgid)) {
		task = (struct task_struct *)bpf_get_current_task();
		ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
		if (!bpf_map_lookup_elem(&target_processes, &ppid))
			return 0;
	}

	event = bpf_map_lookup_elem(&target_processes, &pid);
	if (!event) {
		if (bpf_map_update_elem(&target_processes, &pid, &empty_event, BPF_NOEXIST))
			return 0;
		event = bpf_map_lookup_elem(&target_processes, &pid);
		if (!event)
			return 0;
		event->pid = pid;
	}

	event->pte_event.vaddr = BPF_CORE_READ(vmf, address);
	event->pte_event.vaddr2 = 0;
	event->pte_event.flags = BPF_CORE_READ(vmf, flags);

	#ifdef VMRSS_DEBUG
	task = (struct task_struct *)bpf_get_current_task();
	struct mm_rss_stat mm_rss_stat = BPF_CORE_READ(task, mm, rss_stat);
	event->pte_event.count[0] = *(__u64 *)&mm_rss_stat.count[0];
	event->pte_event.count[1] = *(__u64 *)&mm_rss_stat.count[1];
	struct task_rss_stat task_rss_stat = BPF_CORE_READ(task, rss_stat);
	event->pte_event.count[2] = task_rss_stat.count[0];
	event->pte_event.count[3] = task_rss_stat.count[1];
	#endif

	#ifdef ENABLE_CALLSTACK
	__u32 kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
	event->pte_event.stack_id = kern_stack_id;
	#endif

	#ifdef ENABLE_TIMESTATMP
	event->pte_event.ts = bpf_ktime_get_ns() - start_ts;
	#endif
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

	return 0;
}

#endif /* !HOOK_HANDLE_MM_FAULT */

SEC("kprobe/try_to_unmap_one")
int BPF_KPROBE(try_to_unmap_one_entry, struct folio *folio, struct vm_area_struct *vma, unsigned long address, void *arg)
{
	u64 id;
	pid_t pid;
	struct mm_struct *mm = BPF_CORE_READ(vma, vm_mm);
	struct event *event_mm = bpf_map_lookup_elem(&target_mms, &mm);

	if (!event_mm)
		return 0;

	event_mm->pte_event.vaddr = address;
	event_mm->pte_event.vaddr2 = 0;
	event_mm->pte_event.flags = UNMAP_FLAG;
	#ifdef ENABLE_TIMESTATMP
	event_mm->pte_event.ts = bpf_ktime_get_ns() - start_ts;
	#endif

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;

	if (bpf_map_update_elem(&unmap_pid, &pid, &mm, BPF_NOEXIST))
		return 0;

	return 0;
}

SEC("kretprobe/try_to_unmap_one")
int BPF_KRETPROBE(try_to_unmap_one_exit, long ret)
{
	u64 id;
	pid_t pid;
	struct mm_struct *mm, **mmp;
	struct event *event_mm;
	static int first_unmap_occurred;

	if (!first_unmap_occurred) {
		first_unmap_occurred = 1;
		struct event event = empty_event;
		event.pte_event.flags = FIRST_UNMAP_FLAG;
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	}

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;

	mmp = bpf_map_lookup_elem(&unmap_pid, &pid);
	if (!mmp)
		return 0;
	mm = *mmp;
	bpf_map_delete_elem(&unmap_pid, &pid);

	if (!ret)
		return 0;

	event_mm = bpf_map_lookup_elem(&target_mms, &mm);
	if (!event_mm)
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event_mm, sizeof(*event_mm));

	return 0;
}

SEC("kprobe/zap_pte_range")
int BPF_KPROBE(zap_pte_range_entry, struct mmu_gather *tlb,
			   struct vm_area_struct *vma, pmd_t *pmd,
			   unsigned long addr, unsigned long end,
			   struct zap_details *details)
{
	u64 id;
	pid_t pid;
	struct event *event;

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	event = bpf_map_lookup_elem(&target_processes, &pid);
	if (!event)
		return 0;

	event->pte_event.vaddr = addr;
	event->pte_event.vaddr2 = end;
	event->pte_event.flags = ZAP_FLAG;
	#ifdef ENABLE_TIMESTATMP
	event->pte_event.ts = bpf_ktime_get_ns() - start_ts;
	#endif
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
