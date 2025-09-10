// Based on execsnoop(8) from BCC by Brendan Gregg and others.
//
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "aw_physmem.h"
#include "aw_physmem.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_POLL_TIMEOUT_MS	1

//#define PRINT_UNMAP_EVENT
#define PRINT_AT_FIRST_UNMAP

#ifdef GEN_RAW_BINARY
#define PERF_BUFFER_PAGES   64*16
#define ALIGNMENT 4096
static int wfd;
static const int num_e_page = ALIGNMENT / sizeof(struct event);
static volatile int e_idx;
static struct event *e_buffer;
#else
#define PERF_BUFFER_PAGES   64*1024
#endif

static volatile sig_atomic_t exiting = 0;
static volatile sig_atomic_t insert_marker = 0;

static struct timespec start_time;

const char *argp_program_version = "aw_physmem 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";

static void sig_int(int signo)
{
	exiting = 1;
}

static void sig_usr1(int signo)
{
	insert_marker = 1;
}

static void inline quoted_symbol(char c) {
	switch(c) {
		case '"':
			putchar('\\');
			putchar('"');
			break;
		case '\t':
			putchar('\\');
			putchar('t');
			break;
		case '\n':
			putchar('\\');
			putchar('n');
			break;
		default:
			putchar(c);
			break;
	}
}

#ifdef ENABLE_CALLSTACK
struct fmt_t {
	bool folded;
	char *prefix;
	char *suffix;
	char *delim;
};

static int stack_map_fd;
struct fmt_t stacktrace_formats[] = {
	{ false, "    ", "\n", "--" },	/* multi-line */
	{ true, ";", "", "-" }		/* folded */
};
#define SYM_INFO_LEN			2048
#define STACK_DEPTH  30
struct ksyms *ksyms;
static char syminfo[SYM_INFO_LEN];
typedef const char* (*symname_fn_t)(unsigned long);

#define pr_format(str, fmt)		printf("%s%s%s", fmt->prefix, str, fmt->suffix)

static const char *ksymname(unsigned long addr)
{
	const struct ksym *ksym = ksyms__map_addr(ksyms, addr);
	if (ksym)
		snprintf(syminfo, SYM_INFO_LEN, "0x%lx %s+0x%lx", addr,
			 ksym->name, addr - ksym->addr);
	else
		snprintf(syminfo, SYM_INFO_LEN, "0x%lx [unknown]", addr);

	return syminfo;
}

static void print_stacktrace(unsigned long *ip, symname_fn_t symname, struct fmt_t *f)
{
	int i;

	if (!f->folded) {
		for (i = 0; ip[i] && i < STACK_DEPTH; i++)
			pr_format(symname(ip[i]), f);
		return;
	} else {
		for (i = STACK_DEPTH - 1; i >= 0; i--) {
			if (!ip[i])
				continue;

			pr_format(symname(ip[i]), f);
		}
	}
}

static bool print_kern_stacktrace(__u32 kern_stack_id, int stack_map, unsigned long *ip, struct fmt_t *f)
{
	if (bpf_map_lookup_elem(stack_map, &kern_stack_id, ip) != 0)
		pr_format("[Missed Kernel Stack]", f);
	else {
		print_stacktrace(ip, ksymname, f);
	}

	return true;
}
#endif

#ifdef GEN_RAW_BINARY
static void insert_marker_bin(void)
{
	struct event empty_event;

	memset(&empty_event, 0, sizeof(empty_event));
	empty_event.pte_event.flags = MARKER;
	e_buffer[e_idx++] = empty_event;
	if (e_idx == num_e_page) {
		e_idx = 0;
		int rc = write(wfd, e_buffer, ALIGNMENT);
		if (rc < 0)
			fprintf(stderr, "write failed\n");
	}
	insert_marker = 0;
	printf("marker inserted\n");
}
#endif /* GEN_RAW_BINARY */

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;

	#ifdef GEN_RAW_BINARY
	if (insert_marker)
		insert_marker_bin();

	#ifdef PRINT_UNMAP_EVENT
	if (e->pte_event.flags & UNMAP_FLAG)
		printf("UNMAP: pid=%d, addr=0x%08llx\n", e->pid, e->pte_event.vaddr);
	#endif
	#ifdef PRINT_AT_FIRST_UNMAP
	static int unmap_cnt, autoware_unmap_cnt;
	if (e->pte_event.flags & FIRST_UNMAP_FLAG && !unmap_cnt) {
		unmap_cnt++;
		//insert_marker_bin();
		printf("first unmap\n");
	}
	if (e->pte_event.flags & UNMAP_FLAG && !autoware_unmap_cnt) {
		autoware_unmap_cnt++;
		//insert_marker_bin();
		printf("autoware first unmap\n");
	}
	#endif

	e_buffer[e_idx++] = *e;
	if (e_idx == num_e_page) {
		e_idx = 0;
		int rc = write(wfd, e_buffer, ALIGNMENT);
		if (rc < 0)
			fprintf(stderr, "write failed\n");
	}

	#else /* !GEN_RAW_BINARY */

	#ifdef HOOK_HANDLE_MM_FAULT
	#ifdef ENABLE_TIMESTATMP
	printf("%-6d 0x%-6llx 0x%-6llx 0x%-3x %-3llu %-3llu %-3u\n", e->pid,  e->pte_event.vaddr, e->pte_event.vaddr2, e->pte_event.flags, e->pte_event.ts, e->pte_event.delta, e->pte_event.major);
	#else
	printf("%-6d 0x%-6llx 0x%-6llx 0x%-3x %-3llu %-3u\n", e->pid,  e->pte_event.vaddr, e->pte_event.vaddr2, e->pte_event.flags, e->pte_event.delta, e->pte_event.major);
	#endif

	#else /* !HOOK_HANDLE_MM_FAULT */

	#ifdef VMRSS_DEBUG
	#ifdef ENABLE_TIMESTATMP
	printf("%-6d 0x%-6llx 0x%-6llx 0x%-3x %-6lld %-6lld %-6lld %-6lld %-3llu\n", e->pid, e->pte_event.vaddr, e->pte_event.vaddr2, e->pte_event.flags, e->pte_event.count[0], e->pte_event.count[1], e->pte_event.count[2], e->pte_event.count[3], e->pte_event.ts);
	#else /* !ENABLE_TIMESTATMP */
	printf("%-6d 0x%-6llx 0x%-6llx 0x%-3x %-6lld %-6lld %-6lld %-6lld\n", e->pid,  e->pte_event.vaddr, e->pte_event.vaddr2, e->pte_event.flags, e->pte_event.count[0], e->pte_event.count[1], e->pte_event.count[2], e->pte_event.count[3]);
	#endif /* !ENABLE_TIMESTATMP */

	#else /* !VMRSS_DEBUG */

	#ifdef ENABLE_TIMESTATMP
	printf("%-6d 0x%-6llx 0x%-6llx 0x%-3x %-3llu\n", e->pid, e->pte_event.vaddr, e->pte_event.vaddr2,  e->pte_event.flags, e->pte_event.ts);
	#else /* !ENABLE_TIMESTATMP */
	printf("%-6d 0x%-6llx 0x%-6llx 0x%-3x\n", e->pid, e->pte_event.vaddr, e->pte_event.vaddr2, e->pte_event.flags);
	#endif /* !ENABLE_TIMESTATMP */
	#endif /* !VMRSS_DEBUG */

	#endif /* !HOOK_HANDLE_MM_FAULT */

	#ifdef ENABLE_CALLSTACK
	if (e->pte_event.stack_id) {
		unsigned long *ip = (unsigned long *)malloc(STACK_DEPTH * sizeof(unsigned long));
		printf(" stack_id = %d\n", e->pte_event.stack_id);
		print_kern_stacktrace(e->pte_event.stack_id, stack_map_fd, ip, &stacktrace_formats[0]);
		free(ip);
	}
	#endif

	#endif /* !GEN_RAW_BINARY */


	fflush(stdout);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct perf_buffer *pb = NULL;
	struct aw_physmem_bpf *obj;
	int err;
	int cgfd = -1;

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = aw_physmem_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	err = aw_physmem_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	clock_gettime(CLOCK_MONOTONIC, &start_time);
	err = aw_physmem_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	#ifdef GEN_RAW_BINARY
	char *outfile;
	if (argc == 2)
		outfile = argv[1];
	else
		outfile = "out.bin";
    wfd = open(outfile, O_CREAT | O_TRUNC | O_WRONLY | __O_DIRECT, 0644);
	if (wfd < 0) {
		fprintf(stderr, "could not open %s\n", outfile);
		goto cleanup;
	}
	if (posix_memalign((void *)&e_buffer, ALIGNMENT, ALIGNMENT) != 0) {
        perror("posix_memalign failed");
        goto cleanup;
    }
	#endif

	/* setup event callbacks */
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	#ifdef ENABLE_CALLSTACK
	stack_map_fd = bpf_map__fd(obj->maps.stack_traces);
	ksyms = ksyms__load();
	#endif

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (signal(SIGUSR1, sig_usr1) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler of SIGUSR1: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	//printf("sizeof(event) = %ld\n", sizeof(struct event));

	/* main: poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

	#ifdef GEN_RAW_BINARY
	struct event empty_event;
	if (insert_marker)
		insert_marker_bin();
	memset(&empty_event, 0, sizeof(empty_event));
	empty_event.pte_event.flags = END;
	e_buffer[e_idx] = empty_event;
	int rc = write(wfd, e_buffer, ALIGNMENT);
	if (rc < 0)
		fprintf(stderr, "write failed\n");
	printf("e_idx = %d\n", e_idx);
	close(wfd);
	#endif

cleanup:
	perf_buffer__free(pb);
	aw_physmem_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
