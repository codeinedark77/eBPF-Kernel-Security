#include <linux/bpf.h>
#include <stdint.h>

/* eBPF helper macros */
#define SEC(NAME) __attribute__((section(NAME), used))

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *) BPF_FUNC_trace_printk;

/* 
 * This struct represents the arguments for the sys_enter_execve tracepoint.
 */
struct trace_event_raw_sys_enter_execve {
    uint64_t unused;
    int syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog_execve(struct trace_event_raw_sys_enter_execve *ctx)
{
    char fmt[] = "Process exec triggered\n";
    bpf_trace_printk(fmt, sizeof(fmt));
    return 0;
}

char _license[] SEC("license") = "GPL";
