#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 256

struct pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};

struct data_t {
    __u32 pid;
    __u32 uid;
    char comm[16];
    char fname[MAX_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("kprobe/__arm64_sys_openat")
int bpf_prog1(struct pt_regs *ctx)
{
    struct data_t data = {};
    
    // On arm64, PT_REGS_PARM1 is the original pt_regs pointer for syscall wrappers.
    struct pt_regs *real_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    
    char *fname_ptr;
    // Read the second argument (x1) from the original syscall regs, which contains the filename
    bpf_probe_read(&fname_ptr, sizeof(fname_ptr), &real_regs->regs[1]);
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    bpf_probe_read_str(&data.fname, sizeof(data.fname), fname_ptr);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    
    return 0;
}

char _license[] SEC("license") = "GPL";
