#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 256

struct user_pt_regs {
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

/* 
DISABLED: Hooking sys_openat causes Fatal Kernel Panics on CRDroid due to high frequency event lock contention.
SEC("kprobe/__arm64_sys_openat")
int bpf_prog1(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct user_pt_regs *real_regs = (struct user_pt_regs *)PT_REGS_PARM1(ctx);
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (data.uid < 10000) {
        return 0;
    }
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    char *fname_ptr;
    bpf_probe_read_user(&fname_ptr, sizeof(fname_ptr), &real_regs->regs[1]);
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), fname_ptr);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}
*/

struct sockaddr_in_v4 {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
};

SEC("kprobe/__arm64_sys_connect")
int bpf_prog_connect(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct user_pt_regs *real_regs = (struct user_pt_regs *)PT_REGS_PARM1(ctx);
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (data.uid < 10000) return 0;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    struct sockaddr_in_v4 *uservaddr;
    bpf_probe_read_user(&uservaddr, sizeof(uservaddr), &real_regs->regs[1]);
    
    struct sockaddr_in_v4 addr;
    bpf_probe_read_user(&addr, sizeof(addr), uservaddr);
    
    if (addr.sin_family == 2) { // AF_INET
        unsigned int ip = addr.sin_addr;
        unsigned short port = ((addr.sin_port & 0xFF) << 8) | ((addr.sin_port >> 8) & 0xFF);
        
        // Encode IP and Port in fname payload
        data.fname[0] = 'I'; data.fname[1] = 'P'; data.fname[2] = ':';
        data.fname[3] = ip & 0xFF;
        data.fname[4] = (ip >> 8) & 0xFF;
        data.fname[5] = (ip >> 16) & 0xFF;
        data.fname[6] = (ip >> 24) & 0xFF;
        data.fname[7] = port >> 8;
        data.fname[8] = port & 0xFF;
        data.fname[9] = 0;
        
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }
    return 0;
}

SEC("kprobe/__arm64_sys_execve")
int bpf_prog_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct user_pt_regs *real_regs = (struct user_pt_regs *)PT_REGS_PARM1(ctx);
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (data.uid < 10000) return 0;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // In sys_execve, regs[0] is the pointer to the filename string
    char *fname_ptr;
    bpf_probe_read_user(&fname_ptr, sizeof(fname_ptr), &real_regs->regs[0]);
    
    // Prefix with EXEC: so the Go relay knows it's an execution event
    data.fname[0] = 'E'; data.fname[1] = 'X'; data.fname[2] = 'E'; data.fname[3] = 'C'; data.fname[4] = ':';
    bpf_probe_read_user_str(&data.fname[5], sizeof(data.fname) - 5, fname_ptr);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char _license[] SEC("license") = "GPL";
