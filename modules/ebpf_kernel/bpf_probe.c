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

SEC("kprobe/__arm64_sys_openat")
int bpf_prog1(struct pt_regs *ctx)
{
    struct data_t data = {};
    
    // On arm64, PT_REGS_PARM1 is the original pt_regs pointer for syscall wrappers.
    struct user_pt_regs *real_regs = (struct user_pt_regs *)PT_REGS_PARM1(ctx);
    
    char *fname_ptr;
    // Read the second argument (x1) from the original syscall regs, which contains the filename
    bpf_probe_read(&fname_ptr, sizeof(fname_ptr), &real_regs->regs[1]);
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // Drop Android system framework noise (UIDs under 10000)
    if (data.uid < 10000) {
        return 0;
    }

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    bpf_probe_read_str(&data.fname, sizeof(data.fname), fname_ptr);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    
    return 0;
}

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
    bpf_probe_read(&uservaddr, sizeof(uservaddr), &real_regs->regs[1]);
    
    struct sockaddr_in_v4 addr;
    bpf_probe_read(&addr, sizeof(addr), uservaddr);
    
    if (addr.sin_family == 2) { // AF_INET
        unsigned char *ip = (unsigned char *)&addr.sin_addr;
        unsigned short port = ((addr.sin_port & 0xFF) << 8) | ((addr.sin_port >> 8) & 0xFF);
        
        // Encode IP and Port in fname payload
        data.fname[0] = 'I'; data.fname[1] = 'P'; data.fname[2] = ':';
        data.fname[3] = ip[0];
        data.fname[4] = ip[1];
        data.fname[5] = ip[2];
        data.fname[6] = ip[3];
        data.fname[7] = port >> 8;
        data.fname[8] = port & 0xFF;
        data.fname[9] = 0;
        
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
