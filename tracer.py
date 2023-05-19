#!/usr/bin/sudo python3
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import argparse, os, json
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
from collections import defaultdict

# arguments
examples = """examples:
    ./tracer.py -a           # trace everything
    ./tracer.py -a -p 181    # only trace PID 181
    ./tracer.py -T -P 80     # only trace dport 80
    ./tracer.py -a -P 80,81  # only trace dport 80 and 81
    ./tracer.py -a -u 1000   # only trace UID 1000
"""
parser = argparse.ArgumentParser(
    description="Trace Network Traffic, Process activities (fork, clone, exec, exit), and File activities",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
group = parser.add_argument_group("modes")
group.add_argument("-T", "--traffic", action="store_true",
                   help="Trace Network Traffic")
group.add_argument("-f", "--fork", action="store_true",
                   help="Trace Fork related activities")
group.add_argument("-F", "--file", action="store_true",
                   help="Trace File activities")
group.add_argument("-a", "--all", action="store_true",
                   help="Trace everything")
parser.add_argument("-p", "--pid",
                    help="trace this PID only")
parser.add_argument("-P", "--port",
                    help="comma-separated list of destination ports to trace.")
parser.add_argument("-u", "--uid",
                    help="trace this UID only")
parser.add_argument("--max-args", default="20",
                    help="maximum number of arguments parsed and displayed (used in execve), default is 20")
parser.add_argument("--max-path", default="10",
                    help="maximum path-depht to be returned from (used in read/write files, close, unlink and rename), default is 10")
parser.add_argument("--all-files", action="store_true",
                    help="trace all file types in file activity traces not just regular files, please only use this when redirecting the output to a file (always redirect stdout and stderr)")
parser.add_argument("-j", "--json", action="store_true",
                    help="prints output as json strings")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()
if not args.traffic and not args.fork and not args.file and not args.all and not args.ebpf:
    parser.print_help()
    exit()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define ARGSIZE 128
"""

if args.all or args.traffic:
    bpf_text = bpf_text + """
BPF_HASH(currsock, u32, struct sock *);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 tid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 ip;
    u16 proto;
    u16 sport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    u32 tid;
    u32 uid;
    u32 saddr[4];
    u32 daddr[4];
    u16 ip;
    u16 proto;
    u16 sport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

// inspired by bcc/tools/tcpconnect.py
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID

    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID

    // stash the sock ptr for lookup on return
    currsock.update(&tid, &sk);

    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short proto)
    //proto: 0 is tcp send packet, 1 is udp send packet, 2 is tcp connect, 3 is tcp disconnect,
    //4 is tcp receive packet, 5 is udp receive packet, 6 is tcp connection accept
{
    int ret = PT_REGS_RC(ctx);  //gets the returnvalue of the function
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u32 family;
    short ipver;
    
    struct sock **skpp;
    skpp = currsock.lookup(&tid);
    if (skpp == 0) {
        return 0;   // missed entry
    }

    if (ret != 0 && proto == 2 ) {   // syn packets only occure in tcp_connect phase
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&tid);
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u16 dport = skp->__sk_common.skc_dport;

    FILTER_PORT
    
    family = skp->__sk_common.skc_family;
    if(family == AF_INET){              //get ipversion
        ipver = 4;
    }else if(family == AF_INET6){
        ipver = 6;
    }else{                  //other address family is used, dont want to track this
        currsock.delete(&tid);
        return 0;
    }
    
    if (ipver == 4) {
        struct ipv4_data_t data4 = {.pid = pid, .tid = tid, .ip = ipver, .proto = proto};
        data4.uid = bpf_get_current_uid_gid();
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.saddr = skp->__sk_common.skc_rcv_saddr;
        data4.daddr = skp->__sk_common.skc_daddr;
        data4.dport = ntohs(dport);
        data4.sport = skp->__sk_common.skc_num;
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else /* 6 */ {
        struct ipv6_data_t data6 = {.pid = pid, .tid = tid, .ip = ipver, .proto = proto};
        data6.uid = bpf_get_current_uid_gid();
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.dport = ntohs(dport);
        data6.sport = skp->__sk_common.skc_num;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    currsock.delete(&tid);

    return 0;
}


int trace_tcp_send_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 0);
}

int trace_udp_send_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 1);
}

int trace_connect_tcp_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 2);
}

int trace_disconnect_tcp_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 3);
}

int trace_tcp_rcv_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 4);
}

int trace_udp_rcv_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 5);
}

int trace_con_ack_tcp_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 6);
}

int trace_tcp_sendpage_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 7);
}

int trace_udp_sendpage_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 8);
}
"""

if args.all or args.fork:
    bpf_text = bpf_text + """
struct fork_data_t {
    u64 ts_us;
    u32 parent_pid;
    u32 parent_tid;
    u32 uid;
    long child_pid;
    u16 mode;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(fork_events);

struct process_exit_args {
    // from /sys/kernel/debug/tracing/events/sched/sched_process_exit/format
    u64 __unused_;
    char comm[16];
    pid_t pid;
    int prio;
};

struct process_exit_data {
    u64 start_time;
    u64 exit_time;
    u32 pid;
    u32 tid;
    u32 uid;
    int exit_code;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(process_exit_events);

enum process_exec_event_type {
    EVENT_ARG,
    EVENT_RET,
};
struct process_exec_data {
    u32 pid;
    u64 ts_us;
    u32 tid;
    u32 uid;
    char task[TASK_COMM_LEN];
    enum process_exec_event_type type;
    char argv[ARGSIZE];
    int retval;
};
BPF_PERF_OUTPUT(process_execute_events);

//inspired by bcc/tools/execsnoop.py
static int __submit_arg(struct pt_regs *ctx, void *ptr, struct process_exec_data *data)
{
    bpf_probe_read_str(data->argv, sizeof(data->argv), ptr);
    process_execute_events.perf_submit(ctx, data, sizeof(struct process_exec_data));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct process_exec_data *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall__trace_execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID
    
    // create data here and pass to submit_arg to save stack space (#555)
    struct process_exec_data data = {.pid = pid};

    data.type = EVENT_ARG;


    __submit_arg(ctx, (char *)filename, &data);
    
    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
    
    out:
    return 0;
}

int trace_execve_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID
    
    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID
    
    struct process_exec_data data = {.pid = pid, .tid = tid, .uid = uid};
    
    data.ts_us = bpf_ktime_get_ns() / 1000;
    bpf_get_current_comm(&data.task, sizeof(data.task));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    process_execute_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

static int trace_fork(struct pt_regs *ctx, short mode)
{
    long ret = PT_REGS_RC(ctx);  //gets the returnvalue of the function
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID
    
    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID
    
    struct fork_data_t data = {.parent_pid = pid, .parent_tid = tid, .uid = uid, .mode = mode};
    data.ts_us = bpf_ktime_get_ns() / 1000;
    bpf_get_current_comm(&data.task, sizeof(data.task)); 
    data.child_pid = ret;
    fork_events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}

int trace_fork_return(struct pt_regs *ctx)
{
    return trace_fork(ctx, 0);
}
int trace_vfork_return(struct pt_regs *ctx)
{
    return trace_fork(ctx, 1);
}
int trace_clone_return(struct pt_regs *ctx)
{
    return trace_fork(ctx, 2);
}

// inspired by bcc/tools/exitsnoop.py
int trace_process_exit_tracepoint(struct process_exit_args *args)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID

    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID

    struct task_struct *task = (typeof(task))bpf_get_current_task();
    
    struct process_exit_data data = {.pid = pid, .tid = tid, .uid = uid};
    data.exit_time = bpf_ktime_get_ns() / 1000;
    bpf_get_current_comm(&data.task, sizeof(data.task));
    data.start_time = task->start_time / 1000;
    data.exit_code = task->exit_code >> 8;
    
    process_exit_events.perf_submit(args, &data, sizeof(data));
    
    return 0;
}
"""

if args.all or args.file:
    bpf_text = bpf_text + """
enum file_rw_event_type {
    FILE_R,
    FILE_W,
    PASS_PATH_RW,
};

struct file_rw_data {
    u64 ts_us;
    u32 pid;
    u32 tid;
    u32 uid;
    u32 name_len; //lenght of the filename
    char task[TASK_COMM_LEN]; //name of the process
    // de->d_name.name may point to de->d_iname so limit len accordingly
    char name[NAME_MAX]; //name of the file
    enum file_rw_event_type event;  //read or write
    u64 count; //amount of bytes read or written
    int mode; //inode mode of the file
};
BPF_PERF_OUTPUT(file_rw_events);

struct file_open_data {
    u64 ts_us;
    u32 pid;
    u32 tid;
    u32 uid;
    char task[TASK_COMM_LEN];
    char name[NAME_MAX];
    int flags;
    unsigned short mode;
};
BPF_PERF_OUTPUT(file_open_events);

enum file_close_event_type {
    CLOSE,
    PASS_PATH_CLOSE,
};

struct file_close_data {
    u64 ts_us;
    u32 pid;
    u32 tid;
    u32 uid;
    char task[TASK_COMM_LEN];
    char name[NAME_MAX];
    enum file_close_event_type event;
    int mode;
};
BPF_PERF_OUTPUT(file_close_events);

enum file_unlink_event_type {
    UNLINK,
    PASS_PATH_UNLINK,
};

struct file_unlink_data {
    u64 ts_us;
    u32 pid;
    u32 tid;
    u32 uid;
    char task[TASK_COMM_LEN];
    char name[NAME_MAX];
    enum file_unlink_event_type event;
    int mode;
};
BPF_PERF_OUTPUT(file_unlink_events);

enum file_rename_event_type {
    RENAME,
    PASS_OLD_PATH,
    PASS_NEW_PATH,
    PASS_NEW_NAME,
};

struct file_rename_data {
    u64 ts_us;
    u32 pid;
    u32 tid;
    u32 uid;
    char task[TASK_COMM_LEN];
    char old_name[NAME_MAX];
    enum file_rename_event_type event;
    unsigned int flags;
    int mode;
};
BPF_PERF_OUTPUT(file_rename_events);

static int submit_path_rename(struct pt_regs *ctx, struct dentry *parent, struct file_rename_data *data)
{
    struct qstr d_name = parent->d_name;
    bpf_probe_read_str(data->old_name, sizeof(data->old_name), d_name.name);
    if(data->old_name[0] == 47 || parent->d_parent == parent) //47 is the ascii number for /, with means this is the root directory, also if the parent points to itself it is the root directory
        return 0;
    else{
        file_rename_events.perf_submit(ctx, data, sizeof(struct file_rename_data));
        return 1;
    }
}


int trace_rename_entry(struct pt_regs *ctx, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, struct inode **delegated_inode, unsigned int flags)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID
    
    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID
    
    struct file_rename_data data = {.pid = pid, .tid = tid, .uid = uid};
    data.ts_us = bpf_ktime_get_ns() / 1000;
    
    //old_name is used to transmit all names, now the name of the new file is transmitted, this is done because else the function would overflow the 512 bytes stack limit
    struct qstr d_name = old_dentry->d_name;
    struct qstr new_d_name = new_dentry->d_name;
    data.mode = old_dentry->d_inode->i_mode;
    if (d_name.len == 0 || new_d_name.len == 0 || TYPE_FILTER)
        return 0;
    
    bpf_probe_read(&data.old_name, sizeof(data.old_name), new_d_name.name);
    data.event = PASS_NEW_NAME;
    file_rename_events.perf_submit(ctx, &data, sizeof(data));

        
    //get path of the old file and pass it over the eventstream before finishing
    struct dentry *parent = old_dentry->d_parent;
    data.event = PASS_OLD_PATH;
    #pragma unroll
    for (int i = 0; i < MAXPATH; i++) {
        if (submit_path_rename(ctx, parent, &data) == 0)
             goto old_file_out;
        parent = parent->d_parent;
    }
    old_file_out:
        
    //get path of the new file and pass it over the eventstream before finishing
    parent = new_dentry->d_parent;
    data.event = PASS_NEW_PATH;
    #pragma unroll
    for (int i = 0; i < MAXPATH; i++) {
        if (submit_path_rename(ctx, parent, &data) == 0)
             goto new_file_out;
        parent = parent->d_parent;
    }
    new_file_out:

    bpf_get_current_comm(&data.task, sizeof(data.task));
    bpf_probe_read(&data.old_name, sizeof(data.old_name), d_name.name);
    data.flags = flags;
    data.event = RENAME;
    
    file_rename_events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}

static int submit_path_unlink(struct pt_regs *ctx, struct dentry *parent, struct file_unlink_data *data)
{
    struct qstr d_name = parent->d_name;
    bpf_probe_read_str(data->name, sizeof(data->name), d_name.name);
    data->event = PASS_PATH_UNLINK;
    if(data->name[0] == 47 || parent->d_parent == parent) //47 is the ascii number for /, with means this is the root directory, also if the parent points to itself it is the root directory
        return 0;
    else{
        file_unlink_events.perf_submit(ctx, data, sizeof(struct file_unlink_data));
        return 1;
    }
}

int trace_unlink_entry(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID
    
    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID
    
    struct file_unlink_data data = {.pid = pid, .tid = tid, .uid = uid};
    data.ts_us = bpf_ktime_get_ns() / 1000;
    
    struct qstr d_name = dentry->d_name;
    data.mode = dentry->d_inode->i_mode;
    if (d_name.len == 0 || TYPE_FILTER)
        return 0;
        
    struct dentry *parent = dentry->d_parent;
    //get path of the file and pass it over the eventstream before finishing
    #pragma unroll
    for (int i = 0; i < MAXPATH; i++) {
        if (submit_path_unlink(ctx, parent, &data) == 0)
             goto file_out;
        parent = parent->d_parent;
    }
    file_out:
    
    bpf_get_current_comm(&data.task, sizeof(data.task));
    bpf_probe_read(&data.name, sizeof(data.name), d_name.name);
    data.event = UNLINK;
    
    file_unlink_events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}


static int submit_path_close(struct pt_regs *ctx, struct dentry *parent, struct file_close_data *data)
{
    struct qstr d_name = parent->d_name;
    bpf_probe_read_str(data->name, sizeof(data->name), d_name.name);
    data->event = PASS_PATH_CLOSE;
    if(data->name[0] == 47 || parent->d_parent == parent) //47 is the ascii number for /, with means this is the root directory, also if the parent points to itself it is the root directory
        return 0;
    else{
        file_close_events.perf_submit(ctx, data, sizeof(struct file_close_data));
        return 1;
    }
}

int trace_close_entry(struct pt_regs *ctx, struct file *filp)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID
    
    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID
    
    struct file_close_data data = {.pid = pid, .tid = tid, .uid = uid};
    data.ts_us = bpf_ktime_get_ns() / 1000;
    
    struct dentry *de = filp->f_path.dentry;
    struct qstr d_name = de->d_name;
    data.mode = filp->f_inode->i_mode;
    if (d_name.len == 0 || TYPE_FILTER)
        return 0;
        
    struct dentry *parent = de->d_parent;
    //get path of the file and pass it over the eventstream before finishing
    #pragma unroll
    for (int i = 0; i < MAXPATH; i++) {
        if (submit_path_close(ctx, parent, &data) == 0)
             goto file_out;
        parent = parent->d_parent;
    }
    file_out:
    
    
    bpf_get_current_comm(&data.task, sizeof(data.task));
    bpf_probe_read(&data.name, sizeof(data.name), d_name.name);
    data.event = CLOSE;
    
    file_close_events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}

// inspired by bcc/tools/opensnoop
int trace_open_entry(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode){
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID
    
    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID
    
    struct file_open_data data = {.pid = pid, .tid = tid, .uid = uid};
    data.ts_us = bpf_ktime_get_ns() / 1000;
    bpf_get_current_comm(&data.task, sizeof(data.task));
    bpf_probe_read_str(data.name, sizeof(data.name), filename);
    data.flags = flags;
    data.mode = mode;
    file_open_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

static int submit_path_rw(struct pt_regs *ctx, struct dentry *parent, struct file_rw_data *data)
{
    struct qstr d_name = parent->d_name;
    bpf_probe_read_str(data->name, sizeof(data->name), d_name.name);
    data->event = PASS_PATH_RW;
    if(data->name[0] == 47 || parent->d_parent == parent) //47 is the ascii number for /, with means this is the root directory, also if the parent points to itself it is the root directory
        return 0;
    else{
        file_rw_events.perf_submit(ctx, data, sizeof(struct file_rw_data));
        return 1;
    }
}

// inspired by bcc/tools/filetop
static int trace_rw_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, u64 count, enum file_rw_event_type is_read)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_OWN_PID  //else there is too much spam with --all-files mode
    FILTER_PID
    
    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID
    
    // skip I/O lacking a filename
    struct file_rw_data data = {.pid = pid, .tid = tid, .uid = uid};
    data.ts_us = bpf_ktime_get_ns() / 1000;
    
    
    struct dentry *de = file->f_path.dentry;
    struct qstr d_name = de->d_name;
    data.mode = file->f_inode->i_mode;
    if (d_name.len == 0 || TYPE_FILTER)
        return 0;
        
    struct dentry *parent = de->d_parent;
    //get path of the file and pass it over the eventstream before finishing
    #pragma unroll
    for (int i = 0; i < MAXPATH; i++) {
        if (submit_path_rw(ctx, parent, &data) == 0)
             goto file_out;
        parent = parent->d_parent;
    }
    file_out:
    
    
    bpf_get_current_comm(&data.task, sizeof(data.task));
    data.name_len = d_name.len;
    bpf_probe_read(&data.name, sizeof(data.name), d_name.name);
    data.count = count;
    data.event = is_read;
    
    file_rw_events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}

int trace_read_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    return trace_rw_entry(ctx, file, buf, count, FILE_R);
}
int trace_write_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    return trace_rw_entry(ctx, file, buf, count, FILE_W);
}
"""

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID',
                                'if (pid != %s) { return 0; }' % args.pid)
if args.port:
    dports = [int(dport) for dport in args.port.split(',')]
    dports_if = ' && '.join(['dport != %d' % ntohs(dport) for dport in dports])
    bpf_text = bpf_text.replace('FILTER_PORT',
                                'if (%s) { currsock.delete(&tid); return 0; }' % dports_if)
if args.uid:
    bpf_text = bpf_text.replace('FILTER_UID',
                                'if (uid != %s) { return 0; }' % args.uid)
if args.all_files:
    bpf_text = bpf_text.replace('TYPE_FILTER', '0')
else:
    bpf_text = bpf_text.replace('TYPE_FILTER', '!S_ISREG(data.mode)')

# exclude own pid (python) for spam prevention
bpf_text = bpf_text.replace('FILTER_OWN_PID', 'if (pid == %s) { return 0; }' % os.getpid())

bpf_text = bpf_text.replace('MAXARG', args.max_args)
bpf_text = bpf_text.replace('MAXPATH', args.max_path)

bpf_text = bpf_text.replace('FILTER_PID', '')
bpf_text = bpf_text.replace('FILTER_PORT', '')
bpf_text = bpf_text.replace('FILTER_UID', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()


class Process_exec_EventType(object):
    EVENT_ARG = 0
    EVENT_RET = 1


class File_rw_EventType(object):
    FILE_R = 0
    FILE_W = 1
    PASS_PATH = 2


class File_close_EventType(object):
    CLOSE = 0
    PASS_PATH = 1


class File_unlink_EventType(object):
    UNLINK = 0
    PASS_PATH = 1


class File_rename_EventType(object):
    RENAME = 0
    PASS_OLD_PATH = 1
    PASS_NEW_PATH = 2
    PASS_NEW_NAME = 3


# some global variables we use
start_ts = 0
execve_argv = defaultdict(list)
file_rw_path = defaultdict(list)
file_close_path = defaultdict(list)
file_unlink_path = defaultdict(list)
file_rename_old_path = defaultdict(list)
file_rename_new_path = defaultdict(list)
file_rename_new_name = str()


def decode_ip_proto(proto):
    names = ["TCP send Packet", "UDP send Packet", "TCP Connect", "TCP Disconnect", "TCP receive Packet",
             "UDP receive Packet", "TCP Accept Connection", "TCP send Page", "UDP send Page"]
    try:
        return names[proto]
    except:
        return "Unknown"


def decode_fork_mode(mode):
    names = ["Fork", "vFork", "clone"]

    try:
        return names[mode]
    except:
        return "Unknown"


def decode_rw_mode(mode):
    names = ["File Read", "File Write"]

    try:
        return names[mode]
    except:
        return "Unknown"


# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    global start_ts
    if start_ts == 0:
        start_ts = event.ts_us
    proto = decode_ip_proto(event.proto)
    if not args.json:
        printb(b"%-10.6f %-6d %-6d %-6d %-15.15s %-2d %-16s %-16s %-6d %-6d %s" % (
            ((float(event.ts_us) - start_ts) / 1000000), event.uid, event.pid, event.tid,
            event.task, event.ip,
            inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
            inet_ntop(AF_INET, pack("I", event.daddr)).encode(),
            event.sport, event.dport, proto.encode()))
    else:
        json_data = {
            "event": proto,
            "uid": event.uid,
            "pid": event.pid,
            "tid": event.tid,
            "time": '{:f}'.format((float(event.ts_us) - start_ts) / 1000000),
            "task": event.task.decode(),
            "data": {
                "ipver": event.ip,
                "saddr": inet_ntop(AF_INET, pack("I", event.saddr)),
                "daddr": inet_ntop(AF_INET, pack("I", event.daddr)),
                "sport": event.sport,
                "dport": event.dport
            }
        }
        print(json.dumps(json_data))


def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    global start_ts
    if start_ts == 0:
        start_ts = event.ts_us
    proto = decode_ip_proto(event.proto)
    if not args.json:
        printb(b"%-10.6f %-6d %-6d %-6d %-15.15s %-2d %-16s %-16s %-6d %-6d %s" % (
            ((float(event.ts_us) - start_ts) / 1000000), event.uid, event.pid, event.tid,
            event.task, event.ip,
            inet_ntop(AF_INET6, event.saddr).encode(),
            inet_ntop(AF_INET6, event.daddr).encode(),
            event.sport, event.dport, proto.encode()))
    else:
        json_data = {
            "event": proto,
            "uid": event.uid,
            "pid": event.pid,
            "tid": event.tid,
            "time": '{:f}'.format((float(event.ts_us) - start_ts) / 1000000),
            "task": event.task.decode(),
            "data": {
                "ipver": event.ip,
                "saddr": inet_ntop(AF_INET6, event.saddr),
                "daddr": inet_ntop(AF_INET6, event.daddr),
                "sport": event.sport,
                "dport": event.dport
            }
        }
        print(json.dumps(json_data))


def print_fork_event(cpu, data, size):
    event = b["fork_events"].event(data)
    global start_ts
    if start_ts == 0:
        start_ts = event.ts_us
    mode = decode_fork_mode(event.mode)
    if not args.json:
        printb(b"%-10.6f %-6d %-6d %-6d %-6d %-15.15s %s" % (
            ((float(event.ts_us) - start_ts) / 1000000), event.uid, event.parent_pid, event.parent_tid, event.child_pid,
            event.task, mode.encode()))
    else:
        json_data = {
            "event": mode,
            "uid": event.uid,
            "pid": event.parent_pid,
            "tid": event.parent_tid,
            "time": '{:f}'.format((float(event.ts_us) - start_ts) / 1000000),
            "task": event.task.decode(),
            "data": {
                "child_pid": event.child_pid,
            }
        }
        print(json.dumps(json_data))


def print_process_exit_event(cpu, data, size):
    event = b["process_exit_events"].event(data)
    global start_ts
    if start_ts == 0:
        start_ts = event.exit_time
    if not args.json:
        printb(b"%-10.6f %-6d %-6d %-6d %-15.6f %-6d %-15.15s %s" % (
            ((float(event.exit_time) - start_ts) / 1000000), event.uid, event.pid, event.tid,
            ((float(event.start_time) - start_ts) / 1000000), event.exit_code, event.task, "Process Exit".encode()))
    else:
        json_data = {
            "event": "Process Exit",
            "uid": event.uid,
            "pid": event.pid,
            "tid": event.tid,
            "time": '{:f}'.format((float(event.exit_time) - start_ts) / 1000000),
            "task": event.task.decode(),
            "data": {
                "start_time": '{:f}'.format((float(event.start_time) - start_ts) / 1000000),
                "exit_code": event.exit_code
            }
        }
        print(json.dumps(json_data))


def print_process_execute_event(cpu, data, size):
    event = b["process_execute_events"].event(data)

    if event.type == Process_exec_EventType.EVENT_ARG:
        execve_argv[event.pid].append(event.argv)

    elif event.type == Process_exec_EventType.EVENT_RET:
        global start_ts
        if start_ts == 0:
            start_ts = event.ts_us
        argv_text = b' '.join(execve_argv[event.pid]).replace(b'\n', b'\\n')
        if not args.json:
            printb(b"%-10.6f %-6d %-6d %-6d %-6d %-15.15s %s %s" % (
                ((float(event.ts_us) - start_ts) / 1000000), event.uid, event.pid, event.tid, event.retval, event.task,
                "Process Execute".encode(), argv_text))
        else:
            json_data = {
                "event": "Process Execute",
                "uid": event.uid,
                "pid": event.pid,
                "tid": event.tid,
                "time": '{:f}'.format((float(event.ts_us) - start_ts) / 1000000),
                "task": event.task.decode(),
                "data": {
                    "return_value": event.retval,
                    "name_and_arguments": argv_text.decode()
                }
            }
            print(json.dumps(json_data))
        try:
            del (execve_argv[event.pid])
        except Exception:
            pass


def print_file_rw_event(cpu, data, size):
    event = b["file_rw_events"].event(data)
    if event.event == File_rw_EventType.PASS_PATH:
        file_rw_path[event.pid].append(event.name)
    elif event.event == File_rw_EventType.FILE_R or File_rw_EventType.FILE_W:
        global start_ts
        if start_ts == 0:
            start_ts = event.ts_us
        r_or_w = decode_rw_mode(event.event)
        if file_rw_path[event.pid]:
            path = b'/'
        else:
            path = b''
        path = path + b'/'.join(reversed(file_rw_path[event.pid])).replace(b'\n', b'\\n') + b'/' + event.name
        if not args.json:
            printb(b"%-10.6f %-6d %-6d %-6d %-15.15s %-6d %-10s %s %s" % (
                ((float(event.ts_us) - start_ts) / 1000000), event.uid, event.pid, event.tid, event.task, event.count,
                format(event.mode, "#09o")[2:].encode(), r_or_w.encode(), path))
            # mode is formatted to display in octal, look at "man(7) inode" to see what is means
        else:
            json_data = {
                "event": r_or_w,
                "uid": event.uid,
                "pid": event.pid,
                "tid": event.tid,
                "time": '{:f}'.format((float(event.ts_us) - start_ts) / 1000000),
                "task": event.task.decode(),
                "data": {
                    "bytes": event.count,
                    "file_mode": format(event.mode, "#09o")[2:],
                    "file_name": path.decode()
                }
            }
            print(json.dumps(json_data))
        try:
            del (file_rw_path[event.pid])
        except Exception:
            pass


def print_file_open_event(cpu, data, size):
    event = b["file_open_events"].event(data)
    global start_ts
    if start_ts == 0:
        start_ts = event.ts_us
    if not args.json:
        printb(b"%-10.6f %-6d %-6d %-6d %-15.15s %-10s %-10s %s %s" % (
            ((float(event.ts_us) - start_ts) / 1000000), event.uid, event.pid,
            event.tid, event.task, format(event.mode, "#09o")[2:].encode(), format(event.flags, "#09o")[2:].encode(),
            "File Open".encode(), event.name))
    else:
        json_data = {
            "event": "File Open",
            "uid": event.uid,
            "pid": event.pid,
            "tid": event.tid,
            "time": '{:f}'.format((float(event.ts_us) - start_ts) / 1000000),
            "task": event.task.decode(),
            "data": {
                "file_name": event.name.decode(),
                "flags": format(event.flags, "#09o")[2:],
                "file_mode": format(event.mode, "#09o")[2:]
            }
        }
        print(json.dumps(json_data))


def print_file_close_event(cpu, data, size):
    event = b["file_close_events"].event(data)
    if event.event == File_close_EventType.PASS_PATH:
        file_close_path[event.pid].append(event.name)
    elif event.event == File_close_EventType.CLOSE:
        global start_ts
        if start_ts == 0:
            start_ts = event.ts_us
        if file_close_path[event.pid]:
            path = b'/'
        else:
            path = b''
        path = path + b'/'.join(reversed(file_close_path[event.pid])).replace(b'\n', b'\\n') + b'/' + event.name
        if not args.json:
            printb(b"%-10.6f %-6d %-6d %-6d %-15.15s %-10s %s %s" % (
                ((float(event.ts_us) - start_ts) / 1000000), event.uid, event.pid, event.tid, event.task,
                format(event.mode, "#09o")[2:].encode(), "File Close".encode(), path))
        else:
            json_data = {
                "event": "File Close",
                "uid": event.uid,
                "pid": event.pid,
                "tid": event.tid,
                "time": '{:f}'.format((float(event.ts_us) - start_ts) / 1000000),
                "task": event.task.decode(),
                "data": {
                    "file_mode": format(event.mode, "#09o")[2:],
                    "file_name": path.decode()
                }
            }
            print(json.dumps(json_data))
        try:
            del (file_close_path[event.pid])
        except Exception:
            pass


def print_file_unlink_event(cpu, data, size):
    event = b["file_unlink_events"].event(data)
    if event.event == File_unlink_EventType.PASS_PATH:
        file_unlink_path[event.pid].append(event.name)
    elif event.event == File_unlink_EventType.UNLINK:
        global start_ts
        if start_ts == 0:
            start_ts = event.ts_us
        if file_unlink_path[event.pid]:
            path = b'/'
        else:
            path = b''
        path = path + b'/'.join(reversed(file_unlink_path[event.pid])).replace(b'\n', b'\\n') + b'/' + event.name
        if not args.json:
            printb(b"%-10.6f %-6d %-6d %-6d %-15.15s %-10s %s %s" % (
                ((float(event.ts_us) - start_ts) / 1000000), event.uid, event.pid, event.tid, event.task,
                format(event.mode, "#09o")[2:].encode(), "File Delete".encode(), path))
        else:
            json_data = {
                "event": "File Delete",
                "uid": event.uid,
                "pid": event.pid,
                "tid": event.tid,
                "time": '{:f}'.format((float(event.ts_us) - start_ts) / 1000000),
                "task": event.task.decode(),
                "data": {
                    "file_mode": format(event.mode, "#09o")[2:],
                    "file_name": path.decode()
                }
            }
            print(json.dumps(json_data))
        try:
            del (file_unlink_path[event.pid])
        except Exception:
            pass


def print_file_rename_event(cpu, data, size):
    event = b["file_rename_events"].event(data)
    global file_rename_new_name
    if event.event == File_rename_EventType.PASS_NEW_PATH:
        file_rename_new_path[event.pid].append(event.old_name)
    elif event.event == File_rename_EventType.PASS_OLD_PATH:
        file_rename_old_path[event.pid].append(event.old_name)
    elif event.event == File_rename_EventType.PASS_NEW_NAME:
        file_rename_new_name = event.old_name
    elif event.event == File_rename_EventType.RENAME:
        global start_ts
        if start_ts == 0:
            start_ts = event.ts_us
        # fetch old path
        if file_rename_old_path[event.pid]:
            old_path = b'/'
        else:
            old_path = b''
        old_path = old_path + b'/'.join(reversed(file_rename_old_path[event.pid])).replace(b'\n',
                                                                                           b'\\n') + b'/' + event.old_name
        # fetch new path
        if file_rename_new_path[event.pid]:
            new_path = b'/'
        else:
            new_path = b''
        new_path = new_path + b'/'.join(reversed(file_rename_new_path[event.pid])).replace(b'\n',
                                                                                           b'\\n') + b'/' + file_rename_new_name
        if not args.json:
            printb(b"%-10.6f %-6d %-6d %-6d %-15.15s %-10s %-10s %s %s %s" % (
                ((float(event.ts_us) - start_ts) / 1000000), event.uid, event.pid, event.tid, event.task,
                format(event.mode, "#09o")[2:].encode(), format(event.flags, "#09o")[2:].encode(),
                "File Rename".encode(),
                old_path, new_path))
        else:
            json_data = {
                "event": "File Rename",
                "uid": event.uid,
                "pid": event.pid,
                "tid": event.tid,
                "time": '{:f}'.format((float(event.ts_us) - start_ts) / 1000000),
                "task": event.task.decode(),
                "data": {
                    "flags": format(event.flags, "#09o")[2:],
                    "file_mode": format(event.mode, "#09o")[2:],
                    "file_old_name": old_path.decode(),
                    "file_new_name": new_path.decode()
                }
            }
            print(json.dumps(json_data))
        try:
            del (file_rename_old_path[event.pid])
            del (file_rename_new_path[event.pid])
            file_rename_new_name = str()
        except Exception:
            pass


# initialize BPF
b = BPF(text=bpf_text)
# seperation of activities by given flags
if args.all or args.traffic:
    b.attach_kprobe(event="tcp_connect", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_connect", fn_name="trace_connect_tcp_return")

    b.attach_kprobe(event="inet_csk_accept", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="inet_csk_accept", fn_name="trace_con_ack_tcp_return")

    b.attach_kprobe(event="udp_sendmsg", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="udp_sendmsg", fn_name="trace_udp_send_return")
    b.attach_kprobe(event="udp_sendpage", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="udp_sendpage", fn_name="trace_udp_sendpage_return")
    b.attach_kprobe(event="udpv6_sendmsg", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="udpv6_sendmsg", fn_name="trace_udp_send_return")

    # both are responsible for sending tcp packets, own observation: sendpage is nearly never used
    b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_sendmsg", fn_name="trace_tcp_send_return")
    b.attach_kprobe(event="tcp_sendpage", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_sendpage", fn_name="trace_tcp_sendpage_return")

    b.attach_kprobe(event="tcp_recvmsg", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_recvmsg", fn_name="trace_tcp_rcv_return")

    b.attach_kprobe(event="udp_recvmsg", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="udp_recvmsg", fn_name="trace_udp_rcv_return")
    b.attach_kprobe(event="udpv6_recvmsg", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="udpv6_recvmsg", fn_name="trace_udp_rcv_return")

    # also found tcp_disconnect but no results there
    b.attach_kprobe(event="tcp_close", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_close", fn_name="trace_disconnect_tcp_return")

if args.all or args.fork:
    fork_fnname = b.get_syscall_fnname("fork")
    b.attach_kretprobe(event=fork_fnname, fn_name="trace_fork_return")
    vfork_fnname = b.get_syscall_fnname("vfork")
    b.attach_kretprobe(event=vfork_fnname, fn_name="trace_vfork_return")
    clone_fnname = b.get_syscall_fnname("clone")
    b.attach_kretprobe(event=clone_fnname, fn_name="trace_clone_return")
    b.attach_tracepoint(tp="sched:sched_process_exit", fn_name="trace_process_exit_tracepoint")
    execve_fnname = b.get_syscall_fnname("execve")
    b.attach_kprobe(event=execve_fnname, fn_name="syscall__trace_execve")
    # fn_name has to start with syscall__ else the arguments from the user are empty, don't know why exactly
    b.attach_kretprobe(event=execve_fnname, fn_name="trace_execve_return")

if args.all or args.file:
    b.attach_kprobe(event="vfs_read", fn_name="trace_read_entry")
    b.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")
    b.attach_kprobe(event="do_sys_open", fn_name="trace_open_entry")
    b.attach_kprobe(event="filp_close", fn_name="trace_close_entry")
    b.attach_kprobe(event="vfs_unlink", fn_name="trace_unlink_entry")
    b.attach_kprobe(event="vfs_rename", fn_name="trace_rename_entry")

# header is only valid for ip-based events, no solution found yet to support all eventtypes
if not args.json:
    print("%-10s %-6s %-6s %-6s %-15s %-2s %-16s %-16s %-6.6s %-6.6s" % (
        "TIME(s)", "UID", "PID", "TID", "COMM", "IP", "SADDR",
        "DADDR", "SPORT", "DPORT"))

# read events
if args.all or args.traffic:
    b["ipv4_events"].open_perf_buffer(print_ipv4_event)
    b["ipv6_events"].open_perf_buffer(print_ipv6_event)
if args.all or args.fork:
    b["fork_events"].open_perf_buffer(print_fork_event)
    b["process_exit_events"].open_perf_buffer(print_process_exit_event)
    b["process_execute_events"].open_perf_buffer(print_process_execute_event)
if args.all or args.file:
    b["file_rw_events"].open_perf_buffer(print_file_rw_event, page_cnt=1024)
    b["file_open_events"].open_perf_buffer(print_file_open_event, page_cnt=128)
    b["file_close_events"].open_perf_buffer(print_file_close_event, page_cnt=128)
    b["file_unlink_events"].open_perf_buffer(print_file_unlink_event, page_cnt=128)
    b["file_rename_events"].open_perf_buffer(print_file_rename_event, page_cnt=128)
while 1:
    # '''
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
    # the following only exists for debugging with bpf_trace_printk()
    '''
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%s" % (msg))
    '''
