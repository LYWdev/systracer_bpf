from bcc import BPF
from time import sleep, strftime
import sys
import signal
from bcc.utils import printb
from bcc.syscall import syscall_name, syscalls
import csv
import time
from ctypes import *

# BPF ????
BPF_PROGRAM = r"""
#include<linux/cred.h>

struct block_event_info{
    u64 block_bio_backmerge;
    u64 block_bio_frontmerge;
    u64 block_dirty_buffer;
    u64 block_rq_merge;
    u64 block_split;
    u64 block_bio_bounce;
    u64 block_bio_queue;
    u64 block_getrq;
    u64 block_plug;
    u64 block_rq_insert;
    u64 block_rq_remap;
    u64 block_touch_buffer;
    u64 block_bio_complete;
    u64 block_bio_remap;
    u64 block_rq_complete;
    u64 block_rq_issue;
    u64 block_rq_requeue;
    u64 block_unplug;

    u32 pid;
    u32 tid;
    char task_name[TASK_COMM_LEN];
};

BPF_HASH(data_block_event_info, u64, struct block_event_info);
BPF_HASH(block_event_count, u32);

TRACEPOINT_PROBE(block, block_bio_backmerge) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_bio_backmerge += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_bio_frontmerge) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_bio_frontmerge += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_dirty_buffer) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_dirty_buffer += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_merge) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_rq_merge += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_split) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_split += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_bio_bounce) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_bio_bounce += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_bio_queue) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_bio_queue += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_getrq) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_getrq += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_plug) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_plug += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_insert) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_rq_insert += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_remap) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_rq_remap += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_touch_buffer) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_touch_buffer += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_bio_complete) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_bio_complete += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_bio_remap) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_bio_remap += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_rq_complete += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_issue) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_rq_issue += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_requeue) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_rq_requeue += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

TRACEPOINT_PROBE(block, block_unplug) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    struct block_event_info * val_block_event_info, zero_val_block_event_info = {};
    val_block_event_info = data_block_event_info.lookup_or_init(&pid_tgid, &zero_val_block_event_info);
    if(val_block_event_info)
    {
        val_block_event_info->block_unplug += 1;
        val_block_event_info->pid = pid;
        val_block_event_info->tid = tid;

        char name[TASK_COMM_LEN];
        bpf_get_current_comm(&name, sizeof(name));
        bpf_probe_read_str((char*)val_block_event_info->task_name,sizeof(name),name);   
    }
done :
    return 0;
}

"""
file_name_ori = input('?? ??? ??????: ')
# BPF ??? ???
bpf = BPF(text=BPF_PROGRAM)

# ??? ???? ???? ??
def print_block_event_info():
    data_block_event_info = bpf['data_block_event_info']
    global print_type
    global print_line_count
    for k, v in data_block_event_info.items_lookup_and_delete_batch():
        process_name= (v.task_name).decode('utf-8')
        if '' in process_name:
            write_data = [print_type, v.pid,v.tid,process_name,v.block_bio_backmerge,v.block_bio_frontmerge,v.block_dirty_buffer,v.block_rq_merge,v.block_split,v.block_bio_bounce,v.block_bio_queue, v.block_getrq,v.block_plug,v.block_rq_insert,
            v.block_rq_remap, v.block_touch_buffer, v.block_bio_complete, v.block_bio_remap, v.block_rq_complete, v.block_rq_issue, v.block_rq_requeue, v.block_unplug ]
            writer.writerow(write_data)
            print_line_count += 1
            print(write_data)
    print_type += 1

print_line_count = 0        #?? ???? ???? ??? ???? ??
print_line_check = 100000   #????? ??? ? ??? ??? ??
print_type = 0                   
check_time = 0.1            #?????? ???? ??? ??
file_number = 0             #?? ??? ??? ????? ???? ??
file_name = file_name_ori +'_'+str(file_number)

f = open(file_name+'.csv', 'a')
writer = csv.writer(f)

print_type = 0
is_print = 0
first_time = 0
exiting = 0
print('start')
print('print_type, pid,tid,process_name,block_bio_backmerge,block_bio_frontmerge,block_dirty_buffer,block_rq_merge,block_split,block_bio_bounce,block_bio_queue, block_getrq,block_plug,block_rq_insert, block_rq_remap, block_touch_buffer, block_bio_complete, block_bio_remap, block_rq_complete, block_rq_issue, block_rq_requeue, block_unplug')
# 1??? ??? ???? ??
while 1:
    try:
        print_block_event_info()
        if print_line_count > print_line_check:         #?? ?? ??? ??? ??? ?? ??? ??? ???.
            print_line_count = 0
            f.close()
            file_number += 1
            file_name = file_name_ori +'_'+ str(file_number)
            f = open(file_name+'.csv', 'a')
            writer = csv.writer(f)
        sleep(check_time)
    except KeyboardInterrupt:
        break
