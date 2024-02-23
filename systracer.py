#2024.1.22
#??
#?? ????? ??? uid, suid, euid? ??? ???? ???
#ver4? euid == 0? process? ???? ??? ???? ?? ??? ?? ??
#root???? ??? ?? ??

from time import sleep, strftime
import argparse
import errno
import itertools
import sys
import signal
from bcc import BPF
from bcc.utils import printb
from bcc.syscall import syscall_name, syscalls
import csv
import time
from ctypes import *

# signal handler
def signal_ignore(signal, frame):
    print()

def handle_errno(errstr):
    try:
        return abs(int(errstr))
    except ValueError:
        pass

    try:
        return getattr(errno, errstr)
    except AttributeError:
        raise argparse.ArgumentTypeError("couldn't map %s to an errno" % errstr)

text = r"""
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <linux/cred.h>

#define LAST_SYSCALL_NUMBER 450
#define SCHED_ON 1
#define SCHED_OFF 0
#define PRINT_MODE
struct key_prev_syscall_argument{
    u64 pid_tgid;
    u64 syscall_number;
};

struct prev_syscall_argument //?? ??? ??????? ???? ??
{
    u64 prev_args[6];
};

struct syscall_info_key{
    u64 pid_tgid;
    u64 syscall_number;
};

struct syscall_info{      //thread? dirty cred ???
    u32 pid;
    u32 tid;
    u64 syscall_number;
    u64 count;
    u32 is_not_first;
    char task_name[TASK_COMM_LEN];
};

struct process_syscall_info{
    //???? ??
    u64 sched_status;         //?? cpu?? ???? ????
    u64 prev_cpu_number;
    u64 cpu_similar;   //??? ????? ?? ?? ??? ??
    u32 start_time;
    u32 end_time;
    u32 sched_time;     //???? ??????
    u64 sched_count;    //?? ???? ????

    u64 dangerous_start;  //??? ??? ???? cpu?? ??
    u64 dangerous_sched_count;      //??? ???? ?? cpu?? ???? ??

    //???? ??
    u64 syscall_count; //???? ??????
    u64 syscall_vel;   //???? ?? ??
    u64 syscall_argument_similar; //??? ??? ??? ????? ?????? ??
    u64 prev_syscall_number;    //?? ??? ???? ??
    u64 syscall_kind_similar;   //???? ???

    double syscall_vel_d;   //???? ?? ??
    double syscall_argument_similar_d; //??? ??? ??? ????? ?????? ??
    double syscall_kind_similar_d;   //???? ???

    //kernel memory ??
    u64 prev_kmalloc;           //?? kmalloc slab??
    u64 kmalloc_similar;        //kmalloc ???
    u64 kmalloc_count;             

    u64 prev_kmem_cache_alloc;
    u64 kmem_cache_alloc_similar;
    u64 kmem_cache_alloc_count;

    //kfree kmem_cache_free??
    u64 uaf_posibility;

    u64 prev_kfree;
    u64 kfree_similar;
    u64 kfree_count;

    u64 prev_kmem_cache_free;
    u64 kmem_cache_free_similar;
    u64 kmem_cache_free_count;

    //root?? open ? free??
    u64 does_open_root_file;
    u64 does_free_root_file;

    u64 root_file_address;

    u32 do_exit;

    //???
    char task_name[TASK_COMM_LEN];
    u32 pid;
    u32 tid;
};

BPF_HASH(data_process_syscall_info, u64, struct process_syscall_info);
BPF_HASH(data_prev_syscall_argument,struct key_prev_syscall_argument,struct prev_syscall_argument);
BPF_HASH(print_data_process_syscall_info,u64, struct process_syscall_info);
//?????? ??
BPF_HASH(data_syscall_info, struct syscall_info_key, struct syscall_info);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u32 syscall_argument_similar = 0;

    struct process_syscall_info * val_process_syscall_info, zero_val_process_syscall_info = {};
    struct prev_syscall_argument * val_prev_syscall_argument, zero_val_prev_syscall_argument = {};
    struct key_prev_syscall_argument val_key_prev_syscall_argument = {};

    val_key_prev_syscall_argument.syscall_number = args->id;
    val_key_prev_syscall_argument.pid_tgid = pid_tgid;
    val_process_syscall_info = data_process_syscall_info.lookup_or_try_init(&pid_tgid, &zero_val_process_syscall_info);
    val_prev_syscall_argument = data_prev_syscall_argument.lookup_or_try_init(&val_key_prev_syscall_argument, &zero_val_prev_syscall_argument);

    if(val_process_syscall_info && val_prev_syscall_argument)
    {
        if(val_process_syscall_info->sched_status == SCHED_ON)
        {
            val_process_syscall_info->syscall_count += 1;
            for(int i = 0 ; i < 2 ; ++i)    //??? ? ???? ??? ?? 6?? ??
            {
                if( val_prev_syscall_argument->prev_args[i] == args->args[i] )
                {
                    syscall_argument_similar = 1;
                }
                val_prev_syscall_argument->prev_args[i] = args->args[i];
            }  
            if(syscall_argument_similar == 1)
            {
                val_process_syscall_info->syscall_argument_similar += 1;
            }

            if(val_process_syscall_info->prev_syscall_number == args-> id)
            {
                val_process_syscall_info->syscall_kind_similar += 1;
            }
            val_process_syscall_info->prev_syscall_number = args->id;
        }
    }

    u32 syscall_number = args->id;

    struct syscall_info_key val_syscall_info_key= {};
    val_syscall_info_key.pid_tgid = pid_tgid;
    val_syscall_info_key.syscall_number = syscall_number;

    struct syscall_info * val_syscall_info, val_syscall_info_zero = {};
    val_syscall_info = data_syscall_info.lookup_or_try_init(&val_syscall_info_key,&val_syscall_info_zero);
    if(val_syscall_info)
    {
        val_syscall_info->pid = pid;
        val_syscall_info->tid = tid;
        val_syscall_info->syscall_number = syscall_number;
        val_syscall_info->count += 1;
        if(val_syscall_info->is_not_first == 0)
        {
            char name[TASK_COMM_LEN];
            bpf_get_current_comm(&name, sizeof(name));
            bpf_probe_read_str((char *)val_syscall_info->task_name,sizeof(name),name);
            val_syscall_info->is_not_first = 1;
        }
    }
    
done :
    return 0;
}

RAW_TRACEPOINT_PROBE(sched_switch)
{
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next= (struct task_struct *)ctx->args[2];
    s32 prev_tgid, next_tgid;
    s32 prev_pid, next_pid;
    u64 prev_pid_tgid, next_pid_tgid;

    bpf_probe_read_kernel(&prev_tgid, sizeof(prev->tgid), &prev->tgid);
    bpf_probe_read_kernel(&next_tgid, sizeof(next->tgid), &next->tgid);
    bpf_probe_read_kernel(&prev_pid, sizeof(prev->pid), &prev->pid);
    bpf_probe_read_kernel(&next_pid, sizeof(next->pid), &next->pid);

    prev_pid_tgid = prev_tgid;
    prev_pid_tgid = prev_pid_tgid << 32;
    prev_pid_tgid |= prev_pid;
    next_pid_tgid = next_tgid;
    next_pid_tgid = next_pid_tgid << 32;
    next_pid_tgid |= next_pid;

    struct process_syscall_info * prev_val_process_syscall_info, * next_val_process_syscall_info,zero_val_process_syscall_info = {};
#ifdef PRINT_MODE
    struct process_syscall_info * print_val_process_syscall_info;
#endif
    if((next->cred->euid).val != 0)
    {
    next_val_process_syscall_info = data_process_syscall_info.lookup_or_try_init(&next_pid_tgid, &zero_val_process_syscall_info);
        if(next_val_process_syscall_info)
        {
            next_val_process_syscall_info->sched_status = SCHED_ON;
            next_val_process_syscall_info->start_time = bpf_ktime_get_ns();
        }
    }
    if((prev->cred->euid).val == 0)
    {
        goto done;
    }
    prev_val_process_syscall_info = data_process_syscall_info.lookup_or_try_init(&prev_pid_tgid, &zero_val_process_syscall_info);
    if(prev_val_process_syscall_info)
    {
        if(prev_val_process_syscall_info->sched_status == SCHED_ON)
        {
            prev_val_process_syscall_info->sched_status = SCHED_OFF;
            prev_val_process_syscall_info->end_time = bpf_ktime_get_ns();
            int cpu_number = bpf_get_smp_processor_id();
            if(prev_val_process_syscall_info->prev_cpu_number == cpu_number)
            {
                prev_val_process_syscall_info->cpu_similar += 1;
            }
            prev_val_process_syscall_info->prev_cpu_number = cpu_number;
            prev_val_process_syscall_info->sched_count += 1;
            /*
            if(prev_val_process_syscall_info->syscall_count == 0)
            {
                goto done;
            }
            */
            prev_val_process_syscall_info->sched_time = (prev_val_process_syscall_info->end_time - prev_val_process_syscall_info->start_time);
            prev_val_process_syscall_info->syscall_vel = prev_val_process_syscall_info->syscall_count * (1000000000 / prev_val_process_syscall_info->sched_time);
            /*
            prev_val_process_syscall_info->syscall_argument_similar = prev_val_process_syscall_info->syscall_count;
            prev_val_process_syscall_info->syscall_kind_similar = prev_val_process_syscall_info->syscall_count;
            */
#ifdef PRINT_MODE
            print_val_process_syscall_info = print_data_process_syscall_info.lookup_or_try_init(&prev_pid_tgid,&zero_val_process_syscall_info); 
            if(print_val_process_syscall_info)
            {
                print_val_process_syscall_info->syscall_count += prev_val_process_syscall_info->syscall_count;
                print_val_process_syscall_info->syscall_vel += prev_val_process_syscall_info->syscall_vel;
                print_val_process_syscall_info->syscall_argument_similar += prev_val_process_syscall_info->syscall_argument_similar;
                print_val_process_syscall_info->syscall_kind_similar += prev_val_process_syscall_info->syscall_kind_similar;
                print_val_process_syscall_info->sched_time += prev_val_process_syscall_info->sched_time;
                //kmem??
                print_val_process_syscall_info->kmalloc_count += prev_val_process_syscall_info->kmalloc_count;
                print_val_process_syscall_info->kmem_cache_alloc_count += prev_val_process_syscall_info->kmem_cache_alloc_count;
                print_val_process_syscall_info->kmalloc_similar += prev_val_process_syscall_info->kmalloc_similar;
                print_val_process_syscall_info->kmem_cache_alloc_similar += prev_val_process_syscall_info->kmem_cache_alloc_similar;

                print_val_process_syscall_info->kfree_count += prev_val_process_syscall_info->kfree_count;
                print_val_process_syscall_info->kfree_similar += prev_val_process_syscall_info->kfree_similar;
                print_val_process_syscall_info->kmem_cache_free_count += prev_val_process_syscall_info->kmem_cache_free_count;
                print_val_process_syscall_info->kmem_cache_free_similar += prev_val_process_syscall_info->kmem_cache_free_similar;
                print_val_process_syscall_info->uaf_posibility += prev_val_process_syscall_info->uaf_posibility;

                print_val_process_syscall_info->cpu_similar += prev_val_process_syscall_info->cpu_similar;
                print_val_process_syscall_info->sched_count += prev_val_process_syscall_info->sched_count;

                char name[TASK_COMM_LEN];
                bpf_get_current_comm(&name, sizeof(name));
                bpf_probe_read_str((char*)print_val_process_syscall_info->task_name,sizeof(name),name);   
                print_val_process_syscall_info->pid = prev_tgid;
                print_val_process_syscall_info->tid = prev_pid;
            }
#endif
            if(prev_val_process_syscall_info->do_exit == 1)
            {
                data_process_syscall_info.delete(&prev_pid_tgid);
            }
            else
            {
                prev_val_process_syscall_info->syscall_count = 0;
                prev_val_process_syscall_info->syscall_argument_similar = 0;
                prev_val_process_syscall_info->syscall_kind_similar = 0;

                prev_val_process_syscall_info->kmalloc_count = 0;
                prev_val_process_syscall_info->kmem_cache_alloc_count = 0;
                prev_val_process_syscall_info->kmalloc_similar = 0;
                prev_val_process_syscall_info->kmem_cache_alloc_similar = 0;
                prev_val_process_syscall_info->kfree_count = 0;
                prev_val_process_syscall_info->kfree_similar = 0;
                prev_val_process_syscall_info->kmem_cache_free_count = 0;
                prev_val_process_syscall_info->kmem_cache_free_similar = 0;

                prev_val_process_syscall_info->uaf_posibility = 0;

                prev_val_process_syscall_info->cpu_similar = 0;
                prev_val_process_syscall_info->sched_count = 0;
            }
        }
    }
done :
    return 0;
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
}
/*
TRACEPOINT_PROBE(sched, sched_switch) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    int cpu = bpf_get_smp_processor_id();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct process_syscall_info * val_process_syscall_info, zero_val_process_syscall_info = {};
    val_process_syscall_info = data_process_syscall_info.lookup_or_try_init(&pid_tgid, &zero_val_process_syscall_info);

    if(val_process_syscall_info)
    {
        if(val_process_syscall_info->sched == 1)
        {

        }
    }

done :
    return 0;
}
*/

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
done :
    return 0;
}


int kprobe__do_exit(void *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct key_prev_syscall_argument val_key_prev_syscall_argument = {};
    struct process_syscall_info * val_process_syscall_info, zero_val_process_syscall_info = {};

    for(int i = 0 ; i < LAST_SYSCALL_NUMBER ; i += 1)
    {
        val_key_prev_syscall_argument.syscall_number = i;
        val_key_prev_syscall_argument.pid_tgid = pid_tgid;
        data_prev_syscall_argument.delete(&val_key_prev_syscall_argument);
    }

    val_process_syscall_info = data_process_syscall_info.lookup_or_try_init(&pid_tgid, &zero_val_process_syscall_info);
    if(val_process_syscall_info)
    {
        val_process_syscall_info->do_exit = 1;
    }

done :    
    return 0;
}



TRACEPOINT_PROBE(kmem, kmalloc) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct process_syscall_info * val_process_syscall_info, zero_val_process_syscall_info = {};
    val_process_syscall_info = data_process_syscall_info.lookup_or_try_init(&pid_tgid, &zero_val_process_syscall_info);
    if(val_process_syscall_info)
    {
        if(val_process_syscall_info->sched_status == SCHED_ON)
        {
            val_process_syscall_info->kmalloc_count += 1;
            if(val_process_syscall_info->prev_kmalloc == args->bytes_alloc)
            {
                val_process_syscall_info->kmalloc_similar += 1;
            }
            val_process_syscall_info->prev_kmalloc = args->bytes_alloc;
            if(val_process_syscall_info->prev_kfree == (u64)args->ptr)
            {
                val_process_syscall_info->uaf_posibility += 1;
            }
        }
    }
done :
    return 0;
}

TRACEPOINT_PROBE(kmem, kmem_cache_alloc){
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct process_syscall_info * val_process_syscall_info, zero_val_process_syscall_info = {};
    val_process_syscall_info = data_process_syscall_info.lookup_or_try_init(&pid_tgid, &zero_val_process_syscall_info);
    if(val_process_syscall_info)
    {
        if(val_process_syscall_info->sched_status == SCHED_ON)
        {
            val_process_syscall_info->kmem_cache_alloc_count += 1;
            if(val_process_syscall_info->prev_kmem_cache_alloc == args->bytes_alloc)
            {
                val_process_syscall_info->kmem_cache_alloc_similar += 1;
            }
            val_process_syscall_info->prev_kmem_cache_alloc = args->bytes_alloc;
            if(val_process_syscall_info->prev_kmem_cache_free == (u64)args->ptr)
            {
                val_process_syscall_info->uaf_posibility += 1;
            }
        }
    }
done :
    return 0;
}

TRACEPOINT_PROBE(kmem, mm_page_alloc){

    return 0;
}

TRACEPOINT_PROBE(kmem, kfree) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct process_syscall_info * val_process_syscall_info, zero_val_process_syscall_info = {};
    val_process_syscall_info = data_process_syscall_info.lookup_or_try_init(&pid_tgid, &zero_val_process_syscall_info);
    if(val_process_syscall_info)
    {
        if(val_process_syscall_info->sched_status == SCHED_ON)
        {
            val_process_syscall_info->kfree_count += 1;
            if(val_process_syscall_info->prev_kfree == (u64)args->ptr)
            {
                val_process_syscall_info->kfree_similar += 1;
            }
            val_process_syscall_info->prev_kfree = (u64)args->ptr;
        }
    }
done :
    return 0;
}

TRACEPOINT_PROBE(kmem, kmem_cache_free) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred * cred = task->cred;
    if((cred->euid).val == 0)
    {
        goto done;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct process_syscall_info * val_process_syscall_info, zero_val_process_syscall_info = {};
    val_process_syscall_info = data_process_syscall_info.lookup_or_try_init(&pid_tgid, &zero_val_process_syscall_info);
    if(val_process_syscall_info)
    {
        if(val_process_syscall_info->sched_status == SCHED_ON)
        {
            val_process_syscall_info->kmem_cache_free_count += 1;
            if(val_process_syscall_info->prev_kmem_cache_free == (u64)args->ptr)
            {
                val_process_syscall_info->kmem_cache_free_similar += 1;
            }
            val_process_syscall_info->prev_kmem_cache_free = (u64)args->ptr;
        }
    }
done :
    return 0;
}

//??? kprobe??? ??

//????? ????? cred? ??? ????? ??? ????? ????? ???? ??

//????? ???? ????? ????? pid? ?????? ???? ??
"""

file_name_ori = input('?? ??? ??????: ')

bpf = BPF(text=text)

def print_process_info():
    print_data_process_syscall_info = bpf['print_data_process_syscall_info']
    print_data_syscall_info = bpf["data_syscall_info"]
    is_alert = 0
    global print_type
    global print_line_count
    collect_print_data_process_syscall_info = print_data_process_syscall_info.items_lookup_and_delete_batch()
    collect_print_data_syscall_info = print_data_syscall_info.items_lookup_and_delete_batch()
    for k, v in collect_print_data_process_syscall_info:
        process_name= (v.task_name).decode('utf-8')
        if '' in process_name:
            if v.syscall_count != 0 and v.sched_time != 0:
                write_data = [print_type,v.pid,v.tid,process_name,v.sched_time,v.syscall_count,round(v.syscall_count * (1000000000/v.sched_time),3), round(v.syscall_argument_similar/v.syscall_count,3),
                round(v.syscall_kind_similar/v.syscall_count,3), 'syscall_info' ]
                writer.writerow(write_data)
                print_line_count += 1
                print(write_data)
            else:
                write_data = [print_type,v.pid,v.tid,process_name,v.sched_time,v.syscall_count,v.syscall_count * (1000000000/v.sched_time), v.syscall_argument_similar,v.syscall_kind_similar ,'error happen!!']
                writer.writerow(write_data)
                print_line_count += 1
                print(write_data)
            if v.kmalloc_count != 0 and v.sched_time != 0:
                write_data = [print_type,v.pid,v.tid,process_name,v.sched_time,v.kmalloc_count,round(v.kmalloc_count * (1000000000/v.sched_time),3), round(v.kmalloc_similar/v.kmalloc_count,3),'',
                 'kmalloc_info' ]
                writer.writerow(write_data)
                print_line_count += 1
                print(write_data)
            if v.kmem_cache_alloc_count != 0 and v.sched_time != 0:
                write_data = [print_type,v.pid,v.tid,process_name,v.sched_time,v.kmem_cache_alloc_count,round(v.kmem_cache_alloc_count * (1000000000/v.sched_time),3), round(v.kmem_cache_alloc_similar/v.kmem_cache_alloc_count,3),'',
                 'kmem_cache_alloc_info' ]
                writer.writerow(write_data)
                print_line_count += 1
                print(write_data)
            if v.kfree_count != 0 and v.sched_time != 0:
                write_data = [print_type,v.pid,v.tid,process_name,v.sched_time,v.kfree_count,round(v.kfree_count * (1000000000/v.sched_time),3), round(v.kfree_similar/v.kfree_count,3),'',
                 'kfree_info' ]
                writer.writerow(write_data)
                print_line_count += 1
                print(write_data)
            if v.kmem_cache_free_count != 0 and v.sched_time != 0:
                write_data = [print_type,v.pid,v.tid,process_name,v.sched_time,v.kmem_cache_free_count,round(v.kmem_cache_free_count * (1000000000/v.sched_time),3), round(v.kmem_cache_free_similar/v.kmem_cache_free_count,3),'',
                 'kmem_cache_free_info' ]
                writer.writerow(write_data)
                print_line_count += 1
                print(write_data)
            if (v.kmalloc_count + v.kmem_cache_alloc_count) != 0:
                write_data = [print_type,v.pid,v.tid,process_name,v.sched_time,v.kmalloc_count+v.kmem_cache_alloc_count,round(v.uaf_posibility/(v.kmalloc_count+v.kmem_cache_alloc_count),3),'','',
                 'uaf_posibility' ]
                writer.writerow(write_data)
                print_line_count += 1
                print(write_data)
            if v.sched_count != 0 and v.sched_time != 0:
                write_data = [print_type,v.pid,v.tid,process_name,v.sched_time,v.sched_count,round(v.cpu_similar/v.sched_count,3),'','',
                 'cpu_info' ]
                writer.writerow(write_data)
                print_line_count += 1
                print(write_data)
    #syscall info ??
    for k, v in collect_print_data_syscall_info:
        process_name = (v.task_name).decode('utf-8')
        systemcall_name = syscall_name(v.syscall_number).decode('utf-8')
        write_data = [print_type, v.pid, v.tid, v.count, process_name, systemcall_name,v.syscall_number,'','','syscall_kind_info']
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
while True:
    try:
        print_process_info()
        if print_line_count > print_line_check:         #?? ?? ??? ??? ??? ?? ??? ??? ???.
            print_line_count = 0
            f.close()
            file_number += 1
            file_name = file_name_ori +'_'+ str(file_number)
            f = open(file_name+'.csv', 'a')
            writer = csv.writer(f)
        sleep(check_time)
    except KeyboardInterrupt:
        exiting = 1
        signal.signal(signal.SIGINT, signal_ignore)
    if exiting:
        #f.close()
        print("Detaching...")
        exit()
