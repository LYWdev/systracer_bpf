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

#define NSYSALL_SAME_RATE_CHECK_START 60 //몇개 이상일때부터
#define BIG_RATE 40 //몇프로이상을 점유하는지

struct key_prev_syscall_argument{
    u64 pid_tgid;
    u64 syscall_number;
};

struct prev_syscall_argument //이전 직전의 시스템콜변수를 저장하는 변수
{
    u64 prev_args[6];
};

struct syscall_info_key{
    //u64 pid_tgid;
    u64 pid;
    u64 syscall_number;
};

struct syscall_info{      //thread당 dirty cred 감지용
    u32 pid;
    u32 tid;
    u64 syscall_number;
    u64 count;
    u32 is_not_first;
    char task_name[TASK_COMM_LEN];
};

struct process_syscall_info{
    //스케줄러 관련
    u64 sched_status;         //현재 cpu에서 돌고있는 상태인지
    u64 prev_cpu_number;
    u64 cpu_similar;   //동일한 시피유에서 많이 돌고 있는지 확인
    u32 start_time;
    u32 end_time;
    u32 sched_time;     //몇초동안 실행되었는지
    u64 sched_count;    //몇번 스케줄링 되었는지

    u64 dangerous_start;  //위험한 조건에 부합하게 cpu에서 행동
    u64 dangerous_sched_count;      //위험한 상태에서 몇번 cpu에서 돌았는지 확인

    //시스템콜 관련
    u64 syscall_count; //시스템콜 몇번불렀는지
    u64 syscall_vel;   //시스템콜 호출 속도
    u64 syscall_argument_similar; //유사한 인자를 넣어서 시스템콜을 호출하였는지 확인
    u64 prev_syscall_number;    //직전 호출한 시스템콜 기록
    u64 syscall_kind_similar;   //시스템콜 유사도

    double syscall_vel_d;   //시스템콜 호출 속도
    double syscall_argument_similar_d; //유사한 인자를 넣어서 시스템콜을 호출하였는지 확인
    double syscall_kind_similar_d;   //시스템콜 유사도

    //kernel memory 관련
    u64 prev_kmalloc;           //직전 kmalloc slab크기
    u64 kmalloc_similar;        //kmalloc 유사도
    u64 kmalloc_count;             

    u64 prev_kmem_cache_alloc;
    u64 kmem_cache_alloc_similar;
    u64 kmem_cache_alloc_count;

    //kfree kmem_cache_free관련
    u64 uaf_posibility;

    u64 prev_kfree;
    u64 kfree_similar;
    u64 kfree_count;

    u64 prev_kmem_cache_free;
    u64 kmem_cache_free_similar;
    u64 kmem_cache_free_count;

    //root파일 open 및 free여부
    u64 does_open_root_file;
    u64 does_free_root_file;

    u64 root_file_address;

    u32 do_exit;

    //출력용
    char task_name[TASK_COMM_LEN];
    u32 pid;
    u32 tid;
};

BPF_HASH(data_process_syscall_info, u64, struct process_syscall_info);
BPF_HASH(data_prev_syscall_argument,struct key_prev_syscall_argument,struct prev_syscall_argument);
BPF_HASH(print_data_process_syscall_info,u64, struct process_syscall_info);
//시스템콜종류 관련
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

    u32 syscall_number = args->id;

    struct syscall_info_key val_syscall_info_key= {};
    val_syscall_info_key.pid = pid;
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

//아래는 kprobe함수로 진행

//위험하다고 판단되었고 cred가 변경된 프로세스가 새로운 프로세스를 실행시킬때 감지하는 함수

//위험하다고 판단되는 프로세스가 종료되어서 pid가 반환되었는지 확인하는 함수
"""

file_name_ori = input('파일 이름을 입력해주세요: ')

bpf = BPF(text=text)

def print_process_info():
    print_data_syscall_info = bpf["data_syscall_info"]
    is_alert = 0
    global print_type
    global print_line_count
    global syscall_pid_tid_dict
    global syscall_pid_tid_total_syscall_count
    global syscall_pid_tid_total_syscall_kind_count
    global top_syscall_count
    global top_syscall_rate
    global occupy_rate
    global syscall_pid_tid_syscall_list
    global syscall_pid_tid_syscall_count_list
    global minimum_syscall_check_count
    global top_syscall_total_rate
    global total_syscall_count_mini
    
    collect_print_data_syscall_info = print_data_syscall_info.items_lookup_and_delete_batch()
   
    # make syscall data dictionary 출력
    for k, v in collect_print_data_syscall_info:
        if syscall_pid_tid_dict.get(k.pid) == None:
            syscall_pid_tid_dict[k.pid] = v
        if syscall_pid_tid_total_syscall_count.get(k.pid) == None:
            syscall_pid_tid_total_syscall_count[k.pid] = 0
        syscall_pid_tid_total_syscall_count[k.pid] += v.count
        if syscall_pid_tid_total_syscall_kind_count.get(k.pid) == None:
            syscall_pid_tid_total_syscall_kind_count[k.pid] = 0
        syscall_pid_tid_total_syscall_kind_count[k.pid] += 1
        if syscall_pid_tid_syscall_list.get(k.pid) == None:
            syscall_pid_tid_syscall_list[k.pid] = []
        syscall_pid_tid_syscall_list[k.pid].append((v.count,syscall_name(v.syscall_number).decode('utf-8')))

    for k, v in syscall_pid_tid_dict.items():
        total_syscall_count = syscall_pid_tid_total_syscall_count[k]
        total_syscall_kind_count = syscall_pid_tid_total_syscall_kind_count[k]
        max_syscall_count = 0
        dangerous_count = 0
        top_max_similar_syscall_count = 0
        top_max_syscall_count = 0
        sorted_list_sum = 0
        top_syscall_count = 0
        second_not_dangerous = 0
        write_data = []
        systemcall_few = 0
        first_dangerous = 0
        second_dangerous = 0
        sorted_list = []
        process_name = (v.task_name).decode('utf-8')
        sorted_list = sorted(syscall_pid_tid_syscall_list[k], key=lambda x: -x[0])
        if total_syscall_count < minimum_syscall_check_count:
            write_data = [print_type,v.pid,process_name,total_syscall_count,minimum_syscall_check_count,'','','','syscall_count_few']
            writer.writerow(write_data)
            print_line_count += 1
            print(write_data)
            systemcall_few = 1
        if systemcall_few == 0 and sorted_list[0][0] > total_syscall_count * occupy_rate and total_syscall_count > total_syscall_count_mini:                                #가장 많은 것이 전체의 몇퍼센트 이상이면 위험 프로세스로 간주
            write_data = [print_type,v.pid,process_name,v.count, total_syscall_count,sorted_list[0][0], sorted_list[0][1], occupy_rate,'first_dangerous']
            writer.writerow(write_data)
            print_line_count += 1
            print(write_data)
            first_dangerous = 1
        
        for sorted_list_component in sorted_list:
            sorted_list_sum += sorted_list_component[0]
            top_syscall_count += 1
            if sorted_list_sum > total_syscall_count * top_syscall_total_rate:
                if top_syscall_count > 2:
                    second_not_dangerous = 1
                    top_syscall_count = 2
                break
        if top_syscall_count > 1:
            if len(sorted_list) < top_syscall_count:
                sorted_list = sorted_list[0: len(sorted_list)]
            else:
                sorted_list = sorted_list[0: top_syscall_count]
            if len(sorted_list) > 0:
                max_syscall_count = sorted_list[0][0]
            for sorted_list_component in sorted_list:
                if sorted_list_component[0] > max_syscall_count * top_syscall_rate:
                    dangerous_count += 1
                    top_max_similar_syscall_count += sorted_list_component[0]
                top_max_syscall_count += sorted_list_component[0]
            if systemcall_few == 0 and first_dangerous == 0 and dangerous_count + 1 > top_syscall_count and second_not_dangerous == 0:
                for sorted_list_component in sorted_list:
                    write_data = [print_type,v.pid,process_name,total_syscall_count,top_max_syscall_count,sorted_list_component[0],sorted_list_component[1],top_max_similar_syscall_count,'second_dangerous']
                    writer.writerow(write_data)
                    print_line_count += 1
                    print(write_data)
                    second_dangerous = 1
        elif top_syscall_count == 0:
            top_max_syscall_count = 0
        else :
            top_max_syscall_count = sorted_list[0][0]
        if first_dangerous == 0 and second_dangerous == 0:
            for sorted_list_component in sorted_list:
                write_data = [print_type,v.pid,process_name,total_syscall_count,top_max_syscall_count,sorted_list_component[0],sorted_list_component[1],top_max_similar_syscall_count,'normal']
                writer.writerow(write_data)
                print_line_count += 1
                print(write_data)
    print_type += 1
        
    syscall_pid_tid_dict = {}
    syscall_pid_tid_syscall_list = {}
    syscall_pid_tid_syscall_count_list = {}
    syscall_pid_tid_total_syscall_count = {}
    syscall_pid_tid_total_syscall_kind_count = {}
    syscall_pid_tid_syscall_list = {}

def dangerous_process():
    print('hello')


print_line_count = 0        #현재 몇줄까지 입력되어 있는지 저장하는 변수
print_line_check = 100000   #몇줄까지는 입력할 수 있는지 정하는 변수
print_type = 0                   
check_time = 0.1            #몇초간격으로 입력할지 정하는 변수
file_number = 0             #현재 몇번째 파일로 저장하는지 지정하는 변수
file_name = file_name_ori +'_'+str(file_number)
syscall_pid_tid_dict = {}
syscall_pid_tid_syscall_list = {}
syscall_pid_tid_syscall_count_list = {}
syscall_pid_tid_total_syscall_count = {}
syscall_pid_tid_total_syscall_kind_count = {}
syscall_pid_tid_syscall_list = {}

f = open(file_name+'.csv', 'a')
writer = csv.writer(f)

print_type = 0
is_print = 0
first_time = 0
exiting = 0

#테스트용 파라미터 조정
top_syscall_count = 2 #다이나믹에서는 안씀 호출수가 많은 순서대로 몇개의 시스템콜을 볼 것인가?
top_syscall_rate = 0.9 #호출수가 많은 순서대로 보았을 때 시스템콜끼리 비율이 어느정도 차이가 날 수 있는가? 1 : N (최대 호출수를 1로 보았을 때) (e.g. 0.5면 0.5보다 비율이 높아지면 위험한것으로 간주)
top_syscall_total_rate = 0.8 #시스템콜 n개를 볼때 n개가 전체 호출한 시스템콜에서 차지한 비율이 몇프로인지
occupy_rate = 0.9 #system call이 전체에서 몇%를 차지하고 있는가
minimum_syscall_check_count = 60 #최소 몇개이상의 시스템콜이 불렸을 때부터 검사를 시작할지
total_syscall_count_mini = 5000 #하나만 많이 불렀을 때 시스템콜이 최소 몇개이상 불렸을 때 감지할지


print('start')
while True:
    try:
        print_process_info()
        if print_line_count > print_line_check:         #특정 줄수 이상을 넘으면 파일을 닫고 새로운 파일을 만든다.
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