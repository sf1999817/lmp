#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "write.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, u64);
} data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("tracepoint/syscalls/sys_enter_write")

int kprobe_sys_enter_write( void *ctx)
{
  pid_t pid;
  struct fs_t *e;
  u64 ts;
  pid = bpf_get_current_pid_tgid() >> 32;
  ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&data,&pid,&ts,BPF_ANY);
  if(min_duration_ns)
    return 0;
  e = bpf_ringbuf_reserve(&rb,sizeof(*e),0);
  if(!e)
    return 0;
  e->pid = pid;
  e->duration_ns = ts;

  bpf_ringbuf_submit(e,0);
  return 0;
}