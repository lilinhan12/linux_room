#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#include <linux/mutex.h>
#include <trace/events/oom.h>

#include <linux/oom.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/task.h>
#include <linux/sched/debug.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/timex.h>
#include <linux/jiffies.h>
#include <linux/cpuset.h>
#include <linux/export.h>
#include <linux/notifier.h>
#include <linux/memcontrol.h>
#include <linux/mempolicy.h>
#include <linux/security.h>
#include <linux/ptrace.h>
#include <linux/freezer.h>
#include <linux/ftrace.h>
#include <linux/ratelimit.h>
#include <linux/kthread.h>
#include <linux/init.h>
#include <linux/mmu_notifier.h>
#include <linux/nodemask.h>
#include <linux/debug_locks.h>

extern atomic_t oom_victims;
extern struct wait_queue_head oom_victims_wait;
extern bool oom_killer_disabled __read_mostly;

extern struct task_struct *oom_reaper_th;
extern struct wait_queue_head oom_reaper_wait;
extern struct task_struct *oom_reaper_list;
extern spinlock_t oom_reaper_lock;
extern struct mutex oom_lock;
extern struct mutex oom_adj_mutex;
extern struct blocking_notifier_head oom_notify_list;


struct mutex mutex_initializer_oom_adj(void);
struct mutex mutex_initializer_oom_lock(void);


void rcu_read_lock_rust(void);
void rcu_read_unlock_rust(void);
bool oom_cpuset_eligible_thread(struct task_struct *start,const nodemask_t *mask,bool ret);
struct task_struct * find_lock_task_mm_thread(struct task_struct *p);
int is_global_init_rust(struct task_struct *tsk);
unsigned long global_node_page_state_rust(enum node_stat_item item);
unsigned long global_node_page_state_pages_rust(enum node_stat_item item);
int test_bit_rust(int nr,const volatile unsigned long *vaddr);
bool in_vfork_rust(struct task_struct *tsk);
void task_unlock_rust(struct task_struct *p);
unsigned long get_mm_rss_rust(struct mm_struct *mm);
unsigned long get_mm_counter_rust(struct mm_struct *mm,int member);
unsigned long mm_pgtables_bytes_rust(const struct mm_struct *mm);
long pgsize_rust(void);
enum zone_type gfp_zone_rust(gfp_t flags);
unsigned long mem_cgroup_get_max_rust(struct mem_cgroup *memcg);
bool is_enabled_numa_rust(void);
int nodes_subset_rust(struct oom_control *oc);
unsigned long totalram_pages_rust(void);
void for_each_node_mask_rust1(int nid,struct oom_control *oc);
void for_each_node_mask_rust2(int nid,struct oom_control *oc);
bool for_each_zone_rust(struct oom_control *oc,enum zone_type highest_zoneidx);
void put_task_struct_rust(struct task_struct *t);
bool tsk_is_oom_victim_rust(struct task_struct *task);
bool oom_task_origin_rust(const struct task_struct *p);
struct task_struct *get_task_struct_rust(struct task_struct *t);
struct task_struct *next_task_rust(struct task_struct *p);
int likely_rust(struct mm_struct *m);
void pr_info_dump_task(struct task_struct *task);
void pr_cont_dump_summary(struct task_struct *victim);
void pr_warn_dump_header(struct oom_control *oc);
atomic_t atomic_init_rust(int i);
struct wait_queue_head declare_wait_queue_head_rust(void);
bool process_shares_mm_thread(struct task_struct *p, struct mm_struct *mm);
void set_bit_rust(unsigned long *addr);
void set_bit_rust_skip(unsigned long *addr);
bool can_madv_lru_vma_rust(struct vm_area_struct *vma);
bool vma_is_anonymous_rust(struct vm_area_struct *vma);
struct mmu_notifier_range  mmu_notifier_range_init_rust(enum mmu_notifier_event event,unsigned flags,struct vm_area_struct *vma,struct mm_struct *mm,unsigned long start,unsigned long end);
struct mmu_gather tlb_gather_mmu_rust(struct mm_struct *mm);
int mmu_notifier_invalidate_range_start_nonblock_rust(struct mmu_notifier_range *range);
void mmu_notifier_invalidate_range_end_rust(struct mmu_notifier_range *range);
void unmap_page_range_rust(struct mmu_gather *tlb,
			     struct vm_area_struct *vma,
			     unsigned long addr, unsigned long end);
bool mmap_read_trylock_rust(struct mm_struct *mm);
void trace_skip_task_reaping_rust(pid_t pid);
void trace_finish_task_reaping_rust(pid_t pid);
void mmap_read_unlock_rust(struct mm_struct *mm);
void trace_start_task_reaping_rust(pid_t pid);
void pr_info_oom_reap_task_mm(struct task_struct *tsk,struct mm_struct *mm);void pr_info_reap_task(struct task_struct *tsk);
void debug_show_all_locks_rust(void);
void wait_event_freezable_rust(void);
void spin_lock_rust(void);
void spin_unlock_rust(void);
int test_and_set_bit_rust(unsigned long *addr);
void trace_wake_reaper_rust(pid_t p);
void wake_up_rust(void);
struct task_struct *kthread_run_rust(int (*threadfn)(void *data));
void warn_on_rust(void);
int test_and_set_tsk_thread_flag_rust(struct task_struct *tsk);
int cmpxchg_rust(struct task_struct *tsk,struct mm_struct *m2);
void mmgrab_rust(struct mm_struct *mm);
void set_bit_victim(unsigned long *addr);
void atomic_inc_rust(void);
void trace_mark_victim_rust(pid_t t);
void clear_thread_flag_rust(void);
int atomic_dec_return_rust(void);
void wake_up_all_rust(void);
void pr_info_oom_killer_enable(void);
void pr_info_oom_killer_disable(void);
int mutex_lock_killable_rust(void);
void mutex_unlock_rust(void);
signed long wait_event_interruptible_timeout_rust(signed long timeout);
int thread_group_empty_rust(struct task_struct *task);
int atomic_read_rust(const atomic_t *v);
bool same_thread_group_rust(struct task_struct *p1,struct task_struct *p2);
void print__oom_kill(struct task_struct *victim,const char *message);
void count_vm_event_rust(void);
void memcg_memory_event_mm_rust(struct mm_struct *mm);
void do_send_sig_info_rust(struct task_struct *victim);
void pr_err_oom(struct task_struct *victim,struct mm_struct *mm,const char *message);
void print__oom_kill_2(struct task_struct *victim,struct task_struct *p);
int unlikely_rust(struct task_struct *p);
void mmdrop_rust(struct mm_struct *mm);
struct ratelimit_state define_ratelimit_state_rust(void);
void task_lock_rust(struct task_struct *victim);
int ratelimit(struct ratelimit_state *rs);
void mem_cgroup_put_rust(struct mem_cgroup *oom_group);
int like_rust(int i);
struct task_struct *get_current_rust(void);
int fatal_signal_pending_rust(struct task_struct *p);
void pr_info_1(void);
struct task_struct *find_lock_task_mm_rust(struct task_struct *p);
void dump_task_pr_info(void);
void dump_oom_summary_pr_info(struct oom_control *oc);
void __oom_kill_process_rust(struct task_struct *victim, const char *message);
void oom_kill_process_rust(struct oom_control *oc, const char *message);
void __oom_kill_process_for(struct task_struct *victim,const char* message,bool can_oom_reap,struct task_struct *p,struct mm_struct *mm);
void oom_reap_task_null(struct task_struct *tsk);
void dump_header_rust(struct oom_control *oc);
void nodemask_null(struct oom_control *oc);
void wake_oom_reaper_rust(struct task_struct *victim);
void mmgrab_tsk(struct task_struct *tsk);
void out_of_memory_panic(void);
void hello_lili(void);
