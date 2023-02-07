#include "linhan.h"
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
#include <asm/tlb.h>
#include "internal.h"
#include "slab.h"

atomic_t oom_victims = ATOMIC_INIT(0);
DECLARE_WAIT_QUEUE_HEAD(oom_victims_wait);
bool oom_killer_disabled __read_mostly;

struct task_struct *oom_reaper_th;
DECLARE_WAIT_QUEUE_HEAD(oom_reaper_wait);
struct task_struct *oom_reaper_list;
DEFINE_SPINLOCK(oom_reaper_lock);


DEFINE_MUTEX(oom_lock_rust);

DEFINE_MUTEX(oom_adj_mutex_rust);

BLOCKING_NOTIFIER_HEAD(oom_notify_list);

#define K(x) ((x) << (PAGE_SHIFT-10))

static const char * const oom_constraint_text[] = {
	[CONSTRAINT_NONE] = "CONSTRAINT_NONE",
	[CONSTRAINT_CPUSET] = "CONSTRAINT_CPUSET",
	[CONSTRAINT_MEMORY_POLICY] = "CONSTRAINT_MEMORY_POLICY",
	[CONSTRAINT_MEMCG] = "CONSTRAINT_MEMCG",
};

bool oom_cpuset_eligible_thread(struct task_struct *start,const nodemask_t *mask,bool ret)
{
	struct task_struct *tsk;
	for_each_thread(start, tsk) {
		if (mask){
			ret = mempolicy_in_oom_domain(tsk, mask);
		} else {
			ret = cpuset_mems_allowed_intersects(current, tsk);
		}
		if (ret)
			break;
	}
	return ret;
}

void rcu_read_lock_rust(void)
{
	return rcu_read_lock();
}

void rcu_read_unlock_rust(void)
{
	return rcu_read_unlock();
}

struct task_struct * find_lock_task_mm_thread(struct task_struct *p)
{
        struct task_struct *t;
        rcu_read_lock();
	for_each_thread(p, t) {
		//task_lock(t);
		if (likely(t->mm))
			goto found;
		//	task_unlock(t);
	}
        t = NULL;
found:
	rcu_read_unlock();

        return t;

}

int is_global_init_rust(struct task_struct *tsk)
{
	return is_global_init(tsk);
}

unsigned long global_node_page_state_rust(enum node_stat_item item)
{
	return global_node_page_state(item);
}

unsigned long global_node_page_state_pages_rust(enum node_stat_item item)
{
        return global_node_page_state_pages(item);
}

int test_bit_rust(int nr,const volatile unsigned long *vaddr)
{
	return test_bit(nr,vaddr);
}

bool in_vfork_rust(struct task_struct *tsk)
{
	return in_vfork(tsk);
}

void task_unlock_rust(struct task_struct *p)
{
	return task_unlock(p);
}

unsigned long get_mm_rss_rust(struct mm_struct *mm)
{
	return get_mm_rss(mm);
}

unsigned long get_mm_counter_rust(struct mm_struct *mm,int member)
{
        return get_mm_counter(mm,member);
}

unsigned long mm_pgtables_bytes_rust(const struct mm_struct *mm)
{
        return mm_pgtables_bytes(mm);
}

long pgsize_rust(void)
{
	return PAGE_SIZE;
}

enum zone_type gfp_zone_rust(gfp_t flags)
{
	return gfp_zone(flags);
}

unsigned long mem_cgroup_get_max_rust(struct mem_cgroup *memcg)
{
	return mem_cgroup_get_max(memcg);
}

bool is_enabled_numa_rust(void)
{
	return IS_ENABLED(CONFIG_NUMA);
}

int nodes_subset_rust(struct oom_control *oc)
{
	return nodes_subset(node_states[N_MEMORY], *oc->nodemask);
}

unsigned long totalram_pages_rust(void)
{
	return totalram_pages();
}

void for_each_node_mask_rust1(int nid,struct oom_control *oc)
{
	for_each_node_mask(nid, *oc->nodemask)
		oc->totalpages += node_present_pages(nid);
}

void for_each_node_mask_rust2(int nid,struct oom_control *oc)
{
        for_each_node_mask(nid,cpuset_current_mems_allowed)
                oc->totalpages += node_present_pages(nid);
}

bool for_each_zone_rust(struct oom_control *oc,enum zone_type highest_zoneidx)
{
	struct zone *zone;
	struct zoneref *z;
	for_each_zone_zonelist_nodemask(zone, z, oc->zonelist,
			highest_zoneidx, oc->nodemask)
		if (!cpuset_zone_allowed(zone, oc->gfp_mask))
			return true;

	return false;
}

void put_task_struct_rust(struct task_struct *t)
{
	return put_task_struct(t);
}

bool tsk_is_oom_victim_rust(struct task_struct *task)
{
	return tsk_is_oom_victim(task);
}

bool oom_task_origin_rust(const struct task_struct *p)
{
	return oom_task_origin(p); 
}

struct task_struct *get_task_struct_rust(struct task_struct *t)
{
	return get_task_struct(t);
}

struct task_struct *next_task_rust(struct task_struct *p)
{
	return next_task(p);
}

int likely_rust(struct mm_struct *m)
{
	return likely(m);
}

void pr_info_dump_task(struct task_struct *task)
{
	pr_info("[%7d] %5d %5d %8lu %8lu %8ld %8lu         %5hd %s\n",
		task->pid, from_kuid(&init_user_ns, task_uid(task)),
		task->tgid, task->mm->total_vm, get_mm_rss(task->mm),
		mm_pgtables_bytes(task->mm),
		get_mm_counter(task->mm, MM_SWAPENTS),
		task->signal->oom_score_adj, task->comm);
}

void dump_oom_summary_pr_info(struct oom_control *oc)
{
	pr_info("oom-kill:constraint=%s,nodemask=%*pbl",
			oom_constraint_text[oc->constraint],
			nodemask_pr_args(oc->nodemask));
}

void pr_cont_dump_summary(struct task_struct *victim)
{
	pr_cont(",task=%s,pid=%d,uid=%d\n", victim->comm, victim->pid,
		from_kuid(&init_user_ns, task_uid(victim)));
}

void pr_warn_dump_header(struct oom_control *oc)
{
	pr_warn("%s invoked oom-killer: gfp_mask=%#x(%pGg), order=%d, oom_score_adj=%hd\n",current->comm, oc->gfp_mask, &oc->gfp_mask, oc->order, current->signal->oom_score_adj);

	if (!IS_ENABLED(CONFIG_COMPACTION) && oc->order)
		pr_warn("COMPACTION is disabled!!!\n");
}

atomic_t atomic_init_rust(int i)
{
	atomic_t a= ATOMIC_INIT(i);
	return a;
}

struct wait_queue_head declare_wait_queue_head_rust(void)
{
	DECLARE_WAIT_QUEUE_HEAD(oom_victims_wait);
	return oom_victims_wait;
}

bool process_shares_mm_thread(struct task_struct *p, struct mm_struct *mm)
{

	struct task_struct *t;

	for_each_thread(p, t) {
		struct mm_struct *t_mm = READ_ONCE(t->mm);
		if (t_mm){
			if(t_mm == mm){
			 	return true;
			}
		}
	}
	return false;
}

void set_bit_rust(unsigned long *addr)
{
	set_bit(MMF_UNSTABLE,addr);
}

void set_bit_rust_skip(unsigned long *addr)
{
	set_bit(MMF_OOM_SKIP,addr);
}

bool can_madv_lru_vma_rust(struct vm_area_struct *vma)
{
	return can_madv_lru_vma(vma);
}

bool vma_is_anonymous_rust(struct vm_area_struct *vma)
{
	return vma_is_anonymous(vma);
}

struct mmu_notifier_range mmu_notifier_range_init_rust(enum mmu_notifier_event event,unsigned flags, struct vm_area_struct *vma,struct mm_struct *mm,unsigned long start,unsigned long end)
{
	struct mmu_notifier_range range;
	mmu_notifier_range_init(&range,event,flags,vma,mm,start,end);
	return range;
}

struct mmu_gather tlb_gather_mmu_rust(struct mm_struct *mm)
{
	struct mmu_gather tlb;
	tlb_gather_mmu(&tlb, mm);
	return tlb;
}

int mmu_notifier_invalidate_range_start_nonblock_rust(struct mmu_notifier_range *range)
{
	return mmu_notifier_invalidate_range_start_nonblock(range);
}

void mmu_notifier_invalidate_range_end_rust(struct mmu_notifier_range *range){
	mmu_notifier_invalidate_range_end(range);
}

void unmap_page_range_rust(struct mmu_gather *tlb,
			     struct vm_area_struct *vma,
			     unsigned long addr, unsigned long end)
{
	unmap_page_range(tlb, vma, addr, end, NULL);
}

bool mmap_read_trylock_rust(struct mm_struct *mm)
{
	return mmap_read_trylock(mm);
}

void trace_skip_task_reaping_rust(pid_t pid)
{
	trace_skip_task_reaping(pid);
}

void trace_finish_task_reaping_rust(pid_t pid)
{
	trace_finish_task_reaping(pid);
}

void mmap_read_unlock_rust(struct mm_struct *mm)
{
	mmap_read_unlock(mm);
}

void trace_start_task_reaping_rust(pid_t pid)
{
	trace_start_task_reaping(pid);
}

#define K(x) ((x) << (PAGE_SHIFT-10))

void pr_info_oom_reap_task_mm(struct task_struct *tsk, struct mm_struct *mm){
	pr_info("oom_reaper: reaped process %d (%s), now anon-rss:%lukB, file-rss:%lukB, shmem-rss:%lukB\n",
			task_pid_nr(tsk), tsk->comm,
			K(get_mm_counter(mm, MM_ANONPAGES)),
			K(get_mm_counter(mm, MM_FILEPAGES)),
			K(get_mm_counter(mm, MM_SHMEMPAGES)));
}

void pr_info_reap_task(struct task_struct *tsk)
{
	pr_info("oom_reaper: unable to reap pid:%d (%s)\n",
		task_pid_nr(tsk), tsk->comm);
}

void debug_show_all_locks_rust(void)
{
	debug_show_all_locks();
}

void wait_event_freezable_rust(void)
{
	wait_event_freezable(oom_reaper_wait,oom_reaper_list != NULL);
}

void spin_lock_rust(void)
{
	spin_lock(&oom_reaper_lock);
}

void spin_unlock_rust(void)
{
	spin_unlock(&oom_reaper_lock);
}

int test_and_set_bit_rust(unsigned long *addr)
{
	return test_and_set_bit(MMF_OOM_REAP_QUEUED,addr);
}

void trace_wake_reaper_rust(pid_t p)
{
	trace_wake_reaper(p);
}

void wake_up_rust()
{
	wake_up(&oom_reaper_wait);
}

struct task_struct *kthread_run_rust(int (*threadfn)(void *data))
{

	struct task_struct *thread = kthread_run(threadfn, NULL, "oom_reaper");
	return thread;
}

void warn_on_rust()
{
	WARN_ON(oom_killer_disabled);
}

int test_and_set_tsk_thread_flag_rust(struct task_struct *tsk)
{
	return test_and_set_tsk_thread_flag(tsk, TIF_MEMDIE);
}

int cmpxchg_rust(struct task_struct *tsk,struct mm_struct *m2)
{
	 int i = cmpxchg(&tsk->signal->oom_mm, NULL, m2);
	 return i;
}

void mmgrab_rust(struct mm_struct *mm)
{
	mmgrab(mm);
}

void set_bit_victim(unsigned long *addr)
{
	set_bit(MMF_OOM_VICTIM, addr);
}

void atomic_inc_rust()
{
	atomic_inc(&oom_victims);
}

void trace_mark_victim_rust(pid_t t)
{
	trace_mark_victim(t);
}

void clear_thread_flag_rust()
{
	clear_thread_flag(TIF_MEMDIE);
}

int atomic_dec_return_rust()
{
	int i = atomic_dec_return(&oom_victims);
	return i;
}

void wake_up_all_rust()
{
	wake_up_all(&oom_victims_wait);
}

void pr_info_oom_killer_enable()
{
	pr_info("OOM killer enabled.\n");
}

void pr_info_oom_killer_disable()
{
	pr_info("OOM killer disabled.\n");
}

int mutex_lock_killable_rust()
{
	int i = mutex_lock_killable(&oom_lock);
	return i;
}

void mutex_unlock_rust()
{
	mutex_unlock(&oom_lock);
}

signed long wait_event_interruptible_timeout_rust(signed long timeout)
{
signed long ret=wait_event_interruptible_timeout(oom_victims_wait,
			!atomic_read(&oom_victims), timeout);
	return ret;
}

int thread_group_empty_rust(struct task_struct *task)
{
	return thread_group_empty(task);
}

int atomic_read_rust(const atomic_t *v)
{
	return atomic_read(v);
}

bool same_thread_group_rust(struct task_struct *p1, struct task_struct *p2)
{
	return same_thread_group(p1,p2);
}

void print__oom_kill(struct task_struct *victim, const char *message)
{
	pr_info("%s: OOM victim %d (%s) is already exiting. Skip killing the task\n",
			message, task_pid_nr(victim), victim->comm);
}

void count_vm_event_rust()
{
	count_vm_event(OOM_KILL);
}

void memcg_memory_event_mm_rust(struct mm_struct *mm)
{
	memcg_memory_event_mm(mm, MEMCG_OOM_KILL);
}

void do_send_sig_info_rust(struct task_struct *victim)
{
	do_send_sig_info(SIGKILL, SEND_SIG_PRIV, victim, PIDTYPE_TGID);
}

void pr_err_oom(struct task_struct *victim,struct mm_struct *mm,const char *message)
{
	pr_err("%s: Killed process %d (%s) total-vm:%lukB, anon-rss:%lukB, file-rss:%lukB, shmem-rss:%lukB, UID:%u pgtables:%lukB oom_score_adj:%hd\n",
		message, task_pid_nr(victim), victim->comm, K(mm->total_vm),
		K(get_mm_counter(mm, MM_ANONPAGES)),
		K(get_mm_counter(mm, MM_FILEPAGES)),
		K(get_mm_counter(mm, MM_SHMEMPAGES)),
		from_kuid(&init_user_ns, task_uid(victim)),
		mm_pgtables_bytes(mm) >> 10, victim->signal->oom_score_adj);

}

void print__oom_kill_2(struct task_struct *victim,struct task_struct *p)
{
	pr_info("oom killer %d (%s) has mm pinned by %d (%s)\n",
					task_pid_nr(victim), victim->comm,
					task_pid_nr(p), p->comm);
}

int unlikely_rust(struct task_struct *p)
{
	int i = 0;
	i = unlikely(p->flags & PF_KTHREAD);
	return i;
}

void mmdrop_rust(struct mm_struct *mm)
{
	mmdrop(mm);
}

struct ratelimit_state define_ratelimit_state_rust()
{
	DEFINE_RATELIMIT_STATE(oom_rs, DEFAULT_RATELIMIT_INTERVAL,
					      DEFAULT_RATELIMIT_BURST);
	return oom_rs;
}

void task_lock_rust(struct task_struct *victim)
{
	task_lock(victim);
}

int ratelimit(struct ratelimit_state *rs)
{
	return __ratelimit(rs);
}

void mem_cgroup_put_rust(struct mem_cgroup *oom_group)
{
	mem_cgroup_put(oom_group);
}

int like_rust(int i)
{
	return likely(i);
}

struct task_struct *get_current_rust()
{
	return get_current();
}

int fatal_signal_pending_rust(struct task_struct *p)
{
	return fatal_signal_pending(p);
}

void pr_info_1()
{
	pr_info("111111111111\n");
}

struct task_struct *find_lock_task_mm_rust(struct task_struct *p)
{
	return find_lock_task_mm(p);
}

void dump_task_pr_info(){
	pr_info("Tasks state (memory values in pages):\n");
	pr_info("[  pid  ]   uid  tgid total_vm      rss pgtables_bytes swapents oom_score_adj name\n");
}



void __oom_kill_process_for(struct task_struct *victim,const char *message,bool can_oom_reap,struct task_struct *p,struct mm_struct *mm)
{

}

void oom_reap_task_null(struct task_struct *tsk)
{
	tsk->oom_reaper_list = NULL;
}


void nodemask_null(struct oom_control *oc)
{
	oc->nodemask = NULL;
}


void mmgrab_tsk(struct task_struct *tsk)
{
      mmgrab(tsk->signal->oom_mm);
}

void out_of_memory_panic()
{
	panic("System is deadlocked on memory\n");
}

void hello_lili()
{
	pr_info("hello lilinhan");
}
