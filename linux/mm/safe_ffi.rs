#![no_std]
use kernel::bindings;
use kernel::bindings::{task_struct,mm_struct,oom_control};
use kernel::c_types::c_void;

pub(crate) fn print_1()
{
    unsafe{
        kernel::bindings::hello_lili();
    }
}

pub(crate) fn rcu_read_lock_oom()
{
    unsafe{
        bindings::rcu_read_lock_rust();
    }
}

pub(crate) fn rcu_read_unlock_oom()
{
    unsafe{
        bindings::rcu_read_unlock_rust();
    }
}


pub(crate) fn oom_cpuset_eligible_thread_safe(start:&mut bindings::task_struct,mask:*const bindings::nodemask_t,ret:bool)->bool
{
    unsafe{
        return bindings::oom_cpuset_eligible_thread(start as *mut bindings::task_struct, mask, ret);
    }
}

pub(crate) fn find_lock_task_mm_thread_safe(p:&mut bindings::task_struct)->*mut bindings::task_struct
{
    unsafe{
        return bindings::find_lock_task_mm_thread(p as *mut bindings::task_struct);
    }
}

pub(crate) fn is_global_init_rust_safe(p:&mut task_struct)-> i32
{
    unsafe{
        return  bindings::is_global_init_rust(p as *mut task_struct);
    }
}

pub(crate) fn global_node_page_state_rust_safe(item:bindings::node_stat_item) -> u64
{
    unsafe{
        return bindings::global_node_page_state_rust(item);
    }
}

pub(crate) fn global_node_page_state_pages_rust_safe(item:bindings::node_stat_item) -> u64
{
    unsafe{
        return bindings::global_node_page_state_pages_rust(item);
    }
}

pub(crate) fn task_unlock_rust_safe(p:&mut task_struct)
{
    unsafe{
        bindings::task_unlock_rust(p as *mut task_struct);
    }
}

pub(crate) fn pgsize_rust_safe()->i64
{
    unsafe{
        return bindings::pgsize_rust();
    }
}

pub(crate) fn get_mm_rss_rust_safe(mm:&mut mm_struct) -> u64
{
    unsafe{
        return bindings::get_mm_rss_rust(mm as *mut mm_struct);
    }
}

pub(crate) fn get_mm_counter_rust_safe(mm:&mut mm_struct,i:i32) -> u64
{
    unsafe{
        return bindings::get_mm_counter_rust(mm as *mut mm_struct, i);
    }
}

pub(crate) fn mm_pgtables_bytes_rust_safe(mm:&mut mm_struct)->u64
{
    unsafe{
        return bindings::mm_pgtables_bytes_rust(mm as *mut mm_struct);
    }
}

pub(crate) fn test_bit_rust_safe(i:i32,flag:&mut u64)->i32
{
    unsafe{
        return bindings::test_bit_rust(i,flag as *mut u64);
    }
}

pub(crate) fn in_vfork_rust_safe(p:&mut task_struct)->bool
{
    unsafe{
         return bindings::in_vfork_rust(p);
    }
}

pub(crate) fn gfp_zone_rust_safe(flags:bindings::gfp_t) -> bindings::zone_type
{
    unsafe{
        return bindings::gfp_zone_rust(flags);
    }
}

pub(crate) fn mem_cgroup_get_max_rust_safe(memcg:&mut bindings::mem_cgroup)->u64
{
    unsafe{
        return bindings::mem_cgroup_get_max_rust(memcg as *mut bindings::mem_cgroup);
    }
}

pub(crate) fn totalram_pages_rust_safe()->u64
{
    unsafe{
        return bindings::totalram_pages_rust();
    }
}

pub(crate) fn is_enabled_numa_rust_safe()->bool
{
    unsafe{
        return bindings::is_enabled_numa_rust();
    }
}

pub(crate) fn nodes_subset_rust_safe(oc:&mut oom_control)->i32
{
    unsafe{
        return bindings::nodes_subset_rust(oc as *mut oom_control);
    }
}

pub(crate) fn for_each_node_mask_rust1_safe(nid:i32 ,oc:&mut oom_control)
{
    unsafe{
        bindings::for_each_node_mask_rust1(nid,oc as *mut oom_control);
    }
}

pub(crate) fn for_each_zone_rust_safe(oc:&mut oom_control,zone:bindings::zone_type)->bool
{
    unsafe{
        return bindings::for_each_zone_rust(oc as *mut oom_control,zone);
    }
}

pub(crate) fn for_each_node_mask_rust2_safe(nid:i32, oc:&mut oom_control)
{
    unsafe{
        bindings::for_each_node_mask_rust2(nid,oc as *mut oom_control);
    }
}

pub(crate) fn tsk_is_oom_victim_rust_safe(task:&mut task_struct)->bool
{
    unsafe{
        return bindings::tsk_is_oom_victim_rust(task as *mut task_struct);
    }
}

pub(crate) fn put_task_struct_safe(task:*mut task_struct)
{
    unsafe{
        bindings::put_task_struct_rust(task);
    }
}

pub(crate) fn oom_task_origin_rust_safe(task:&mut task_struct)->bool
{
    unsafe{
        return bindings::oom_task_origin_rust(task as *mut task_struct);
    }
}

pub(crate) fn get_task_struct_rust_safe(task:&mut task_struct)->*mut task_struct
{
    unsafe{
        return bindings::get_task_struct_rust(task as *mut task_struct);
    }
}

pub(crate) fn next_task_rust_safe(task:*mut task_struct)->*mut task_struct
{
    unsafe{
        return bindings::next_task_rust(task);
    }
}

pub(crate) fn pr_info_dump_task_safe(task:&mut task_struct)
{
    unsafe{
        bindings::pr_info_dump_task(task as *mut task_struct);
    }
}

pub(crate) fn dump_task_pr_info_safe()
{
    unsafe{
        bindings::dump_task_pr_info();
    }
}

pub(crate) fn dump_oom_summary_pr_info_safe(oc:&mut oom_control)
{
    unsafe{
        bindings::dump_oom_summary_pr_info(oc as *mut oom_control);
    }
}

pub(crate) fn cpuset_print_current_mems_allowed_safe()
{
    unsafe{
        bindings::cpuset_print_current_mems_allowed();
    }
}

pub(crate) fn mem_cgroup_print_oom_context_safe(memcg:*mut bindings::mem_cgroup,task:&mut task_struct)
{
    unsafe{
        bindings::mem_cgroup_print_oom_context(memcg,task as *mut task_struct);
    }
}

pub(crate) fn pr_cont_dump_summary_safe(task:&mut task_struct)
{
    unsafe{
        bindings::pr_cont_dump_summary(task as *mut task_struct);
    }
}

pub(crate) fn pr_warn_dump_header_safe(oc:&mut oom_control)
{
    unsafe{
        bindings::pr_warn_dump_header(oc as *mut oom_control);
    }
}

pub(crate) fn dump_stack_safe()
{
    unsafe{
        bindings::dump_stack();
    }
}

pub(crate) fn mem_cgroup_print_oom_meminfo_safe(memcg:*mut bindings::mem_cgroup)
{
    unsafe{
        bindings::mem_cgroup_print_oom_meminfo(memcg);
    }
}

pub(crate) fn show_mem_safe(flag:u32, mask:*mut bindings::nodemask_t)
{
    unsafe{
        bindings::show_mem(flag ,mask);
    }
}

pub(crate) fn dump_unreclaimable_slab_safe()
{
    unsafe{
        bindings::dump_unreclaimable_slab();
    }
}

pub(crate) fn process_shares_mm_thread_safe(task:*mut task_struct,mm:*mut mm_struct)->bool
{
    unsafe{
        return bindings::process_shares_mm_thread(task,mm);
    }
}

pub(crate) fn set_bit_rust_safe(addr:*mut u64)
{
    unsafe{
        bindings::set_bit_rust(addr);
    }
}

pub(crate) fn vma_is_anonymous_rust_safe(vma:&mut bindings::vm_area_struct)->bool
{
    unsafe{
        return bindings::vma_is_anonymous_rust(vma);
    }
}

pub(crate) fn mmu_notifier_range_init_rust_safe(event:bindings::mmu_notifier_event, flags:u32,vma:&mut bindings::vm_area_struct,mm:&mut mm_struct,start:u64,end:u64)->bindings::mmu_notifier_range
{
    unsafe{
        return bindings:: mmu_notifier_range_init_rust(event,flags,vma as *mut bindings::vm_area_struct,mm as *mut mm_struct,start,end);
    }
}

pub(crate) fn tlb_gather_mmu_rust_safe(mm:&mut mm_struct)->bindings::mmu_gather
{
    unsafe{
        return bindings::tlb_gather_mmu_rust(mm as *mut mm_struct);
    }
}

pub(crate) fn mmu_notifier_invalidate_range_start_nonblock_rust_safe(range:&mut bindings::mmu_notifier_range)->i32
{
    unsafe{
        return bindings::mmu_notifier_invalidate_range_start_nonblock_rust(range as *mut bindings::mmu_notifier_range);
    }
}

pub(crate) fn tlb_finish_mmu_safe(tlb:&mut bindings::mmu_gather)
{
    unsafe{
        bindings::tlb_finish_mmu(tlb as *mut bindings::mmu_gather);
    }
}

pub(crate) fn unmap_page_range_rust_safe(tlb:&mut bindings::mmu_gather,vma:&mut bindings::vm_area_struct,addr:u64,end:u64)
{
    unsafe{
        return bindings::unmap_page_range_rust(tlb as *mut bindings::mmu_gather,vma as *mut bindings::vm_area_struct,addr,end);
    }
}

pub(crate) fn mmu_notifier_invalidate_range_end_rust_safe(range:&mut bindings::mmu_notifier_range)
{
    unsafe{
        bindings::mmu_notifier_invalidate_range_end_rust(range as *mut bindings::mmu_notifier_range);
    }
}

pub(crate) fn can_madv_lru_vma_rust_safe(vma:&mut bindings::vm_area_struct)->bool
{
    unsafe{
        return bindings::can_madv_lru_vma_rust(vma as *mut bindings::vm_area_struct);
    }
}


pub(crate) fn mmap_read_trylock_rust_safe(mm:&mut mm_struct) -> bool
{
    unsafe{
        return bindings::mmap_read_trylock_rust(mm as *mut mm_struct);
    }
}

pub(crate) fn trace_skip_task_reaping_rust_safe(pid:bindings::pid_t)
{
    unsafe{
        bindings::trace_skip_task_reaping_rust(pid);
    }
}

pub(crate) fn mmap_read_unlock_rust_safe(mm:&mut mm_struct)
{
    unsafe{
        bindings::mmap_read_unlock_rust(mm as *mut mm_struct);
    }
}

pub(crate) fn trace_start_task_reaping_rust_safe(pid:bindings::pid_t)
{
    unsafe{
        bindings::trace_start_task_reaping_rust(pid);
    }
}

pub(crate) fn trace_finish_task_reaping_rust_safe(pid:bindings::pid_t)
{
    unsafe{
        bindings::trace_finish_task_reaping_rust(pid);
    }
}

pub(crate) fn pr_info_oom_reap_task_mm_safe(task:&mut task_struct,mm:&mut mm_struct)
{
    unsafe{
        bindings::pr_info_oom_reap_task_mm(task as *mut task_struct,mm as *mut mm_struct);
    }
}

pub(crate) fn schedule_timeout_idle_safe(i:i64)
{
    unsafe{
        bindings::schedule_timeout_idle(i);
    }
}

pub(crate) fn set_bit_rust_skip_safe(long:&mut u64)
{
    unsafe{
        bindings::set_bit_rust_skip(long as *mut u64);
    }
}

pub(crate) fn pr_info_reap_task_safe(task:&mut task_struct)
{
    unsafe{
        bindings::pr_info_reap_task(task as *mut task_struct);
    }
}

pub(crate) fn sched_show_task_safe(task:&mut task_struct)
{
    unsafe{
        bindings::sched_show_task(task as *mut task_struct);
    }
}

pub(crate) fn debug_show_all_locks_rust_safe()
{
    unsafe{
        bindings::debug_show_all_locks_rust();
    }
}

pub(crate) fn wait_event_freezable_rust_safe()
{
    unsafe{
        bindings::wait_event_freezable_rust();
    }
}
pub(crate) fn spin_lock_rust_safe()
{
    unsafe{
        bindings::spin_lock_rust();
    }
}

pub(crate) fn spin_unlock_rust_safe()
{
    unsafe{
        bindings::spin_unlock_rust();
    }
}

pub(crate) fn trace_wake_reaper_rust_safe(p:bindings::pid_t)
{
    unsafe{
        bindings::trace_wake_reaper_rust(p);
    }
}
pub(crate) fn wake_up_rust_safe()
{
    unsafe{
        bindings::wake_up_rust();
    }
}

pub(crate) fn test_and_set_bit_rust_safe(i:*mut u64)->i32
{
    unsafe{
        return bindings::test_and_set_bit_rust(i);
    }
}

pub(crate) fn warn_on_rust_safe()
{
    unsafe{
        bindings::warn_on_rust();
    }
}

pub(crate) fn test_and_set_tsk_thread_flag_rust_safe(tsk:&mut task_struct)->i32
{
    unsafe{
        return bindings::test_and_set_tsk_thread_flag_rust(tsk as *mut task_struct);
    }
}

pub(crate) fn cmpxchg_rust_safe(tsk:&mut task_struct, mm:&mut mm_struct)->i32
{
    unsafe{
        return bindings::cmpxchg_rust(tsk as *mut task_struct,mm as *mut mm_struct);
    }
}

pub(crate) fn mmgrab_tsk_safe(task:&mut task_struct)
{
    unsafe{
        bindings::mmgrab_tsk(task as *mut task_struct);
    }
}

pub(crate) fn set_bit_victim_safe(i:&mut u64)
{
    unsafe{
        bindings::set_bit_victim(i as *mut u64);
    }
}

pub(crate) fn __thaw_task_safe(tsk:&mut task_struct)
{
    unsafe{
        bindings::__thaw_task(tsk as *mut task_struct);
    }
}

pub(crate) fn atomic_inc_rust_safe()
{
    unsafe{
        bindings::atomic_inc_rust();
    }
}

pub(crate) fn trace_mark_victim_rust_safe(p:bindings::pid_t)
{
    unsafe{
        bindings::trace_mark_victim_rust(p);
    }
}

pub(crate) fn clear_thread_flag_rust_safe()
{
    unsafe{
        bindings::clear_thread_flag_rust();
    }
}

pub(crate) fn atomic_dec_return_rust_safe()->i32
{
    unsafe{
        return bindings::atomic_dec_return_rust();
    }
}

pub(crate) fn wake_up_all_rust_safe()
{
    unsafe{
        bindings::wake_up_all_rust();
    }
}

pub(crate) fn pr_info_oom_killer_enable_safe()
{
    unsafe{
        bindings::pr_info_oom_killer_enable();
    }
}

pub(crate) fn mutex_lock_killable_rust_safe()->i32
{
    unsafe{
        return bindings::mutex_lock_killable_rust();
    }
}

pub(crate) fn mutex_unlock_rust_safe()
{
    unsafe{
        bindings::mutex_unlock_rust();
    }
}

pub(crate) fn wait_event_interruptible_timeout_rust_safe(time:i64)->i64
{
    unsafe{
        return bindings::wait_event_interruptible_timeout_rust(time);
    }
}

pub(crate) fn pr_info_oom_killer_disable()
{
    unsafe{
        bindings::pr_info_oom_killer_disable();
    }
}

pub(crate) fn thread_group_empty_rust_safe(tsk:&mut task_struct)->i32
{
    unsafe{
        return bindings::thread_group_empty_rust(tsk as *mut task_struct);
    }
}

pub(crate) fn atomic_read_rust_safe(v:&bindings::atomic_t)->i32
{
    unsafe{
        return bindings::atomic_read_rust(v as *const bindings::atomic_t);
    }
}

pub(crate) fn same_thread_group_rust_safe(p1:&mut task_struct,p2:*mut task_struct)-> bool
{
    unsafe{
        return bindings::same_thread_group_rust(p1 as *mut task_struct,p2);
    }
}

pub(crate) fn print__oom_kill_safe(task:&mut task_struct,message:*const i8)
{
    unsafe{
        bindings::print__oom_kill(task as *mut task_struct,message);
    }
}

pub(crate) fn mmgrab_rust_safe(mm:&mut mm_struct)
{
    unsafe{
        bindings::mmgrab_rust(mm as *mut mm_struct);
    }
}

pub(crate) fn count_vm_event_rust_safe()
{
    unsafe{
        bindings::count_vm_event_rust();
    }
}

pub(crate) fn memcg_memory_event_mm_rust_safe(mm:&mut mm_struct)
{
    unsafe{
        bindings::memcg_memory_event_mm_rust(mm as *mut mm_struct);
    }
}

pub(crate) fn do_send_sig_info_rust_safe(tsk:&mut task_struct)
{
    unsafe{
        bindings::do_send_sig_info_rust(tsk as *mut task_struct);
    }
}

pub(crate) fn pr_err_oom_safe(task:&mut task_struct,mm:&mut mm_struct,message:*const i8)
{
    unsafe{
        bindings::pr_err_oom(task as *mut task_struct ,mm as *mut mm_struct,message as *const i8);
    }
}

pub(crate) fn print__oom_kill_2_safe(t1:&mut task_struct,t2:&mut task_struct)
{
    unsafe{
        bindings::print__oom_kill_2(t1 as *mut task_struct,t2 as *mut task_struct);
    }
}

pub(crate) fn unlikely_rust_safe(q:&mut task_struct)->i32
{
    unsafe{
        return bindings::unlikely_rust(q as *mut task_struct);
    }
}

pub(crate) fn mmdrop_rust_safe(mm:&mut mm_struct)
{
    unsafe{
        bindings::mmdrop_rust(mm as *mut mm_struct);
    }
}

pub(crate) fn define_ratelimit_state_rust_safe()->bindings::ratelimit_state
{
    unsafe{
        return bindings::define_ratelimit_state_rust();
    }
}

pub(crate) fn task_lock_rust_safe(tsk:&mut task_struct)
{
    unsafe{
        bindings::task_lock_rust(tsk as *mut task_struct);
    }
}

pub(crate) fn ratelimit_safe(rs:&mut bindings::ratelimit_state)->i32
{
    unsafe{
        return bindings::ratelimit(rs as *mut bindings::ratelimit_state);
    }
}

pub(crate) fn mem_cgroup_get_oom_group_safe(tsk:&mut task_struct,memcg:*mut bindings::mem_cgroup)->*mut bindings::mem_cgroup
{
    unsafe{
        return bindings::mem_cgroup_get_oom_group(tsk as *mut task_struct,memcg);
    }
}

pub(crate) fn mem_cgroup_print_oom_group_safe(oom:*mut bindings::mem_cgroup)
{
    unsafe{
        bindings::mem_cgroup_print_oom_group(oom);
    }
}

pub(crate) fn mem_cgroup_put_rust_safe(oom:*mut bindings::mem_cgroup)
{
    unsafe{
        bindings::mem_cgroup_put_rust(oom);
    }
}

pub(crate) fn blocking_notifier_chain_register_safe(nh:*mut bindings::blocking_notifier_head,nb:*mut bindings::notifier_block)->i32
{
    unsafe{
        return bindings::blocking_notifier_chain_register(nh, nb);
    }
}

pub(crate) fn blocking_notifier_chain_unregister_safe(nh:*mut bindings::blocking_notifier_head,nb:*mut bindings::notifier_block)->i32
{
    unsafe{
        return bindings::blocking_notifier_chain_unregister(nh, nb);
    }
}

pub(crate) fn blocking_notifier_call_chain_safe(nh:&mut bindings::blocking_notifier_head,i:u64,v:*mut c_void)
{
    unsafe{
         bindings::blocking_notifier_call_chain(nh as *mut bindings::blocking_notifier_head, i, v);
    }
}

pub(crate) fn get_current_rust_safe()->*mut task_struct
{
    unsafe{
        return bindings::get_current_rust();
    }
}

pub(crate) fn out_of_memory_panic_safe()
{
    unsafe{
        bindings::out_of_memory_panic();
    }
}

pub(crate) fn mem_cgroup_oom_synchronize_safe(i:bool)->bool
{
    unsafe{
        return bindings::mem_cgroup_oom_synchronize(i);
    }
}

pub(crate) fn fatal_signal_pending_rust_safe(p:*mut task_struct)->i32
{
    unsafe{
        return bindings::fatal_signal_pending_rust(p);
    }
}
