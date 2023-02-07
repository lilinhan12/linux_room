#![no_std]

//include!(concat!(env!("OUT_DIR"), "/safe_ffi.rs"));
//include!("safe_ffi.rs");
mod safe_ffi;
use kernel::{ bindings, c_types };
use core::ptr;
use kernel::bindings::{ task_struct, oom_control, mm_struct ,pid_t, signal_struct,pr_info_1};
use kernel::c_types::{ c_void, c_char};
use kernel::prelude::*;

static mut sysctl_panic_on_oom:i32=0;

static mut sysctl_oom_kill_allocating_task:i32=0;

static mut sysctl_oom_dump_tasks:i32 = 1;

fn find_lock_task_mm(p:*mut task_struct)->*mut bindings::task_struct{

    let mut t:*mut task_struct = unsafe{bindings::find_lock_task_mm_thread(p)};

    return t;

}

#[cfg(CONFIG_NUMA)]
fn oom_cpuset_eligible(start:&mut task_struct,oc_rust:&mut oom_control) -> bool{

    let mut ret:bool=false;
    if !(oc_rust.memcg.is_null()){
        return true;
    }

    let mask:*const bindings::nodemask_t = (oc_rust.nodemask);

    safe_ffi::rcu_read_lock_oom();
    ret= safe_ffi::oom_cpuset_eligible_thread_safe(start, mask, ret);
    safe_ffi::rcu_read_unlock_oom();

    return ret;
}

#[cfg(not(CONFIG_NUMA))]
fn oom_cpuset_eligible(start:&mut task_struct,oc:&mut oom_control) -> bool
{
    return true;
}

#[no_mangle]
pub extern "C" fn oom_badness_rust(mut p_rust:&mut task_struct,totalpages:u64) -> i64{

    let mut points:i64;
    let mut adj:i64 = 0;
    let mut mm_flags:u64 = 0;

    if safe_ffi::is_global_init_rust_safe(p_rust) != 0{
        return i64::MIN;
    }

    if (p_rust.flags & bindings::PF_KTHREAD) != 0{
        return i64::MIN;;
    }

    let mut p:*mut task_struct = safe_ffi::find_lock_task_mm_thread_safe(p_rust);

    safe_ffi::rcu_read_unlock_oom();

    if p.is_null(){
        return i64::MIN;
    }
    let mut p_ref:&mut task_struct = unsafe{p.as_mut().unwrap()};

    let mut signal_rust:&mut bindings::signal_struct = unsafe{p_rust.signal.as_mut().unwrap()};
    adj = signal_rust.oom_score_adj as i64;

    let mut mm_rust:&mut mm_struct = unsafe{p_rust.mm.as_mut().unwrap()};

    mm_flags = mm_rust.__bindgen_anon_1.flags;


    if adj == bindings::OOM_SCORE_ADJ_MIN as i64 || safe_ffi::test_bit_rust_safe(bindings::MMF_OOM_SKIP as i32, &mut mm_flags) !=0 || safe_ffi::in_vfork_rust_safe(p_ref){
        safe_ffi::task_unlock_rust_safe(p_ref);
            return i64::MIN;
        }


    let page_size = safe_ffi::pgsize_rust_safe();
    points = (safe_ffi::get_mm_rss_rust_safe(mm_rust) + safe_ffi::get_mm_counter_rust_safe(mm_rust, unsafe{bindings::MM_SWAPENTS as i32}) + safe_ffi::mm_pgtables_bytes_rust_safe(mm_rust)/(page_size as u64)) as i64;
    safe_ffi::task_unlock_rust_safe(p_ref);

    adj *= (totalpages / 1000) as i64;
    points += adj;

    return points;

}

fn constrained_alloc(mut oc_rust:&mut oom_control)->bindings::oom_constraint{

    let mut cpuset_limited:bool = false;
    let mut nid = 0;

    let mut highest_zoneidx:bindings::zone_type = safe_ffi::gfp_zone_rust_safe(oc_rust.gfp_mask);

    if !(oc_rust.memcg.is_null()){
        let mut memcg_ref:&mut bindings::mem_cgroup = unsafe{(oc_rust.memcg).as_mut().unwrap()};
        if safe_ffi::mem_cgroup_get_max_rust_safe(memcg_ref) != 0{
            oc_rust.totalpages = safe_ffi::mem_cgroup_get_max_rust_safe(memcg_ref);
        }
        else{
            oc_rust.totalpages = 1;
        }

        return bindings::oom_constraint_CONSTRAINT_MEMCG;
    }
    oc_rust.totalpages = safe_ffi::totalram_pages_rust_safe() + unsafe{bindings::total_swap_pages as u64};

    if !(safe_ffi::is_enabled_numa_rust_safe()){
            return bindings::oom_constraint_CONSTRAINT_NONE;
        }

        if (oc_rust.zonelist).is_null(){
            return bindings::oom_constraint_CONSTRAINT_NONE;
        }

        if (oc_rust.gfp_mask & bindings::___GFP_THISNODE) != 0{
            return bindings::oom_constraint_CONSTRAINT_NONE;
        }

    if !((oc_rust.nodemask).is_null()) && safe_ffi::nodes_subset_rust_safe(oc_rust)  == 0{
        oc_rust.totalpages = unsafe{ bindings::total_swap_pages as u64 };
        safe_ffi::for_each_node_mask_rust1_safe(nid, oc_rust);
        return bindings::oom_constraint_CONSTRAINT_MEMORY_POLICY;
    }

    cpuset_limited = safe_ffi::for_each_zone_rust_safe(oc_rust ,highest_zoneidx);

    if cpuset_limited{
        oc_rust.totalpages = unsafe{ bindings::total_swap_pages as u64 };
        safe_ffi::for_each_node_mask_rust2_safe(nid,oc_rust);
        return bindings::oom_constraint_CONSTRAINT_CPUSET;
    }

    return bindings::oom_constraint_CONSTRAINT_NONE;
}

#[no_mangle]
pub extern "C" fn oom_evaluate_task(task:*mut task_struct,arg:*mut c_types::c_void)->i32{


    let oc:*mut bindings::oom_control = arg as *mut bindings::oom_control;
    let mut oc_rust:&mut oom_control = unsafe{ oc.as_mut().unwrap() };
    let mut task_rust:&mut task_struct = unsafe{ task.as_mut().unwrap() };

    let mut points:i64 = 0;

    if safe_ffi::is_global_init_rust_safe(task_rust) != 0{
        return 0;
    }

    if (task_rust.flags & bindings::PF_KTHREAD) != 0{
        return 0;
    }

    if oc_rust.memcg.is_null() && !oom_cpuset_eligible(task_rust, oc_rust){
	return 0;
    }

    if !(oc_rust.order == -1) && safe_ffi::tsk_is_oom_victim_rust_safe(task_rust){
	if safe_ffi::test_bit_rust_safe(bindings::MMF_OOM_SKIP as i32,unsafe{&mut ((*((*((task_rust).signal)).oom_mm)).__bindgen_anon_1.flags)}) != 0 {
	    return 0;
	}
	if !((oc_rust.chosen).is_null()){
	    safe_ffi::put_task_struct_safe(oc_rust.chosen);
	}

	oc_rust.chosen = u64::MAX as *mut task_struct;
	return 1;
    }

    if safe_ffi::oom_task_origin_rust_safe(task_rust){
	points = i64::MAX;
	if !((oc_rust.chosen).is_null()){
	    safe_ffi::put_task_struct_safe(oc_rust.chosen);
	}

        safe_ffi::get_task_struct_rust_safe(task_rust);
	oc_rust.chosen = task;
	oc_rust.chosen_points = points;

    }

    points = oom_badness_rust(task_rust,oc_rust.totalpages);
    if points == i64::MIN || points < oc_rust.chosen_points{
	return 0;
    }

    if !((oc_rust.chosen).is_null()){
	safe_ffi::put_task_struct_safe(oc_rust.chosen);
    }
    safe_ffi::get_task_struct_rust_safe(task_rust);
    oc_rust.chosen = task;
    oc_rust.chosen_points = points;

    return 0;

}

fn select_bad_process(oc_rust:&mut bindings::oom_control){

    oc_rust.chosen_points = i64::MIN;

    if !oc_rust.memcg.is_null(){
        let foo:Option<unsafe extern "C" fn(*mut task_struct, *mut c_void) -> i32> = Some(oom_evaluate_task);
        unsafe{ bindings::mem_cgroup_scan_tasks(((oc_rust).memcg),foo,oc_rust as *mut oom_control as *mut c_types::c_void) };
    }
    else{
        safe_ffi::rcu_read_lock_oom();
        let p:*mut bindings::task_struct = unsafe{ &mut bindings::init_task };
        let mut q:*mut bindings::task_struct = safe_ffi::next_task_rust_safe(p);
        while(q != p){
            if oom_evaluate_task(q,oc_rust as *mut oom_control as *mut c_types::c_void) != 0{
                break;
            }
            q = safe_ffi::next_task_rust_safe(q);
        }
        safe_ffi::rcu_read_unlock_oom();
    }

}

#[no_mangle]
pub extern "C" fn dump_task(p:*mut task_struct,arg:*mut c_void)-> i32{

    let mut oc:*mut oom_control = arg as *mut bindings::oom_control;
    let mut oc_rust:&mut oom_control = unsafe{ oc.as_mut().unwrap() };
    let mut p_rust:&mut task_struct = unsafe{ p.as_mut().unwrap() };

    let mut task:*mut task_struct = find_lock_task_mm(p);

    if safe_ffi::is_global_init_rust_safe(p_rust) != 0{
        return 0;
    }

    if (p_rust.flags & bindings::PF_KTHREAD) != 0{
        return 0;
    }

    if oc_rust.memcg.is_null() && !oom_cpuset_eligible(p_rust, oc_rust){
        return 0;
    }

    if task.is_null(){
        return 0;
    }
    let mut task_ref:&mut task_struct = unsafe{task.as_mut().unwrap()};


    safe_ffi::pr_info_dump_task_safe(task_ref);
 //   unsafe{bindings::task_unlock_rust(task)};

    return 0;
}

fn dump_oom_summary(oc_rust:&mut oom_control,victim:&mut task_struct)
{

    safe_ffi::dump_oom_summary_pr_info_safe(oc_rust);
    safe_ffi::cpuset_print_current_mems_allowed_safe();
    safe_ffi::mem_cgroup_print_oom_context_safe((oc_rust).memcg,victim);
    safe_ffi::pr_cont_dump_summary_safe(victim);

}

//#[cfg(CONFIG_MMU)]
//#[no_mangle]
pub extern "C" fn __oom_reap_task_mm(mm_rust:&mut mm_struct)->bool
{

    let mut ret:bool = true;
    let mut flags:*mut u64 = &mut ((mm_rust).__bindgen_anon_1.flags);

    safe_ffi::set_bit_rust_safe(flags);
    let mut vma:*mut bindings::vm_area_struct = (mm_rust).__bindgen_anon_1.mmap;

    while(!vma.is_null()){
        let mut vma_rust:&mut bindings::vm_area_struct = unsafe{vma.as_mut().unwrap()};

        if (vma_rust.vm_flags & (bindings::VM_HUGETLB|bindings::VM_PFNMAP) as u64) != 0{
            vma = (vma_rust).vm_next;
            continue;
        }

        if safe_ffi::vma_is_anonymous_rust_safe(vma_rust) || !((vma_rust).vm_flags & bindings::VM_SHARED as u64) !=0{
            let mut range:bindings::mmu_notifier_range = safe_ffi::mmu_notifier_range_init_rust_safe(unsafe{bindings::mmu_notifier_event_MMU_NOTIFY_UNMAP},0,vma_rust,mm_rust,(vma_rust).vm_start,(vma_rust).vm_end);
            let mut tlb:bindings::mmu_gather = safe_ffi::tlb_gather_mmu_rust_safe(mm_rust);

            if safe_ffi::mmu_notifier_invalidate_range_start_nonblock_rust_safe(&mut range) !=0{
                safe_ffi::tlb_finish_mmu_safe(&mut tlb);
                ret = false;
                vma = (vma_rust).vm_next;
                continue;
            }
            safe_ffi::unmap_page_range_rust_safe(&mut tlb,vma_rust,(range).start,(range).end);
            safe_ffi::mmu_notifier_invalidate_range_end_rust_safe(&mut range);
            safe_ffi::tlb_finish_mmu_safe(&mut tlb);
        }

        vma = (vma_rust).vm_next;

    }

    return ret;

}

#[cfg(CONFIG_MMU)]
fn oom_reap_task_mm(tsk_rust:&mut task_struct,mm_rust:&mut mm_struct)->bool
{
    let mut ret:bool = true;

    if !safe_ffi::mmap_read_trylock_rust_safe(mm_rust){
        safe_ffi::trace_skip_task_reaping_rust_safe((tsk_rust).pid);
        return false;
    }

    let mut flags:&mut u64 = &mut ((mm_rust).__bindgen_anon_1.flags);

    if safe_ffi::test_bit_rust_safe(bindings::MMF_OOM_SKIP as i32,flags)!=0{
        safe_ffi::trace_skip_task_reaping_rust_safe((tsk_rust).pid);
        safe_ffi::mmap_read_unlock_rust_safe(mm_rust);
        return ret;
    }

    safe_ffi::trace_start_task_reaping_rust_safe((tsk_rust).pid);

    let mut flag:*mut u64 = &mut ((mm_rust).__bindgen_anon_1.flags);
    safe_ffi::set_bit_rust_safe(flag);
    let mut vma:*mut bindings::vm_area_struct = (mm_rust).__bindgen_anon_1.mmap;

    while(!vma.is_null()){
        let mut vma_rust:&mut bindings::vm_area_struct = unsafe{vma.as_mut().unwrap()};

        if (vma_rust.vm_flags & (bindings::VM_HUGETLB|bindings::VM_PFNMAP) as u64) != 0{
            vma = (vma_rust).vm_next;
            continue;
        }

        if safe_ffi::vma_is_anonymous_rust_safe(vma_rust) || !((vma_rust).vm_flags & bindings::VM_SHARED as u64) !=0{
            let mut range:bindings::mmu_notifier_range = safe_ffi::mmu_notifier_range_init_rust_safe(unsafe{bindings::mmu_notifier_event_MMU_NOTIFY_UNMAP},0,vma_rust,mm_rust,(vma_rust).vm_start,(vma_rust).vm_end);
            let mut tlb:bindings::mmu_gather = safe_ffi::tlb_gather_mmu_rust_safe(mm_rust);

            if safe_ffi::mmu_notifier_invalidate_range_start_nonblock_rust_safe(&mut range) !=0{
                safe_ffi::tlb_finish_mmu_safe(&mut tlb);
                ret = false;
                vma = (vma_rust).vm_next;
                continue;
            }
            safe_ffi::unmap_page_range_rust_safe(&mut tlb,vma_rust,(range).start,(range).end);
            safe_ffi::mmu_notifier_invalidate_range_end_rust_safe(&mut range);
            safe_ffi::tlb_finish_mmu_safe(&mut tlb);
        }

        vma = (vma_rust).vm_next;

    }

    if !ret{
        safe_ffi::trace_finish_task_reaping_rust_safe((tsk_rust).pid);
        safe_ffi::mmap_read_unlock_rust_safe(mm_rust);
        return ret;
    }

    safe_ffi::pr_info_oom_reap_task_mm_safe(tsk_rust,mm_rust);
    safe_ffi::trace_finish_task_reaping_rust_safe((tsk_rust).pid);
    safe_ffi::mmap_read_unlock_rust_safe(mm_rust);
    return ret;
}

static mut MAX_OOM_REAP_RETRIES:i32 = 10;

#[cfg(CONFIG_MMU)]
#[no_mangle]
pub extern "C" fn oom_reaper(unused:*mut c_void)->i32
{
    while true{
        safe_ffi::wait_event_freezable_rust_safe();
        safe_ffi::spin_lock_rust_safe();

        if !unsafe{ bindings::oom_reaper_list.is_null() }{
            let mut tsk:*mut task_struct = unsafe{ bindings::oom_reaper_list };
            let mut tsk_rust:&mut task_struct = unsafe{ tsk.as_mut().unwrap() };
            unsafe{ bindings::oom_reaper_list = (tsk_rust).oom_reaper_list };

            safe_ffi::spin_unlock_rust_safe();

            if !tsk.is_null(){
                let mut attempts:u8 = 0;

                let mm:*mut mm_struct = unsafe{ (*(tsk_rust.signal)).oom_mm };
                let mut mm_rust:&mut mm_struct = unsafe{  mm.as_mut().unwrap() };

                while attempts < unsafe{ MAX_OOM_REAP_RETRIES } as u8 && !oom_reap_task_mm(tsk_rust,mm_rust){

                    safe_ffi::schedule_timeout_idle_safe((bindings::HZ as i64 / 10) as i64);
                    attempts += 1;
                }

                let mut flags:&mut u64 = &mut ((mm_rust).__bindgen_anon_1.flags);
                if attempts <= unsafe{ MAX_OOM_REAP_RETRIES } as u8 || safe_ffi::test_bit_rust_safe(bindings::MMF_OOM_SKIP as i32, flags) !=0 {

                    (tsk_rust).oom_reaper_list = ptr::null_mut();

                    safe_ffi::set_bit_rust_skip_safe(flags);
                    safe_ffi::put_task_struct_safe(tsk_rust);
                    continue;
                }

                safe_ffi::pr_info_reap_task_safe(tsk_rust);
                safe_ffi::sched_show_task_safe(tsk_rust);
                safe_ffi::debug_show_all_locks_rust_safe();

                (tsk_rust).oom_reaper_list = ptr::null_mut();

                safe_ffi::set_bit_rust_skip_safe(flags);
                safe_ffi::put_task_struct_safe(tsk_rust);
            }
        }
    }
    return 0;
}

#[cfg(CONFIG_MMU)]
fn wake_oom_reaper(tsk:&mut task_struct)
{
    let mut flags:*mut u64 = unsafe{ &mut(*((*((tsk).signal)).oom_mm)).__bindgen_anon_1.flags};

    if safe_ffi::test_and_set_bit_rust_safe(flags) != 0{
        return;
    }

    safe_ffi::get_task_struct_rust_safe(tsk);
    safe_ffi::spin_lock_rust_safe();
    (tsk).oom_reaper_list = unsafe{ bindings::oom_reaper_list};
    unsafe{bindings::oom_reaper_list = tsk as *mut task_struct};
    safe_ffi::spin_unlock_rust_safe();
    safe_ffi::trace_wake_reaper_rust_safe((tsk).pid);
    safe_ffi::wake_up_rust_safe();
}

#[cfg(CONFIG_MMU)]
fn oom_init()->i32
{
    unsafe{
        bindings::oom_reaper_th = bindings::kthread_run_rust(Some(oom_reaper));
    }
    return 0;
}

#[cfg(not(CONFIG_MMU))]
fn wake_oom_reaper(tsk:*mut task_struct)
{
}

//#[no_mangle]
fn exit_oom_victim()
{
    safe_ffi::clear_thread_flag_rust_safe();

    if !safe_ffi::atomic_dec_return_rust_safe() !=0 { 
        safe_ffi::wake_up_all_rust_safe();
    }
}

//#[no_mangle]
fn oom_killer_enable()
{
    unsafe{
        bindings::oom_killer_disabled = false;
    }
        safe_ffi::pr_info_oom_killer_enable_safe();
}
//#[no_mangle]
fn oom_killer_disable(timeout:i64) -> bool
{
    let mut ret:i64 = 0;

    if safe_ffi::mutex_lock_killable_rust_safe() != 0{
        return false;
    }
    unsafe{ bindings::oom_killer_disabled = true };
    safe_ffi::mutex_unlock_rust_safe();

    ret = safe_ffi::wait_event_interruptible_timeout_rust_safe(timeout);

    if ret <= 0 {
        oom_killer_enable();
        return false;
    }
    safe_ffi::pr_info_oom_killer_disable();

    return true;
}


fn task_will_free_mem(task:&mut task_struct) -> bool
{

    let mut mm:*mut mm_struct = (task).mm;
    let mut ret:bool = true;

    if mm.is_null(){
        return false;
    }
    let mut mm_rust:&mut mm_struct = unsafe{ mm.as_mut().unwrap() };
    let sig:*mut signal_struct = (task).signal;
    let sig_rust:&mut signal_struct = unsafe{ sig.as_mut().unwrap() };

    if (sig_rust).flags & 8 as u32 != 0{
        return false;
    }
    if (sig_rust).flags & bindings::SIGNAL_GROUP_EXIT == 0 && (safe_ffi::thread_group_empty_rust_safe(task) == 0 || ((task).flags & bindings::PF_EXITING) == 0)
    {
        return false;
    }

    let mut mm_flags:u64 = ((mm_rust)).__bindgen_anon_1.flags;
    if safe_ffi::test_bit_rust_safe(bindings::MMF_OOM_SKIP as i32,&mut mm_flags) != 0{
        return false;
    }

    if safe_ffi::atomic_read_rust_safe(&(((mm_rust)).__bindgen_anon_1.mm_users)) <= 1{
        return true;
    }

    safe_ffi::rcu_read_lock_oom();
    let p:*mut task_struct = unsafe{ &mut bindings::init_task };
    let mut q:*mut task_struct = safe_ffi::next_task_rust_safe(p);
    while(q != p){
        if !safe_ffi::process_shares_mm_thread_safe(q,mm){
            q = safe_ffi::next_task_rust_safe(q);
            continue;
        }
        if safe_ffi::same_thread_group_rust_safe(task,q){
            q = safe_ffi::next_task_rust_safe(q);
            continue;
        }
        let mut task_rust:&mut task_struct = unsafe{ q.as_mut().unwrap() };
        let sig:*mut signal_struct = (task_rust).signal;
        let sig_rust:&mut signal_struct = unsafe{ sig.as_mut().unwrap() };

        if (sig_rust).flags & 8 as u32 != 0 {
            ret = false;
        }

        else if (sig_rust).flags & bindings::SIGNAL_GROUP_EXIT != 0 {
            ret = true;
        }

        else if safe_ffi::thread_group_empty_rust_safe(task_rust) != 0 && ((task_rust).flags & bindings::PF_EXITING) != 0{
            ret =  true;
        }
        else{
            ret = false;
        }

        if !ret {
            break;
        }
        q = safe_ffi::next_task_rust_safe(q);
    }
    safe_ffi::rcu_read_unlock_oom();

    return ret;

}

fn __oom_kill_process(mut victim_rust:&mut task_struct,message:*const u8)
{

    let mut p:*mut task_struct = safe_ffi::find_lock_task_mm_thread_safe(victim_rust);
    safe_ffi::rcu_read_unlock_oom();
    let mut can_oom_reap:bool = true;

    if p.is_null(){
        safe_ffi::print__oom_kill_safe(victim_rust,message as *const i8);
        safe_ffi::put_task_struct_safe(victim_rust as *mut task_struct);
        return;
    }
    let mut p_rust:&mut task_struct = unsafe{p.as_mut().unwrap()};
    if victim_rust as *mut task_struct != p{
        safe_ffi::get_task_struct_rust_safe(p_rust);
        safe_ffi::put_task_struct_safe(victim_rust as *mut task_struct);
        victim_rust = p_rust;
    }

    let mut mm:*mut mm_struct = (victim_rust).mm;
    let mut mm_rust:&mut mm_struct = unsafe{mm.as_mut().unwrap()};
    safe_ffi::mmgrab_rust_safe(mm_rust);

    safe_ffi::count_vm_event_rust_safe();
    safe_ffi::memcg_memory_event_mm_rust_safe(mm_rust);

    safe_ffi::do_send_sig_info_rust_safe(victim_rust);

    safe_ffi::warn_on_rust_safe();

    if safe_ffi::test_and_set_tsk_thread_flag_rust_safe(victim_rust) !=0 {
        return
    }

    if !safe_ffi::cmpxchg_rust_safe(victim_rust,mm_rust) != 0{
        safe_ffi::mmgrab_tsk_safe(victim_rust);
        let mut flags:&mut u64 = &mut ((mm_rust).__bindgen_anon_1.flags);
        safe_ffi::set_bit_victim_safe(flags);
    }

    safe_ffi::__thaw_task_safe(victim_rust);
    safe_ffi::atomic_inc_rust_safe();
    safe_ffi::trace_mark_victim_rust_safe((victim_rust).pid);

    safe_ffi::pr_err_oom_safe(victim_rust,mm_rust,message as *const i8);
    safe_ffi::task_unlock_rust_safe(victim_rust);

    safe_ffi::rcu_read_lock_oom();

    let mut p:*mut task_struct = unsafe{&mut bindings::init_task};
    let mut q:*mut task_struct = safe_ffi::next_task_rust_safe(p);

    while(q != p){
        if !safe_ffi::process_shares_mm_thread_safe(q,mm){
            q = safe_ffi::next_task_rust_safe(q);
            continue;
        }


        if safe_ffi::same_thread_group_rust_safe(victim_rust,q){
            q = safe_ffi::next_task_rust_safe(q);
            continue;
        }

        let mut q_ref:&mut task_struct = unsafe{q.as_mut().unwrap()};
        if safe_ffi::is_global_init_rust_safe(q_ref) !=0 {
            can_oom_reap = false;
            let mut mm_flags:u64 = (mm_rust).__bindgen_anon_1.flags;
            safe_ffi::set_bit_rust_skip_safe(&mut mm_flags);
            safe_ffi::print__oom_kill_2_safe(victim_rust,q_ref);
            q = safe_ffi::next_task_rust_safe(q);
            continue;
        }

        if safe_ffi::unlikely_rust_safe(q_ref) != 0{
            q = safe_ffi::next_task_rust_safe(q);
            continue;
        }

        safe_ffi::do_send_sig_info_rust_safe(q_ref);
        q = safe_ffi::next_task_rust_safe(q);
    }

    safe_ffi::rcu_read_unlock_oom();

    if can_oom_reap{
        wake_oom_reaper(victim_rust);
    }

    safe_ffi::mmdrop_rust_safe(mm_rust);

    safe_ffi::put_task_struct_safe(victim_rust as *mut task_struct);
}


#[no_mangle]
pub extern "C" fn oom_kill_memcg_member(task:*mut task_struct,message:*mut c_void)->i32
{
    let mut victim_rust:&mut task_struct = unsafe{task.as_mut().unwrap()};
    if unsafe{(*((*task).signal)).oom_score_adj} != bindings::OOM_SCORE_ADJ_MIN as i16 && safe_ffi::is_global_init_rust_safe(victim_rust) ==0 {
        safe_ffi::get_task_struct_rust_safe(victim_rust);
        // __oom_kill_process(task_rust, message as *const u8);
        let mut p:*mut task_struct = safe_ffi::find_lock_task_mm_thread_safe(victim_rust);
        safe_ffi::rcu_read_unlock_oom();
        let mut can_oom_reap:bool = true;

        if p.is_null(){
            safe_ffi::print__oom_kill_safe(victim_rust,message as *const i8);
            safe_ffi::put_task_struct_safe(victim_rust as *mut task_struct);
            return 0;
        }
        let mut p_rust:&mut task_struct = unsafe{p.as_mut().unwrap()};
        if victim_rust as *mut task_struct != p{
            safe_ffi::get_task_struct_rust_safe(p_rust);
            safe_ffi::put_task_struct_safe(victim_rust as *mut task_struct);
            victim_rust = p_rust;
        }

        let mut mm:*mut mm_struct = (victim_rust).mm;
        let mut mm_rust:&mut mm_struct = unsafe{mm.as_mut().unwrap()};
        safe_ffi::mmgrab_rust_safe(mm_rust);

        safe_ffi::count_vm_event_rust_safe();
        safe_ffi::memcg_memory_event_mm_rust_safe(mm_rust);

        safe_ffi::do_send_sig_info_rust_safe(victim_rust);

        safe_ffi::warn_on_rust_safe();

        if safe_ffi::test_and_set_tsk_thread_flag_rust_safe(victim_rust) !=0 {
            return 0;
        }

        if !safe_ffi::cmpxchg_rust_safe(victim_rust,mm_rust) != 0{
            safe_ffi::mmgrab_tsk_safe(victim_rust);
            let mut flags:&mut u64 = &mut ((mm_rust).__bindgen_anon_1.flags);
            safe_ffi::set_bit_victim_safe(flags);
        }

        safe_ffi::__thaw_task_safe(victim_rust);
        safe_ffi::atomic_inc_rust_safe();
        safe_ffi::trace_mark_victim_rust_safe((victim_rust).pid);

        safe_ffi::pr_err_oom_safe(victim_rust,mm_rust,message as *const i8);
        safe_ffi::task_unlock_rust_safe(victim_rust);

        safe_ffi::rcu_read_lock_oom();

        let mut p:*mut task_struct = unsafe{&mut bindings::init_task};
        let mut q:*mut task_struct = safe_ffi::next_task_rust_safe(p);

        while(q != p){
            if !safe_ffi::process_shares_mm_thread_safe(q,mm){
                q = safe_ffi::next_task_rust_safe(q);
                continue;
            }

            if safe_ffi::same_thread_group_rust_safe(victim_rust,q){
                q = safe_ffi::next_task_rust_safe(q);
                continue;
            }

            let mut q_ref:&mut task_struct = unsafe{q.as_mut().unwrap()};
            if safe_ffi::is_global_init_rust_safe(q_ref) !=0 {
                can_oom_reap = false;
                let mut mm_flags:u64 = (mm_rust).__bindgen_anon_1.flags;
                safe_ffi::set_bit_rust_skip_safe(&mut mm_flags);
                safe_ffi::print__oom_kill_2_safe(victim_rust,q_ref);
                q = safe_ffi::next_task_rust_safe(q);
                continue;
            }

            if safe_ffi::unlikely_rust_safe(q_ref) != 0{
                q = safe_ffi::next_task_rust_safe(q);
                continue;
            }

            safe_ffi::do_send_sig_info_rust_safe(q_ref);
            q = safe_ffi::next_task_rust_safe(q);
        }

        safe_ffi::rcu_read_unlock_oom();

        if can_oom_reap{
            wake_oom_reaper(victim_rust);
        }

        safe_ffi::mmdrop_rust_safe(mm_rust);

        safe_ffi::put_task_struct_safe(victim_rust as *mut task_struct);
    }
    return 0;
}

fn oom_kill_process(oc_rust:&mut bindings::oom_control,message:*const u8)
{

    let mut victim:*mut task_struct = (oc_rust).chosen;
    let mut oom_rs:bindings::ratelimit_state = safe_ffi::define_ratelimit_state_rust_safe();
    let mut victim_rust:&mut task_struct = unsafe{ victim.as_mut().unwrap() };
    let mut victim_option:Option<&mut task_struct> = unsafe{ victim.as_mut() };

    safe_ffi::task_lock_rust_safe(victim_rust);
    if task_will_free_mem(victim_rust){
        //mark_oom_victim(victim_rust);
        let mut mm:*mut mm_struct = (victim_rust).mm;
        let mut mm_rust:&mut mm_struct = unsafe{ mm.as_mut().unwrap() };

        safe_ffi::warn_on_rust_safe();

        if safe_ffi::test_and_set_tsk_thread_flag_rust_safe(victim_rust) !=0 {
            wake_oom_reaper(victim_rust);
            safe_ffi::task_unlock_rust_safe(victim_rust);
            safe_ffi::put_task_struct_safe(victim);
            return;
        }

        if !safe_ffi::cmpxchg_rust_safe(victim_rust,mm_rust) != 0{
            safe_ffi::mmgrab_tsk_safe(victim_rust);
            let mut flags:&mut u64 = &mut ((mm_rust).__bindgen_anon_1.flags);
            safe_ffi::set_bit_victim_safe(flags);
        }

        safe_ffi::__thaw_task_safe(victim_rust);
        safe_ffi::atomic_inc_rust_safe();
        safe_ffi::trace_mark_victim_rust_safe((victim_rust).pid);

        wake_oom_reaper(victim_rust);
        safe_ffi::task_unlock_rust_safe(victim_rust);
        safe_ffi::put_task_struct_safe(victim);
        return;
    }
    safe_ffi::task_unlock_rust_safe(victim_rust);

    let mut rate:&mut bindings::ratelimit_state = &mut oom_rs;
    if safe_ffi::ratelimit_safe(rate) != 0{
        safe_ffi::pr_warn_dump_header_safe(oc_rust);

        safe_ffi::dump_stack_safe();

        if !(oc_rust.memcg.is_null()){
            safe_ffi::mem_cgroup_print_oom_meminfo_safe(oc_rust.memcg);
        }
        else{
            safe_ffi::show_mem_safe(bindings::SHOW_MEM_FILTER_NODES, (oc_rust).nodemask);
            let mut nr_lru:u64=0;

            nr_lru =  safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_ACTIVE_ANON) +
                safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_INACTIVE_ANON) +
                safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_ACTIVE_FILE) +
                safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_INACTIVE_FILE) +
                safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_ISOLATED_ANON) +
                safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_ISOLATED_FILE) +
                safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_UNEVICTABLE);

            if (safe_ffi::global_node_page_state_pages_rust_safe(bindings::node_stat_item_NR_SLAB_UNRECLAIMABLE_B) > nr_lru){
                safe_ffi::dump_unreclaimable_slab_safe();
            }
        }

        if unsafe{ sysctl_oom_dump_tasks } != 0{
            safe_ffi::dump_task_pr_info_safe();

            if !(oc_rust.memcg.is_null()){
                let foo:Option<unsafe extern "C" fn(*mut task_struct, *mut c_void) -> i32> = Some(dump_task);

                unsafe{ bindings::mem_cgroup_scan_tasks(((oc_rust).memcg), foo,oc_rust as *mut oom_control as *mut c_types::c_void) };
            }
            else{
                safe_ffi::rcu_read_lock_oom();
                let p:*mut task_struct = unsafe{ &mut bindings::init_task };
                let mut q:*mut task_struct = safe_ffi::next_task_rust_safe(p);
                while(q != p){
                    dump_task(q,oc_rust as *mut oom_control as *mut c_types::c_void);
                    q = safe_ffi::next_task_rust_safe(q);
                }
                safe_ffi::rcu_read_unlock_oom();
            }
        }

        match victim_option{
            Some(i) => dump_oom_summary(oc_rust, i),
            None => (),
        }
    }

    let mut oom_group:*mut bindings::mem_cgroup = safe_ffi::mem_cgroup_get_oom_group_safe(victim_rust,(oc_rust).memcg);
    {
        let mut p:*mut task_struct = safe_ffi::find_lock_task_mm_thread_safe(victim_rust);
        safe_ffi::rcu_read_unlock_oom();
        let mut can_oom_reap:bool = true;

        if p.is_null(){
            safe_ffi::print__oom_kill_safe(victim_rust,message as *const i8);
            safe_ffi::put_task_struct_safe(victim_rust as *mut task_struct);

            if !oom_group.is_null(){
                safe_ffi::mem_cgroup_print_oom_group_safe(oom_group);
                let foo:Option<unsafe extern "C" fn(*mut task_struct,*mut c_void)-> i32> = Some(oom_kill_memcg_member);
                unsafe{ bindings::mem_cgroup_scan_tasks(oom_group, foo, message as *mut c_void);}
                safe_ffi::mem_cgroup_put_rust_safe(oom_group);
            }
            return;
        }
        let mut p_rust:&mut task_struct = unsafe{p.as_mut().unwrap()};
        if victim_rust as *mut task_struct != p{
            safe_ffi::get_task_struct_rust_safe(p_rust);
            safe_ffi::put_task_struct_safe(victim_rust as *mut task_struct);
            victim_rust = p_rust;
        }

        let mut mm:*mut mm_struct = (victim_rust).mm;
        let mut mm_rust:&mut mm_struct = unsafe{mm.as_mut().unwrap()};
        safe_ffi::mmgrab_rust_safe(mm_rust);

        safe_ffi::count_vm_event_rust_safe();
        safe_ffi::memcg_memory_event_mm_rust_safe(mm_rust);

        safe_ffi::do_send_sig_info_rust_safe(victim_rust);

        safe_ffi::warn_on_rust_safe();

        if safe_ffi::test_and_set_tsk_thread_flag_rust_safe(victim_rust) !=0 {
            if !oom_group.is_null(){
                safe_ffi::mem_cgroup_print_oom_group_safe(oom_group);
                let foo:Option<unsafe extern "C" fn(*mut task_struct,*mut c_void)-> i32> = Some(oom_kill_memcg_member);
                unsafe{ bindings::mem_cgroup_scan_tasks(oom_group, foo, message as *mut c_void);}
                safe_ffi::mem_cgroup_put_rust_safe(oom_group);
            }
            return
        }

        if !safe_ffi::cmpxchg_rust_safe(victim_rust,mm_rust) != 0{
            safe_ffi::mmgrab_tsk_safe(victim_rust);
            let mut flags:&mut u64 = &mut ((mm_rust).__bindgen_anon_1.flags);
            safe_ffi::set_bit_victim_safe(flags);
        }

        safe_ffi::__thaw_task_safe(victim_rust);
        safe_ffi::atomic_inc_rust_safe();
        safe_ffi::trace_mark_victim_rust_safe((victim_rust).pid);

        safe_ffi::pr_err_oom_safe(victim_rust,mm_rust,message as *const i8);
        safe_ffi::task_unlock_rust_safe(victim_rust);

        safe_ffi::rcu_read_lock_oom();

        let mut p:*mut task_struct = unsafe{&mut bindings::init_task};
        let mut q:*mut task_struct = safe_ffi::next_task_rust_safe(p);

        while(q != p){
            if !safe_ffi::process_shares_mm_thread_safe(q,mm){
                q = safe_ffi::next_task_rust_safe(q);
                continue;
            }


            if safe_ffi::same_thread_group_rust_safe(victim_rust,q){
                q = safe_ffi::next_task_rust_safe(q);
                continue;
            }

            let mut q_ref:&mut task_struct = unsafe{q.as_mut().unwrap()};
            if safe_ffi::is_global_init_rust_safe(q_ref) !=0 {
                can_oom_reap = false;
                let mut mm_flags:u64 = (mm_rust).__bindgen_anon_1.flags;
                safe_ffi::set_bit_rust_skip_safe(&mut mm_flags);
                safe_ffi::print__oom_kill_2_safe(victim_rust,q_ref);
                q = safe_ffi::next_task_rust_safe(q);
                continue;
            }

            if safe_ffi::unlikely_rust_safe(q_ref) != 0{
                q = safe_ffi::next_task_rust_safe(q);
                continue;
            }

            safe_ffi::do_send_sig_info_rust_safe(q_ref);
            q = safe_ffi::next_task_rust_safe(q);
        }

        safe_ffi::rcu_read_unlock_oom();

        if can_oom_reap{
            wake_oom_reaper(victim_rust);
        }

        safe_ffi::mmdrop_rust_safe(mm_rust);

        safe_ffi::put_task_struct_safe(victim_rust as *mut task_struct);
    }

    if !oom_group.is_null(){
        safe_ffi::mem_cgroup_print_oom_group_safe(oom_group);
        let foo:Option<unsafe extern "C" fn(*mut task_struct,*mut c_void)-> i32> = Some(oom_kill_memcg_member);
        unsafe{ bindings::mem_cgroup_scan_tasks(oom_group, foo, message as *mut c_void);}
        safe_ffi::mem_cgroup_put_rust_safe(oom_group);
    }

}

fn check_panic_on_oom(oc:*mut oom_control)
{
    let mut oc_rust:&mut oom_control = unsafe{ oc.as_mut().unwrap() };
    if unsafe{ bindings::like_rust(!sysctl_panic_on_oom) } != 0{
        return;
    }
    if unsafe{ sysctl_panic_on_oom } != 2{

        if (oc_rust).constraint != bindings::oom_constraint_CONSTRAINT_NONE{
            return;
        }
    }

    if (oc_rust.order == -1){
        return;
    }

    safe_ffi::pr_warn_dump_header_safe(oc_rust);

    safe_ffi::dump_stack_safe();

    if !(oc_rust.memcg.is_null()){
        safe_ffi::mem_cgroup_print_oom_meminfo_safe(oc_rust.memcg);
    }
    else{
        safe_ffi::show_mem_safe(bindings::SHOW_MEM_FILTER_NODES, (oc_rust).nodemask);
        let mut nr_lru:u64=0;

        nr_lru =  safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_ACTIVE_ANON) +
            safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_INACTIVE_ANON) +
            safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_ACTIVE_FILE) +
            safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_INACTIVE_FILE) +
            safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_ISOLATED_ANON) +
            safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_ISOLATED_FILE) +
            safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_UNEVICTABLE);

        if (safe_ffi::global_node_page_state_pages_rust_safe(bindings::node_stat_item_NR_SLAB_UNRECLAIMABLE_B) > nr_lru){
            safe_ffi::dump_unreclaimable_slab_safe();
        }
    }

    if unsafe{ sysctl_oom_dump_tasks } != 0{
        safe_ffi::dump_task_pr_info_safe();
        if !(oc_rust.memcg.is_null()){
            let foo:Option<unsafe extern "C" fn(*mut task_struct, *mut c_void) -> i32> = Some(dump_task);

            unsafe{ bindings::mem_cgroup_scan_tasks(((oc_rust).memcg), foo,oc_rust as *mut oom_control as *mut c_types::c_void) };
        }
        else{
            safe_ffi::rcu_read_lock_oom();
            let p:*mut task_struct = unsafe{ &mut bindings::init_task };
            let mut q:*mut task_struct = safe_ffi::next_task_rust_safe(p);

            while(q != p){
                dump_task(q,oc_rust as *mut oom_control as *mut c_types::c_void);
                q = safe_ffi::next_task_rust_safe(q);
            }
            safe_ffi::rcu_read_unlock_oom();
        }
    }

    if unsafe{ sysctl_panic_on_oom } == 2{
        panic!("Out of memory: compulsory panic_on_oom is enabled\n");
    }
    else{
        panic!("Out of memory: system-wide panic_on_oom is enabled\n");
    }

}

//#[no_mangle]
fn register_oom_notifier(nb:*mut bindings::notifier_block)->i32
{
    let mut nh:*mut bindings::blocking_notifier_head =unsafe{&mut bindings::oom_notify_list};

    return safe_ffi::blocking_notifier_chain_register_safe(nh, nb);
}

//#[no_mangle]
fn unregister_oom_notifier(nb:*mut bindings::notifier_block)->i32
{

    let mut nh:*mut bindings::blocking_notifier_head = unsafe{&mut bindings::oom_notify_list};

    return safe_ffi::blocking_notifier_chain_unregister_safe(nh, nb);
}

#[no_mangle]
pub extern "C" fn out_of_memory_rust(oc:*mut oom_control) -> bool
{

    let mut oc_rust:&mut oom_control = unsafe{ oc.as_mut().unwrap() };
    let mut freed:u64 = 0;

    if unsafe{ bindings::oom_killer_disabled }{
        return false;
    }

    if !(oc_rust.memcg.is_null()){
        let mut nh:&mut bindings::blocking_notifier_head = unsafe{ &mut bindings::oom_notify_list };
        let mut free:*mut u64 = &mut freed;
        safe_ffi::blocking_notifier_call_chain_safe(nh, 0, free as *mut c_void);

        if freed > 0{
            return true;
        }
    }

    let mut current:*mut task_struct = safe_ffi::get_current_rust_safe();
    let mut current_rust:&mut task_struct = unsafe{current.as_mut().unwrap()};

    if task_will_free_mem(current_rust){
        //mark_oom_victim(current_rust);
        let mut mm:*mut mm_struct = (current_rust).mm;
        let mut mm_rust:&mut mm_struct = unsafe{ mm.as_mut().unwrap() };

        safe_ffi::warn_on_rust_safe();

        if safe_ffi::test_and_set_tsk_thread_flag_rust_safe(current_rust) !=0 {
            wake_oom_reaper(current_rust);
            return true;
        }

        if !safe_ffi::cmpxchg_rust_safe(current_rust,mm_rust) != 0{
            safe_ffi::mmgrab_tsk_safe(current_rust);
            let mut flags:&mut u64 = &mut ((mm_rust).__bindgen_anon_1.flags);
            safe_ffi::set_bit_victim_safe(flags);
        }

        safe_ffi::__thaw_task_safe(current_rust);
        safe_ffi::atomic_inc_rust_safe();
        safe_ffi::trace_mark_victim_rust_safe((current_rust).pid);
        wake_oom_reaper(current_rust);
        return true;
    }

    if (oc_rust).gfp_mask != 0 && (oc_rust).gfp_mask & bindings::___GFP_FS == 0 && !(oc_rust.memcg.is_null()){
        return true;
    }

    (oc_rust).constraint = constrained_alloc(oc_rust);
    if (oc_rust).constraint != bindings::oom_constraint_CONSTRAINT_MEMORY_POLICY{
        (oc_rust).nodemask = ptr::null_mut();
        // bindings::nodemask_null(oc);
    }
    check_panic_on_oom(oc_rust);

    if !(oc_rust.memcg.is_null()) && unsafe{ sysctl_oom_kill_allocating_task != 0 } && !(((current_rust).mm).is_null()) && safe_ffi::is_global_init_rust_safe(current_rust) == 0 && (current_rust.flags & bindings::PF_KTHREAD) == 0 && oom_cpuset_eligible(current_rust, oc_rust) && unsafe{ (*((current_rust).signal)).oom_score_adj } != bindings::OOM_SCORE_ADJ_MIN as i16{

        safe_ffi::get_task_struct_rust_safe(current_rust);
        (oc_rust).chosen = current_rust as *mut task_struct;
        oom_kill_process(oc_rust, "Out of memory (oom_kill_allocating_task)".as_ptr());
        return true;
    }

    select_bad_process(oc_rust);

    if ((oc_rust).chosen).is_null(){
        safe_ffi::pr_warn_dump_header_safe(oc_rust);
        safe_ffi::dump_stack_safe();

        if !(oc_rust.memcg.is_null()){
            safe_ffi::mem_cgroup_print_oom_meminfo_safe(oc_rust.memcg);
        }
        else{
            safe_ffi::show_mem_safe(bindings::SHOW_MEM_FILTER_NODES, (oc_rust).nodemask);
            let mut nr_lru:u64=0;

            nr_lru =  safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_ACTIVE_ANON) +
                safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_INACTIVE_ANON) +
                safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_ACTIVE_FILE) +
                safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_INACTIVE_FILE) +
                safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_ISOLATED_ANON) +
                safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_ISOLATED_FILE) +
                safe_ffi::global_node_page_state_rust_safe(bindings::node_stat_item_NR_UNEVICTABLE);

            if (safe_ffi::global_node_page_state_pages_rust_safe(bindings::node_stat_item_NR_SLAB_UNRECLAIMABLE_B) > nr_lru){
                safe_ffi::dump_unreclaimable_slab_safe();
            }
        }

        if unsafe{ sysctl_oom_dump_tasks } != 0{
            safe_ffi::dump_task_pr_info_safe();
            if !(oc_rust.memcg.is_null()){
                let foo:Option<unsafe extern "C" fn(*mut task_struct, *mut c_void) -> i32> = Some(dump_task);

                unsafe{ bindings::mem_cgroup_scan_tasks(((oc_rust).memcg), foo,oc_rust as *mut oom_control as *mut c_types::c_void) };
            }
            else{
                safe_ffi::rcu_read_lock_oom();
                let p:*mut task_struct = unsafe{ &mut bindings::init_task };
                let mut q:*mut task_struct = safe_ffi::next_task_rust_safe(p);

                while(q != p){
                    dump_task(q,oc_rust as *mut oom_control as *mut c_types::c_void);
                    q = safe_ffi::next_task_rust_safe(q);
                }
                safe_ffi::rcu_read_unlock_oom();
            }
        }
        if !(oc_rust.order == -1) && oc_rust.memcg.is_null(){
            safe_ffi::out_of_memory_panic_safe();
        }
    }

    if !(((oc_rust).chosen).is_null()) && (oc_rust).chosen != u64::MAX as *mut task_struct{
        if oc_rust.memcg.is_null(){
            oom_kill_process(oc_rust, "Out of memory".as_ptr()) ;
        }
        else{
            oom_kill_process(oc_rust, "Memory cgroup out of memory".as_ptr());
        }

    }

    return true;
}

fn pagefault_out_of_memory()
{
    let mut pfoom_rs:bindings::ratelimit_state = safe_ffi::define_ratelimit_state_rust_safe();
    let mut current:*mut task_struct = safe_ffi::get_current_rust_safe();

    if safe_ffi::mem_cgroup_oom_synchronize_safe(true){
        return;
    }

    if safe_ffi::fatal_signal_pending_rust_safe(current) != 0 {
        return;
    }

    let mut rate:&mut bindings::ratelimit_state = &mut pfoom_rs;
    if safe_ffi::ratelimit_safe(rate) != 0 {
       // pr_warn!("Huh VM_FAULT_OOM leaked out to the #PF handler. Retrying PF\n");
    }

}
