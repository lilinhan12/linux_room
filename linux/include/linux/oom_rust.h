#include <linux/oom.h>

long oom_badness_rust(struct task_struct *p,unsigned long totalpages);
extern bool out_of_memory_rust(struct oom_control *oc);
