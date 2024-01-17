/* SPDX-License-Identifier: GPL-2.0 */

/*
 # created by xsyin 2022-7-24
 # map the secure container region 0xffff 7dff fcc0 0000 ~ 0xffff 7dff fec0 0000
 # get, read, write that region
*/


#include <linux/types.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm_types.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/io.h>
#include <asm/sysreg.h>
#include <asm/cacheflush.h>
#include <linux/trust_container.h>

#include "mount.h"


struct llist_head_container {
	struct llist_node *first;
    unsigned int lock;
};

static struct llist_head_container *task_hashtable __read_mostly;
static struct llist_head_container *cred_hashtable __read_mostly;
static struct llist_head *nsproxy_hashtable __read_mostly;

extern struct gen_pool *cred_pool;
extern struct gen_pool *nsproxy_pool;
extern struct gen_pool *task_pool;
extern struct gen_pool *user_ns_pool;
extern struct gen_pool *fs_pool;
extern struct gen_pool *mnt_ns_pool;
extern struct gen_pool *mnt_pool;
extern int prepare_count;

static struct gen_pool *container_shm_pool;

// struct kmem_cache *fs_cachep;

static unsigned long secure_paddr_vaddr_offset;

static inline struct llist_head_container *task_hash(struct task_struct *tsk)
{
	unsigned long tmp = ((unsigned long)__pa(tsk) & (SZ_1M - 1)) / 8;
	return &task_hashtable[tmp];
}

static inline struct llist_head_container *cred_hash(unsigned long cred_paddr)
{
	unsigned long tmp = (cred_paddr & (SZ_1M - 1)) / 8;
    return &cred_hashtable[tmp];
}

static inline struct llist_head *nsproxy_hash(unsigned long nsp_paddr)
{
	unsigned long tmp = (nsp_paddr & (SZ_1M - 1)) / 8;
	return &nsproxy_hashtable[tmp];
}

struct container_cred *get_container_cred(unsigned long cred_paddr){
    struct llist_head_container *head = cred_hash(cred_paddr);
    struct container_cred *p, *t;
    struct llist_node *first = NULL;

    if(!(head->first))
        return NULL;

    first = (struct llist_node *)(container_phys_to_virt((unsigned long)head->first + secure_paddr_vaddr_offset));
    
    if(!in_container_range(first, CRED))
        return NULL;
    llist_for_each_entry_safe(p, t, first, cred_list){
		if(p == NULL)
            break;
        if (p != NULL && p->paddr == cred_paddr)
			return p;
    }
	return NULL;
}

struct container_nsproxy *get_container_nsproxy(unsigned long nsp_paddr){
    struct llist_head *head = nsproxy_hash(nsp_paddr);
    struct container_nsproxy *p, *t;
    struct llist_node *first = NULL;
    
    if(!(head->first))
        return NULL;

    first = (struct llist_node *)(container_phys_to_virt((unsigned long)head->first + secure_paddr_vaddr_offset));
    if(!in_container_range(first, NSPROXY))
        return NULL;
    llist_for_each_entry_safe(p, t, first, nsp_list){
		if (p != NULL && p->paddr == nsp_paddr)
			return p;
    }
	return NULL;
}

struct container_task *get_container_task(struct task_struct *tsk){
    struct container_task *p, *t, *first_task;
    struct llist_head_container *head = task_hash(tsk);
    struct llist_node *first = NULL;
    static int task_count;

    if(!(head->first))
        return NULL;

    task_count ++;
    first = (struct llist_node *)(container_phys_to_virt((unsigned long)head->first + secure_paddr_vaddr_offset));

    if(!in_container_range(first, TSK)){
        return NULL;
    }
    
    llist_for_each_entry_safe(p, t, first, tsk_list){
        if (p != NULL && p->tsk_paddr == __pa(tsk))
			return p;
    }
	return NULL;
}
EXPORT_SYMBOL(get_container_task);

void polling_checker(struct task_struct *task)
{
	if(is_container && (task->nsproxy == container_ns)){
        if( !task->cred->uid.val)
		    pr_alert("%s: exist potenial attack task %#lx, name %s, current %#lx, nsproxy %#lx, cred %#lx, uid %d, euid %#lx cap %#lx!!!",__func__, task, task->comm, current, task->nsproxy, task->cred, task->cred->uid.val, task->cred->euid.val, task->cred->cap_effective);
        if( !(in_container_range(task->fs, FS) || (get_flag(task->fs) == CONTAINER_FS)))
            pr_alert("%s: task %s, %#lx, fs error %#lx ------- ", __func__, task->comm, task, task->fs);
    }

	// 	if((task->nsproxy == &init_nsproxy) || (task->cred->uid.val == 0))
	// 		pr_alert("%s: exist potenial attack task %#lx, name %s, current %#lx, nsproxy %#lx, cred %#lx, uid %d, euid %#lx!!!",__func__, task, task->comm, current, task->nsproxy, task->cred, task->cred->uid.val);
	// }
    // if(is_container && !strstr(task->comm, "runc") && !task->cred->uid.val)
    //     if(task->nsproxy == container_ns || task->nsproxy == (struct nsproxy *)mask_con_value(NSPROXY, container_ns))


} 

int init_secure_container_region(void)
{
    int rc;
    struct arm_smccc_res res;
    void *va;
    unsigned long container_nsec_shm_paddr;
    unsigned long container_nsec_shm_size;

    task_hashtable = (struct llist_head_container *)CONTAINER_REGION_HTSK_START;
    cred_hashtable = (struct llist_head_container *)CONTAINER_REGION_HCRED_START;
    nsproxy_hashtable = (struct llist_head *)CONTAINER_REGION_HNSPROXY_START;
    arm_smccc_smc(OPTEE_SMC_INIT_CONTAINER_REGION, CONTAINER_REGION_VADDR_PADDR_OFFSET, 0, 0, 0, 0, 0, 0, &res);
    secure_paddr_vaddr_offset = res.a1;
    // container_nsec_shm_paddr = res.a2;
    // container_nsec_shm_size = res.a3;

    // va = memremap(container_nsec_shm_paddr, container_nsec_shm_size, MEMREMAP_WB);

    // container_shm_pool = gen_pool_create(PAGE_SHIFT, -1);
    // rc = gen_pool_add_virt(container_shm_pool, va, container_nsec_shm_paddr, container_nsec_shm_size, -1);
    // if (rc) {
    //     gen_pool_destroy(container_shm_pool);
    //     return -1;
    // }

    pr_alert("%s: res.a0 %d, res.a1 %#lx, tsk region start %#lx, end %#lx, size: tsk %#lx, cred %#lx, nsproxy %#lx, fs_struct size %#lx, offset head in wait_queue_head %#lx, spinlock_t size %#lx, fs_pin size %#lx", __func__, res.a0, res.a1, CONTAINER_REGION_TSK_START, CONTAINER_REGION_TSK_END, sizeof(struct task_struct), sizeof(struct cred), sizeof(struct nsproxy), sizeof(struct fs_struct), offsetof(struct wait_queue_head, head), sizeof(spinlock_t), sizeof(struct fs_pin));
    pr_alert("%s: size task_struct: %#lx, size mnt_namespace %#lx, cred offset %#lx, real_cred offset %#lx, nsproxy offset %#lx, fs offset %#lx, user_ns offset %#lx, mnt_ns offset %#lx", __func__, sizeof(struct task_struct), sizeof(struct mnt_namespace), offsetof(struct task_struct, cred), offsetof(struct task_struct, real_cred), offsetof(struct task_struct, nsproxy), offsetof(struct task_struct, fs), offsetof(struct cred, user_ns), offsetof(struct nsproxy, mnt_ns));
    pr_alert("%s: addr init_task %#lx, tasks %#lx, next %#lx, prev %#lx, pid %#lx, offset %#lx", __func__, &init_task, &init_task.tasks, init_task.tasks.next, init_task.tasks.prev, &init_task.pid, offsetof(struct task_struct, pid));

    return res.a0;
}

unsigned long container_pool_alloc(struct gen_pool *genpool, size_t s)
{
    unsigned long va;
	phys_addr_t con_pa;

    va = gen_pool_alloc(genpool, s);
	con_pa = gen_pool_virt_to_phys(genpool, va);

    return va;
}

void container_pool_free(struct gen_pool *genpool, void *vaddr, size_t s)
{
	gen_pool_free(genpool, vaddr, s);
}

struct gen_pool *container_pool_create(const char *name, size_t s)
{
    struct gen_pool *genpool;
    int rc;
    genpool = gen_pool_create(ilog2(s), -1);
    gen_pool_set_algo(genpool, gen_pool_best_fit, NULL);
    if (!genpool)
		return -ENOMEM;
    
    genpool->name = kstrdup(name, GFP_KERNEL);

    if(!memcmp(name, "nsproxy", sizeof("nsproxy"))){
        rc = gen_pool_add_virt(genpool, CONTAINER_REGION_NSPROXY_START, (CONTAINER_REGION_NSPROXY_START-CONTAINER_REGION_VADDR_PADDR_OFFSET), CONTAINER_REGION_NSPROXY_SIZE, -1);
    }else if(!memcmp(name, "cred_pool", sizeof("cred_pool"))){
        rc = gen_pool_add_virt(genpool, CONTAINER_REGION_CRED_START, (CONTAINER_REGION_CRED_START-CONTAINER_REGION_VADDR_PADDR_OFFSET), CONTAINER_REGION_CRED_SIZE, -1);
    }else if(!memcmp(name, "task_pool", sizeof("task_pool"))){
        rc = gen_pool_add_virt(genpool, CONTAINER_REGION_TSK_START, (CONTAINER_REGION_TSK_START-CONTAINER_REGION_VADDR_PADDR_OFFSET), CONTAINER_REGION_TSK_SIZE, -1);
    }else if(!memcmp(name, "mount_pool", sizeof("mount_pool"))){
        rc = gen_pool_add_virt(genpool, CONTAINER_REGION_MOUNT_START, (CONTAINER_REGION_MOUNT_START-CONTAINER_REGION_VADDR_PADDR_OFFSET), CONTAINER_REGION_MOUNT_SIZE, -1);
    }else if(!memcmp(name, "fs_pool", sizeof("fs_pool"))){
        rc = gen_pool_add_virt(genpool, CONTAINER_REGION_FS_START, (CONTAINER_REGION_FS_START-CONTAINER_REGION_VADDR_PADDR_OFFSET), CONTAINER_REGION_FS_SIZE, -1);
	}else if(!memcmp(name, "mnt_ns_pool", sizeof("mnt_ns_pool"))){
        rc = gen_pool_add_virt(genpool, CONTAINER_REGION_MNT_NS_START, (CONTAINER_REGION_MNT_NS_START-CONTAINER_REGION_VADDR_PADDR_OFFSET), CONTAINER_REGION_MNT_NS_SIZE, -1);
	}else if(!memcmp(name, "user_ns_pool", sizeof("user_ns_pool"))){
        rc = gen_pool_add_virt(genpool, CONTAINER_REGION_USER_NS_START, (CONTAINER_REGION_USER_NS_START-CONTAINER_REGION_VADDR_PADDR_OFFSET), CONTAINER_REGION_USER_NS_SIZE, -1);
    }else{
        pr_err("currently not support.....");
        return 0;
    }
    if (rc) {
        gen_pool_destroy(genpool);
        return NULL;
    }

    return genpool;
}

bool container_data_init(unsigned int flags, void *con_vaddr, struct task_struct *p, unsigned long s, unsigned long ns_paddr, unsigned long cred_paddr, unsigned long fs_paddr)
{
    bool ret;
    struct arm_smccc_res res;
    static int count;
    ret = false;
    count++;
    // if(count % 50 == 0){
        // pr_alert("%s: count %d, current %#lx, name %s, flags %#lx", __func__, count, current, current->comm, flags);
    // }
    arm_smccc_smc(OPTEE_SMC_CONTAINER_DATA_INIT, flags, container_virt_to_phys(con_vaddr), __pa(p), s, ns_paddr, cred_paddr, fs_paddr, &res);
    if(!res.a0){
        ret = true;
    }else{
        pr_alert("%s: flag %d, container data init error, res.a0 %d !", __func__, flags, res.a0);
    }

    return ret;
}

bool container_data_destory(const void *vaddr, const unsigned int flags)
{
    struct arm_smccc_res res;
    bool ret = false;
    static int count;
    
    if(in_container_region(vaddr)){
        count++;
        // pr_alert("%s: count %d, flags %#lx", __func__, flags);
        arm_smccc_smc(OPTEE_SMC_CONTAINER_DATA_DESTORY, container_virt_to_phys(vaddr), flags, 0, 0, 0, 0, 0, &res);
        if(!res.a0)
            ret = true;
    }else{
        pr_alert("%s: the free data %#lx is not in container region! ", __func__, vaddr);
    }

    return ret;
}



bool container_memcpy(void *dest, void *source, size_t size)
{
    struct arm_smccc_res res;
    static int count;

    if(!in_container_region(dest))
        pr_alert("%s: not container memcopy dest %#lx, paddr %#lx, size %d", __func__, dest, container_virt_to_phys(dest), size);
    count ++;
    // if(count % 50 == 0){
    //     pr_alert("%s: count %d, current %#lx, name %s", __func__, count, current, current->comm);
    // }
    if(in_container_region(source)){
        arm_smccc_smc(OPTEE_SMC_CONTAINER_REGION_MEMCPY, container_virt_to_phys(source), container_virt_to_phys(dest), size, 0, 0, 0, 0, &res);
    }else{
        arm_smccc_smc(OPTEE_SMC_CONTAINER_REGION_MEMCPY, __pa(source), container_virt_to_phys(dest), size, 0, 0, 0, 0, &res);
    }

    if(res.a0)
        return false;
    return true;
}

int get_container_data_flag(struct task_struct *tsk)
{
    int flag = 0;

    if(in_container_range(tsk->nsproxy, NSPROXY) || (get_flag(tsk->nsproxy) == CONTAINER_NSPROXY))
        flag |= CONTAINER_NSPROXY;
    if(in_container_range(tsk->cred, CRED) || (get_flag(tsk->cred) == CONTAINER_CRED))
        flag |= CONTAINER_CRED;
    if(in_container_range(tsk->fs, FS) || (get_flag(tsk->fs) == CONTAINER_FS))
        flag |= CONTAINER_FS;
    if(in_container_range(tsk->nsproxy->mnt_ns, MNT_NS))
        flag |= CONTAINER_MNT_NS;
    if(in_container_range(tsk->cred->user_ns, USER_NS))
        flag |= CONTAINER_USER_NS;


    return (flag ^ 0x7f);
}

bool copy_container_data_to_region(struct task_struct *tsk, int flag){
    struct container_task *con_tsk, *p_con_tsk;
    struct cred *k_cred;
    struct nsproxy *k_nsproxy;
    struct fs_struct *k_fs;
    void *shm_va;
    phys_addr_t k_nsproxy_pa, k_cred_pa, k_fs_pa, p_con_tsk_pa, con_fs_pa;
    static int cred_count;
    static int shadow_count;
     struct fs_struct *con_fs;

    con_tsk = get_container_task(tsk);
    k_nsproxy = tsk->nsproxy; 
    k_cred = tsk->cred;
    k_fs = tsk->fs;

    p_con_tsk_pa = 0;
    k_nsproxy_pa = 0;
    k_cred_pa = 0;
    k_fs_pa = 0;

    if(get_flag(k_nsproxy) == CONTAINER_NSPROXY)
        k_nsproxy = get_con_value(k_nsproxy);
    if(k_nsproxy && in_container_range(k_nsproxy, NSPROXY))
        k_nsproxy_pa = container_virt_to_phys(k_nsproxy);
    else if(k_nsproxy)
        k_nsproxy_pa = __pa(k_nsproxy);

    if(get_flag(k_cred) == CONTAINER_CRED)
        k_cred = get_con_value(k_cred);
    if(k_cred && in_container_range(k_cred, CRED))
        k_cred_pa = container_virt_to_phys(k_cred);
    else if(k_cred)
        k_cred_pa = __pa(k_cred);
    
    if(get_flag(k_fs) == CONTAINER_FS)
        k_fs = get_con_value(k_fs);
    if(k_fs && in_container_range(k_fs, FS))
        k_fs_pa = container_virt_to_phys(k_fs);
    else if(k_fs)
        k_fs_pa = __pa(k_fs);


    if((flag & CONTAINER_NSPROXY)){
        
        if(k_nsproxy && !(in_container_range(k_nsproxy, NSPROXY) || get_flag(k_nsproxy) == CONTAINER_NSPROXY)){
            struct container_nsproxy *c_nsp;
            c_nsp = get_container_nsproxy(__pa(k_nsproxy));

            if(c_nsp){
                k_nsproxy = &(c_nsp->k_nsp);
            }else{
                c_nsp = (struct container_nsproxy *)container_pool_alloc(nsproxy_pool, sizeof(struct container_nsproxy));
                if(!c_nsp){
                    pr_alert("nsproxy region exhausted!!!!!");
                    return false;
                }

                if(!con_tsk){
                    con_tsk = (struct container_task *)container_pool_alloc(task_pool, sizeof(struct container_task));
    
                    if(!con_tsk){
                        pr_alert("container task alloc error or region exhausted!!!!!");
                        return false;
                    }

                    if(!container_data_init(CONTAINER_TSK | CONTAINER_NSPROXY, c_nsp, tsk, container_virt_to_phys(con_tsk), k_nsproxy_pa, k_cred_pa, k_fs_pa))
                        pr_alert("%s: secure world init con tsk %#lx error !!", __func__, con_tsk);

                }else{
                    if(!container_data_init(CONTAINER_NSPROXY, c_nsp, tsk, k_nsproxy_pa, k_nsproxy_pa, k_cred_pa, k_fs_pa))
                        pr_alert("%s: secure world init NSPROXY %#lx error !!", __func__, tsk->nsproxy);
                }
            
                k_nsproxy = &(c_nsp->k_nsp);

            }
            // pr_alert("%s: nsproxy copy, tsk %#lx, tsk->nsproxy: %#lx, count %d, uts_ns %#lx, con_tsk: %#lx, k_nsproxy: %#lx, count %d, uts_ns %#lx,con_tsk->con_nsp %#lx, mask_ns %#lx", __func__, tsk, tsk->nsproxy, tsk->nsproxy->count, tsk->nsproxy->uts_ns, con_tsk, k_nsproxy, k_nsproxy->count, k_nsproxy->uts_ns, con_tsk->con_nsp, mask_con_value(NSPROXY, k_nsproxy));

            rcu_assign_pointer(tsk->nsproxy, k_nsproxy); 
            // rcu_assign_pointer(tsk->nsproxy, mask_con_value(NSPROXY, k_nsproxy)); 
 
        }

    }

#ifdef CON_CRED
    if((flag & CONTAINER_CRED)){
        
        if(k_cred && !(in_container_range(k_cred, CRED) || get_flag(k_cred) == CONTAINER_CRED)){
            struct container_cred *c_cred;
            c_cred = get_container_cred(__pa(k_cred));
            
            if(c_cred){
                k_cred = &(c_cred->k_cred);

            }else{
                c_cred = (struct container_cred *)container_pool_alloc(cred_pool, sizeof(struct container_cred));
                if(!c_cred){
                    pr_alert("cred region exhausted!!!!!");
                    return false;
                }

                cred_count++;

                if(!container_data_init(CONTAINER_CRED, c_cred, tsk, k_cred_pa, k_nsproxy_pa, k_cred_pa, k_fs_pa))
                    pr_alert("%s: secure world init CRED %#lx error !!", __func__, k_cred);
                k_cred = &(c_cred->k_cred);
                // pr_alert("%s: cred copy, tsk %#lx, offset %#lx, tsk->nsproxy: %#lx,  uid %d, k_cred_pa %#lx, con_tsk: %#lx, k_cred %lx, con_cred %#lx, usage %d, con_cred->uid %d, con_cred->euid %d, cap %#lx", __func__, tsk, offsetof(struct container_cred, k_cred), tsk->nsproxy, tsk->cred->uid, k_cred_pa, con_tsk, tsk->cred, k_cred, k_cred->usage, k_cred->uid, k_cred->euid, k_cred->cap_effective);
            }
            if(is_container && !k_cred->uid.val)
                 pr_alert("%s: RET_IP %#lx, task %s, nsproxy %#lx, cred %#lx, uid %d, con_cred %#lx, uid %d, euid %d, cap %x, flags %#x", __func__, _RET_IP_, tsk->comm, tsk->nsproxy, tsk->cred, tsk->cred->uid.val, k_cred, k_cred->uid.val, k_cred->euid.val, k_cred->cap_effective, flag);

            // rcu_assign_pointer(tsk->cred, mask_con_value(CRED, k_cred));
            rcu_assign_pointer(tsk->cred, k_cred);
        }
    }
#endif

#ifdef CON_FS
    if((flag & CONTAINER_FS)){
        struct container_fs * con_fs;
        struct fs_struct *new_k_fs;
        phys_addr_t new_k_fs_pa;
        if(k_fs){
            con_fs = (struct container_fs *)container_pool_alloc(fs_pool, sizeof(struct container_fs));
            if(!con_fs){
                pr_alert("fs region exhausted!!!!!");
                return false;
            }
            // normal memory fs of con_fs 
           
            new_k_fs = copy_fs_struct(k_fs);
            new_k_fs_pa = __pa(new_k_fs);
            
            if(!con_tsk){
                con_tsk = (struct container_task *)container_pool_alloc(task_pool, sizeof(struct container_task));

                if(!con_tsk){
                    pr_alert("container task alloc error or region exhausted!!!!!");
                    return false;
                }
                // pr_alert("%s: shadow tsk and fs --------------  ", __func__);
                if(!container_data_init(CONTAINER_TSK | CONTAINER_FS, con_fs, tsk, container_virt_to_phys(con_tsk), k_nsproxy_pa, k_cred_pa, new_k_fs_pa))
                    pr_alert("%s: secure world init con tsk %#lx error !!", __func__, con_tsk);

            }else{
                if(!container_data_init(CONTAINER_FS, con_fs, tsk, new_k_fs_pa, k_nsproxy_pa, k_cred_pa, k_fs_pa))
                    pr_alert("%s: secure world init FS %#lx error !!", __func__, con_fs);
                 
            }
            
            task_lock(tsk);
            // tsk->fs = mask_con_value(FS, &(con_fs->fs));
            tsk->fs = &(con_fs->fs); 
            task_unlock(tsk);

            // pr_alert("%s: fs copy, tsk %#lx, tsk->fs: %#lx, con_tsk: %#lx, k_fs: %#lx, pa %#lx, con_fs %#lx, new_k_fs_pa %#lx, con_fs->paddr %#lx", __func__, tsk, tsk->fs, con_tsk, k_fs, k_fs_pa, con_fs, new_k_fs_pa, con_fs->paddr);
        }

    }
#endif

    if(!con_tsk){
        con_tsk = (struct container_task *)container_pool_alloc(task_pool, sizeof(struct container_task));
        
        shadow_count++;
        if(!con_tsk){
            pr_alert("container task alloc error or region exhausted!!!!!");
            return false;
        }

        p_con_tsk = get_container_task(tsk);
        if(p_con_tsk)
            p_con_tsk_pa = container_virt_to_phys(p_con_tsk);

        if(!container_data_init(CONTAINER_TSK, con_tsk, tsk, p_con_tsk_pa, k_nsproxy_pa, k_cred_pa, k_fs_pa))
            pr_alert("%s: secure world init %#lx error !!", __func__, con_tsk);
        
        // pr_alert_once("%s: tsk %#lx, cred %#lx, nsproxy %#lx, con_tsk %#lx, con_tsk->con_nsp %#lx, con_cred %#lx, uid %d", __func__, tsk, tsk->cred, tsk->nsproxy, con_tsk, con_tsk->con_nsp, con_tsk->con_cred, con_tsk->con_cred->uid);

    }

    return true;
}

bool copy_user_ns_data_to_region(struct task_struct *tsk, struct cred *cred){
    struct user_namespace *k_user_ns, *new_user_ns;
    struct container_user_ns *con_user_ns;
    k_user_ns = cred->user_ns;

    if(!in_container_range(k_user_ns, USER_NS)){
        con_user_ns = (struct container_user_ns *)container_pool_alloc(user_ns_pool, sizeof(struct container_user_ns));
        if(!con_user_ns){
            pr_alert("user_ns region exhausted!!!!!");
            return false;
        }
        new_user_ns = &(con_user_ns->user_ns);

        if(!container_memcpy(new_user_ns, k_user_ns, sizeof(struct user_namespace))){
            pr_alert("%s: secure world copy user ns %#lx errorrrrrr", __func__, k_user_ns);
            return false;
        }
        // pr_alert("%s: user_namespace copy, tsk %#lx, tsk->cred: %#lx, tsk->cred->user_ns: %#lx,  cred %#lx, cred->user_ns: %#lx, paddr %#lx, count %d, parent %#lx, con_user_ns %#lx, new_user_ns %#lx, parent %#lx, paddr %#lx", __func__, tsk, tsk->cred, tsk->cred->user_ns, cred, k_user_ns, __pa(k_user_ns), atomic_read(&k_user_ns->count), k_user_ns->parent, con_user_ns, new_user_ns, new_user_ns->parent, con_user_ns->paddr);
        cred->user_ns = new_user_ns;

    }
    return true;
}

bool copy_mnt_ns_data_to_region(struct mnt_namespace **mnt_ns){
    struct container_mnt_ns *con_mnt_ns;
    struct mnt_namespace *new_ns;

    if(*mnt_ns && !in_container_range(*mnt_ns, MNT_NS)){
        con_mnt_ns = (struct container_mnt_ns *)container_pool_alloc(mnt_ns_pool, sizeof(struct container_mnt_ns));
        if(!con_mnt_ns){
            pr_alert("mnt_ns region exhausted!!!!!");
            return false;
        }
        new_ns = &(con_mnt_ns->mnt_ns);
        if(!container_memcpy(con_mnt_ns, *mnt_ns, sizeof(struct mnt_namespace))){
            pr_alert("%s: secure world copy mnt ns %#lx errorrrrrr", __func__, *mnt_ns);
            return false;
        }
        // pr_alert("%s: mnt_namespace copy, tsk %#lx, current mnt ns: %#lx, copy mnt ns: %#lx, new mnt ns %#lx, con_mnt_ns: %#lx", __func__, current, current->nsproxy->mnt_ns, *mnt_ns, new_ns, con_mnt_ns);
        
        *mnt_ns = new_ns;
        
    }
    return true;
}

bool copy_mount_data_to_region(struct mount **mnt){
    struct container_mount *con_mount;
    struct mount *new_mount;
    static int mnt_count;

    if(*mnt && !in_container_range(*mnt, MOUNT)){
        con_mount = (struct container_mount *)container_pool_alloc(mnt_pool, sizeof(struct container_mount));

        if(!con_mount){
            pr_alert("mount region exhausted!!!!!");
            return false;
        }
        new_mount = &(con_mount->mnt);

        if(!container_memcpy(new_mount, *mnt, sizeof(struct mount))){
            pr_alert("%s: secure world copy mnt ns %#lx errorrrrrr", __func__, *mnt);
            return false;
        }
        mnt_count++;
        // pr_alert("%s: %d mount copy, tsk %#lx, current mnt ns: %#lx, copy mount: %#lx, mnt_id offset %#lx, mnt_id %d, new_mount %#lx, mnt_id %d, mnt_parent %#lx, con_mount: %#lx", __func__, mnt_count, current, current->nsproxy->mnt_ns, *mnt, offsetof(struct mount, mnt_id), (*mnt)->mnt_id, new_mount, new_mount->mnt_id, new_mount->mnt_parent, con_mount);
        
        *mnt = new_mount;

    }
    return true;
}
