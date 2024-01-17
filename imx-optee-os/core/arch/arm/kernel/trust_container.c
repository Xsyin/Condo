/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, xsyin Limited
 */

#include <kernel/trust_container.h>
#include <mm/core_memprot.h>   // phys_to_virt
#include <trace.h>     // DMSG
#include <string.h>    // memcpy
#include <atomic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_time.h>
#include <kernel/misc.h>
#include <kernel/delay.h>
#include <kernel/panic.h> // panic
#include <kernel/thread.h> // thread_get_id

#define	SLIST_HEAD_CONTAINER(name, type)						\
struct name {								\
	struct type *slh_first;	/* first element */			\
	unsigned int slh_lock;	/* list lock */			\
}

#define	SLIST_INIT_CONTAINER(head) do {						\
	(head)->slh_first = NULL;					\
	(head)->slh_lock = 0;					\
} while (/* CONSTCOND */0)

#if 0
#ifndef CONTAINER_PRINT
#define CONTAINER_PRINT
#endif
#else
#ifdef CONTAINER_PRINT
#undef CONTAINER_PRINT
#endif
#endif

#define PRINT_INTERVAL 10

unsigned long error_paddr;
static uint64_t con_normal_vaddr_paddr_off;
static uint64_t con_secure_paddr_vaddr_off;
static SLIST_HEAD_CONTAINER(container_tsk_head, container_task) *task_hashtable;
static SLIST_HEAD_CONTAINER(container_cred_head, container_cred) *cred_hashtable;
static SLIST_HEAD(container_nsp_head, container_nsproxy) *nsproxy_hashtable;
// static unsigned int task_slist_lock = SPINLOCK_UNLOCK;
// static unsigned int cred_slist_lock = SPINLOCK_UNLOCK;
static unsigned int nsproxy_slist_lock = SPINLOCK_UNLOCK;

#define container_secure_vaddr_to_normal(vaddr) ((uint64_t)virt_to_phys(vaddr) + con_normal_vaddr_paddr_off)
#define container_normal_vaddr_to_paddr(vaddr) ((uint64_t)(vaddr) - con_normal_vaddr_paddr_off)
#define container_secure_paddr_to_vaddr(paddr) ((uint64_t)(paddr) - con_secure_paddr_vaddr_off)

#define	SLIST_INSERT_HEAD_CONTAINER(head, elm, field) do {			\
	(elm)->field.sle_next = (head)->slh_first;			\
	if((head)->slh_first)                               \
		(elm)->normal_next = (void *)container_secure_vaddr_to_normal((head)->slh_first);			\
	(head)->slh_first = (elm);					\
} while (/* CONSTCOND */0)

#define	SLIST_REMOVE_CONTAINER(head, elm, type, field) do {			\
	if ((head)->slh_first == (elm)) {				\
		SLIST_REMOVE_HEAD((head), field);			\
		elm->normal_next = NULL;			\
	}								\
	else {								\
		struct type *curelm = (head)->slh_first;		\
		while(curelm->field.sle_next != (elm))			\
			curelm = curelm->field.sle_next;		\
		curelm->field.sle_next =				\
		    curelm->field.sle_next->field.sle_next;		\
		curelm->normal_next = (elm)->normal_next;			\
	}								\
} while (/* CONSTCOND */0)


static inline struct container_tsk_head *task_hash(paddr_t tsk)
{
	unsigned long tmp = ((unsigned long)tsk & (SZ_1M - 1)) / 8;
	return &task_hashtable[tmp];
}

static inline struct container_cred_head *cred_hash(paddr_t k_cred)
{
	unsigned long tmp = ((unsigned long)k_cred & (SZ_1M - 1)) / 8;
	return &cred_hashtable[tmp];
}

static inline struct container_nsp_head *nsproxy_hash(paddr_t k_nsp)
{
	unsigned long tmp = ((unsigned long)k_nsp & (SZ_1M - 1)) / 8;
	return &nsproxy_hashtable[tmp];
}

struct container_task *get_container_task(paddr_t tsk)
{
	struct container_tsk_head *head = task_hash(tsk);
	struct container_task *p;
	uint32_t tsk_exceptions;

	if(!(head->slh_first))
		return NULL;

    if(!in_container_range(head->slh_first+con_secure_paddr_vaddr_off, TSK)){
        return NULL;
    }

	tsk_exceptions = cpu_spin_lock_xsave(&(head->slh_lock));
    SLIST_FOREACH(p, head, next){
		if (p != NULL && p->tsk_paddr == tsk)
		{
			cpu_spin_unlock_xrestore(&(head->slh_lock), tsk_exceptions);
			return p;
		}
    }
	cpu_spin_unlock_xrestore(&(head->slh_lock), tsk_exceptions);

	return NULL;
}

struct container_cred *get_container_cred(paddr_t k_cred)
{
	struct container_cred_head *head = cred_hash(k_cred);
	struct container_cred *p;
	uint32_t cred_exceptions;

    if(!in_container_range(head->slh_first+con_secure_paddr_vaddr_off, CRED)){
        return NULL;
    }

	cred_exceptions = cpu_spin_lock_xsave(&(head->slh_lock));
    SLIST_FOREACH(p, head, next){
		if (p != NULL && p->paddr == k_cred){

			cpu_spin_unlock_xrestore(&(head->slh_lock), cred_exceptions);
			return p;
		}
    }
	cpu_spin_unlock_xrestore(&(head->slh_lock), cred_exceptions);
	return NULL;
}

struct container_nsproxy *get_container_nsproxy(paddr_t k_nsp)
{
	struct container_nsp_head *head = nsproxy_hash(k_nsp);
	struct container_nsproxy *p;
	uint32_t nsp_exceptions;

    if(!in_container_range(head->slh_first+con_secure_paddr_vaddr_off, NSPROXY)){
        return NULL;
    }

	nsp_exceptions = cpu_spin_lock_xsave(&nsproxy_slist_lock);
    SLIST_FOREACH(p, head, next){
		if (p != NULL && p->paddr == k_nsp){
			cpu_spin_unlock_xrestore(&nsproxy_slist_lock, nsp_exceptions);
			return p;
		}
    }
	cpu_spin_unlock_xrestore(&nsproxy_slist_lock, nsp_exceptions);

	return NULL;
}

void tee_entry_init_container_region(struct thread_smc_args *args)
{
	con_normal_vaddr_paddr_off = args->a1;

	memset(tee_container_vaddr, 0, TEE_CONTAINER_SIZE / 2);
	memset(tee_container_vaddr + TEE_CONTAINER_SIZE / 2, 0, TEE_CONTAINER_SIZE / 2);
	task_hashtable = (struct container_tsk_head *)phys_to_virt(CONTAINER_REGION_HTSK_START, MEM_AREA_TEE_CONTAINER);
	SLIST_INIT(task_hashtable);
    cred_hashtable = (struct container_cred_head *)phys_to_virt(CONTAINER_REGION_HCRED_START, MEM_AREA_TEE_CONTAINER);
    SLIST_INIT_CONTAINER(cred_hashtable);
	nsproxy_hashtable = (struct container_nsp_head *)phys_to_virt(CONTAINER_REGION_HNSPROXY_START, MEM_AREA_TEE_CONTAINER);
	SLIST_INIT(nsproxy_hashtable);
	
	con_secure_paddr_vaddr_off = (uint64_t)CONTAINER_REGION_TSK_START - (uint64_t)phys_to_virt(CONTAINER_REGION_TSK_START, MEM_AREA_TEE_CONTAINER);
	args->a0 = OPTEE_SMC_RETURN_OK;
	args->a1 = con_secure_paddr_vaddr_off;
	// args->a2 = container_nsec_shm_paddr;
	// args->a3 = container_nsec_shm_size;

	DMSG("tsk start %#lx, end %#lx, size: tsk %#lx, nsproxy %#lx, cred %#lx, fs_struct %#lx, offset: lock %#lx, seq %#lx, umask %#lx, in_exec %#lx, root %#lx ", CONTAINER_REGION_TSK_START, CONTAINER_REGION_TSK_END, sizeof(struct task_struct), sizeof(struct nsproxy), sizeof(struct cred), sizeof(struct fs_struct), offsetof(struct fs_struct, lock), offsetof(struct fs_struct, seq), offsetof(struct fs_struct, umask), offsetof(struct fs_struct, in_exec), offsetof(struct fs_struct, root));
	DMSG("offset: head in fs_pin %#lx",  offsetof(struct fs_pin, head));

}

void tee_entry_update_container_region(struct thread_smc_args *args)
{
    static int all_count, tsk_count, cred_count, ns_count, user_ns_count, mnt_ns_count, mnt_count, fs_count;
    paddr_t tsk_paddr, dest_paddr;
    unsigned long Rt2_value, Rt_value;
    uint64_t *dest_vaddr;
    unsigned int instr, flag, bit_inst;

    uint64_t *l_value;
	uint32_t *i_value;
	uint16_t *s_value;
	uint8_t *c_value;

    dest_paddr = args->a1;
	tsk_paddr = args->a2;
	Rt_value = args->a3;
	Rt2_value = args->a4;
	flag = args->a5;
	instr = args->a6;

    args->a0 = OPTEE_SMC_RETURN_EBADADDR;

    if( !in_container_range(dest_paddr, PADDR) ){
		EMSG("bad dest_paddr!!");
		return;
	}

	// DMSG("UPPPPDATE dest_paddr %#lx", dest_paddr);
    // dest_vaddr = (uint64_t *)phys_to_virt(dest_paddr, MEM_AREA_TEE_CONTAINER);
    dest_vaddr = (uint64_t *)container_secure_paddr_to_vaddr(dest_paddr);
	error_paddr = dest_vaddr;
	bit_inst = get_stp_str_bit_instr(instr);

	all_count++;
    switch(flag){
		case stp_flag(64):
			// if(bit_inst == STP_INST_64){
				l_value = (uint64_t *)dest_vaddr;
				*l_value = (uint64_t)Rt_value;
				*(l_value + 1) = (uint64_t)Rt2_value;
				args->a0 = OPTEE_SMC_RETURN_OK;
			// }
			break;
		case stp_flag(32):
			// if(bit_inst == STP_INST_32){
				i_value = (uint32_t *)dest_vaddr;
				*i_value = (uint32_t)Rt_value;
				*(i_value + 1) = (uint32_t)Rt2_value;
				args->a0 = OPTEE_SMC_RETURN_OK;
			// }
			break;
		case str_flag(64):
			// if(bit_inst == STR_INST_64){
				l_value = (uint64_t *)dest_vaddr;
				*l_value = (uint64_t)Rt_value;
				args->a0 = OPTEE_SMC_RETURN_OK;
			// }
			break;
		case str_flag(32):
				i_value = (uint32_t *)dest_vaddr;
				*i_value = (uint32_t)Rt_value;
				args->a0 = OPTEE_SMC_RETURN_OK;
			break;
		case str_flag(16):
			// if(bit_inst == STR_INST_16 && Rt2_value == 0){
				s_value = (uint16_t *)dest_vaddr;
				*s_value = (uint16_t)Rt_value;
				args->a0 = OPTEE_SMC_RETURN_OK;
			// }
			break;
		case str_flag(8):
				c_value = (uint8_t *)dest_vaddr;
				*c_value = (uint8_t)Rt_value;
				args->a0 = OPTEE_SMC_RETURN_OK;
			
			break;
		case DC_FLAG:
			memset(dest_vaddr, 0, read_dczid_el0()<<4);
			args->a0 = OPTEE_SMC_RETURN_OK;
			break;
		default:
			EMSG("instruction error! instruction: %08x", instr);
	}
	// if(all_count % 1000 == 0)
	// 	DMSG("all_count %d, mnt_count %d,  tsk_count %d, fs_count %d, cred_count %d, ns_count %d, user_ns_count %d, mnt_ns_count %d, Rt_value %#lx, dest_vaddr %#lx", all_count, mnt_count, tsk_count, fs_count, cred_count, ns_count, user_ns_count, mnt_ns_count, Rt_value, dest_vaddr);


    if(in_container_range(dest_paddr, CRED)){
		cred_count++;
        struct cred *cred = (struct cred *)get_con_struct(dest_vaddr, sizeof(struct cred));
		if(cred->uid.val == 0 || cred->euid.val == 0)
			EMSG("exist attack, uid = 0");
#ifdef CONTAINER_PRINT
		if(cred_count % PRINT_INTERVAL == 0){

        	DMSG(" CREDCREDCRED cred_count %d, all_count %d, ns_count %d, user_ns_count %d, fs_count %d, dest_vaddr %#lx, Rt_value %#lx, cred: %#lx", cred_count, all_count, ns_count, user_ns_count, fs_count, dest_vaddr, Rt_value, cred+0x10);
		}
#endif
    }
	if(in_container_range(dest_paddr, TSK)){
        // struct container_task *con_tsk = (struct container_task *)mask_con_tsk(dest_vaddr);
		tsk_count++;
		// if(tsk_count > 100 && tsk_count % 100 == 0)
        	// DMSG("TSK tsk_count %d, dest_paddr %#lx, dest_vaddr %#lx, value: %#llx, con_tsk %#lx, con_cred %#lx, con_nsp %#lx", tsk_count, dest_paddr, dest_vaddr, Rt_value, con_tsk, con_tsk->con_cred, con_tsk->con_nsp);
    }
	if(in_container_range(dest_paddr, NSPROXY)){
		ns_count++;
#ifdef CONTAINER_PRINT
		if(ns_count % PRINT_INTERVAL == 0){
        	unsigned int ns = get_con_struct(dest_vaddr, sizeof(struct nsproxy));
        	DMSG(" NSNSNSNS ns_count %d, all_count %d,  dest_vaddr %#lx, Rt_value %#lx, ns: %#lx", ns_count, all_count, dest_vaddr, Rt_value, ns+0x10);
		}
#endif
    }

	if(in_container_range(dest_paddr, USER_NS)){
		user_ns_count++;
#ifdef CONTAINER_PRINT
		if(user_ns_count % PRINT_INTERVAL == 0){
			unsigned int user_ns = get_con_struct(dest_vaddr, sizeof(struct user_namespace));
        	DMSG("USER_NS user_ns_count %d, all_count %d, dest_vaddr %#lx, value: %#llx, user_ns %#lx", user_ns_count, all_count, dest_vaddr, Rt_value, user_ns);
		}
#endif
    }

	if(in_container_range(dest_paddr, FS)){
		fs_count++;
#ifdef CONTAINER_PRINT
		if(fs_count % PRINT_INTERVAL == 0){
			unsigned int fs = get_con_struct(dest_vaddr, sizeof(struct fs_struct));
			DMSG("fs_count %d, all_count %d, cred_count %d, instr %#lx, Rt_value %#lx, Rt2_value %#lx, fs %#lx, dest_vaddr %#lx", fs_count, all_count, cred_count, instr, Rt_value, Rt2_value, fs, dest_vaddr);
		}
#endif
    }

	if(in_container_range(dest_paddr, MNT_NS)){
		mnt_ns_count++;
#ifdef CONTAINER_PRINT
		if(mnt_ns_count % PRINT_INTERVAL == 0){
			unsigned int mnt_ns = get_con_struct(dest_vaddr, sizeof(struct mnt_namespace));
			DMSG("mnt_ns_count %d, all_count %d, Rt_value %#lx, mnt_ns %#lx, dest_vaddr %#lx", mnt_count, Rt_value, mnt_ns, dest_vaddr);
		}
#endif
    }

	if(in_container_range(dest_paddr, MOUNT)){
		mnt_count++;
#ifdef CONTAINER_PRINT
		if(mnt_count % PRINT_INTERVAL == 0){
			unsigned int mnt = get_con_struct(dest_vaddr, sizeof(struct mount));
			DMSG("mnt_count %d, all_count %d, fs_count %d, cred_count %d, Rt_value %#lx, mnt %#lx, dest_vaddr %#lx", mnt_count, all_count, fs_count, cred_count, Rt_value, mnt, dest_vaddr);
		}
#endif
    }

    args->a0 = OPTEE_SMC_RETURN_OK;

    return;
}

void tee_entry_memcpy_container_region(struct thread_smc_args *args)
{
	paddr_t source_paddr, dest_paddr;
    uint64_t *source_vaddr, *dest_vaddr;
	size_t size;
    struct mobj *mobj = NULL;
	unsigned long *paddr;
	static int memcpy_count, user_ns_count, mnt_ns_count, mount_count;

    source_paddr = args->a1;
    dest_paddr = args->a2;
    size = args->a3;
    args->a0 = OPTEE_SMC_RETURN_EBADADDR;
    
	memcpy_count++;
	// if(memcpy_count % 50 == 0)
	// 	DMSG("memcpy_count %d, user_ns_count %d, entry_count %d,  mnt_ns_count %d, mount_count %d, dest_vaddr %#lx, size %#lx-----", memcpy_count, user_ns_count, entry_count, mnt_ns_count, mount_count, dest_vaddr, size);
	if(!source_paddr || !in_container_range(dest_paddr, PADDR) ){
		EMSG("bad paddr or vaddr!! dest_paddr %#lx, source_paddr %#lx", dest_paddr, source_paddr);
		return;
	}
    dest_vaddr = (uint64_t *)phys_to_virt(dest_paddr, MEM_AREA_TEE_CONTAINER);

	if(in_container_range(source_paddr, PADDR)){
		source_vaddr = (uint64_t *)phys_to_virt(source_paddr, MEM_AREA_TEE_CONTAINER);
	}else{
		mobj = map_normal_memory_to_shm(source_paddr, size);
		source_vaddr = mobj_get_va(mobj, 0);
		paddr = (unsigned long *)((uint64_t)dest_vaddr + size);
		// DMSG("source_paddr %#lx, dest_vaddr %#lx, size %#lx paddr %#lx-----", source_paddr, dest_vaddr, size, paddr);

		*paddr = source_paddr;
	}

    memcpy(dest_vaddr, source_vaddr, size);
	// DMSG("dest_vaddr %#lx, size %#lx paddr %#lx, *paddr %#lx-----", dest_vaddr, size, paddr, *paddr);
	if(in_container_range(dest_paddr, USER_NS)){
		user_ns_count++;
		// DMSG("user_ns_count %d, entry_count %d, memcpy_count %d, mnt_ns_count %d, mount_count %d, dest_vaddr %#lx, size %#lx-----", user_ns_count, entry_count, memcpy_count, mnt_ns_count, mount_count, dest_vaddr, size);
	}

	if(in_container_range(dest_paddr, MNT_NS)){
		mnt_ns_count++;
		// DMSG("mnt_ns_count %d, user_ns_count %d, entry_count %d, memcpy_count %d,  mount_count %d, dest_vaddr %#lx, size %#lx-----",  mnt_ns_count, user_ns_count, entry_count, memcpy_count, mount_count, dest_vaddr, size);
	}

	if(in_container_range(dest_paddr, MOUNT)){
		mount_count++;
		struct list_head * head;
		unsigned long normal_mount = dest_paddr + con_normal_vaddr_paddr_off;
		struct mount *mnt = (struct mount *)dest_vaddr;
		// init mount
		head = (struct list_head *)(normal_mount + offsetof(struct mount, mnt_child));
		INIT_LIST_HEAD(&mnt->mnt_child, head);
		head = (struct list_head *)(normal_mount + offsetof(struct mount, mnt_mounts));
		INIT_LIST_HEAD(&mnt->mnt_mounts, head);
		head = (struct list_head *)(normal_mount + offsetof(struct mount, mnt_list));
		INIT_LIST_HEAD(&mnt->mnt_list, head);
		head = (struct list_head *)(normal_mount + offsetof(struct mount, mnt_expire));
		INIT_LIST_HEAD(&mnt->mnt_expire, head);
		head = (struct list_head *)(normal_mount + offsetof(struct mount, mnt_share));
		INIT_LIST_HEAD(&mnt->mnt_share, head);
		head = (struct list_head *)(normal_mount + offsetof(struct mount, mnt_slave_list));
		INIT_LIST_HEAD(&mnt->mnt_slave_list, head);
		head = (struct list_head *)(normal_mount + offsetof(struct mount, mnt_slave));
		INIT_LIST_HEAD(&mnt->mnt_slave, head);
		head = (struct list_head *)(normal_mount + offsetof(struct mount, mnt_umounting));
		INIT_LIST_HEAD(&mnt->mnt_umounting, head);
		head = (struct list_head *)(normal_mount + offsetof(struct mount, mnt_umount) + offsetof(struct fs_pin, head));
		INIT_LIST_HEAD(&mnt->mnt_umount.head, head);

		// DMSG("  mount_count %d, mnt_ns_count %d, user_ns_count %d, entry_count %d, memcpy_count %d, dest_vaddr %#lx, size %#lx-----", mount_count, mnt_ns_count, user_ns_count, entry_count, memcpy_count,  dest_vaddr, size);
	}

	if(mobj)
		mobj_free(mobj);
		
	args->a0 = OPTEE_SMC_RETURN_OK;

}


struct mobj *map_normal_memory_to_shm(paddr_t normal_paddr, size_t size)
{
	paddr_t *pages, page_offset, paddr;
	size_t num_pages, cnt;
	struct mobj *mobj;
	mobj = NULL;

	page_offset = normal_paddr & SMALL_PAGE_MASK;
	num_pages = (size + page_offset - 1) / SMALL_PAGE_SIZE + 1;
	paddr = normal_paddr  & ~SMALL_PAGE_MASK;
	pages = malloc(num_pages * sizeof(paddr_t));
	if (!pages)
		return NULL;

	for (cnt = 0; cnt < num_pages; cnt++) {
		pages[cnt] = paddr + cnt * SMALL_PAGE_SIZE;
		if (pages[cnt] & SMALL_PAGE_MASK)
			goto out;
	}

	mobj = mobj_mapped_shm_alloc(pages, num_pages, page_offset, 0);
	if (!mobj){
		DMSG("mobj_mapped_shm_alloc error, normal_paddr %#lx, paddr %#lx, num_pages %d, page_offset %#lx size %d", normal_paddr, paddr, num_pages, page_offset, size);
		return NULL;
	}

out:
	free(pages);
	return mobj;
}

void tee_entry_container_data_init(struct thread_smc_args *args)
{
	paddr_t tsk_paddr, con_paddr, nsproxy_pa, cred_pa, fs_pa;
	unsigned long cred, nsproxy, fs, size_or_pa;
	unsigned int flags;

	struct container_task *con_tsk;
	static int all_count, tsk_count, cred_count, cred_copy_count, ns_count, fs_count;
	
    flags = args->a1;
	con_paddr = args->a2;
    tsk_paddr = args->a3;
    size_or_pa = args->a4;
    nsproxy_pa = args->a5;
    cred_pa = args->a6;
    fs_pa = args->a7;

	cred = 0;
	nsproxy = 0;
	fs = 0;

	error_paddr = cred;
    args->a0 = OPTEE_SMC_RETURN_EBADADDR;


	if(!in_container_region(con_paddr))
		EMSG("ERROR PADDR!!");
	
	con_tsk = get_container_task(tsk_paddr);

	// DMSG("start alloc flags %#lx, tsk_paddr %#lx, con_tsk %#lx, size_or_pa %#lx, cred %#lx, cpu %d", flags, tsk_paddr, con_tsk, size_or_pa, cred, get_core_pos());
	all_count++;

	// if(all_count % 100 == 0)
	// 	DMSG("all_count %d, tsk_count %d, cred_count %d, cred_copy_count %d, ns_count %d, fs_count %d", all_count, tsk_count, cred_count, cred_copy_count, ns_count, fs_count);
	if(!con_tsk && (flags & CONTAINER_TSK)){
		uint32_t tsk_exceptions;
		struct container_task *p_con_tsk;

		tsk_count++;

		if(in_container_range(nsproxy_pa, NSPROXY)){
			nsproxy = nsproxy_pa + con_normal_vaddr_paddr_off;
		}else if(nsproxy_pa){
			nsproxy = nsproxy_pa + TSK_OFFSET;
		}

		if(in_container_range(cred_pa, CRED)){
			cred = cred_pa + con_normal_vaddr_paddr_off;
		}else if(cred_pa){
			cred = cred_pa + TSK_OFFSET;
		}

		if(in_container_range(fs_pa, FS)){
			fs = fs_pa + con_normal_vaddr_paddr_off;
		}else if(fs_pa){
			fs = fs_pa + TSK_OFFSET;
		}

		if(flags == CONTAINER_TSK){
			if(!in_container_range(con_paddr, TSK)){
				DMSG("only CONTAIENR_TSK con_paddr %#lx  is not in shadow task region!!!! ", con_paddr);
			}
			// con_tsk = (struct container_task *)phys_to_virt(con_paddr, MEM_AREA_TEE_CONTAINER);
			con_tsk = (struct container_task *)container_secure_paddr_to_vaddr(con_paddr);
			
			if(size_or_pa && in_container_range(size_or_pa, TSK)){
				// p_con_tsk = (struct container_task *)phys_to_virt(size_or_pa, MEM_AREA_TEE_CONTAINER);
				p_con_tsk = (struct container_task *)container_secure_paddr_to_vaddr(size_or_pa);
				if(nsproxy != (unsigned long)p_con_tsk->con_nsp)
					EMSG("con_tsk %#lx, p_con_tsk %#lx, nsproxy %#lx, p_con_tsk->con_nsp %#lx", con_tsk, p_con_tsk, nsproxy, p_con_tsk->con_nsp);
			}
		}else{
			if(!in_container_range(size_or_pa, TSK)){
				DMSG("CONTAIENR_TSK size_or_pa %#lx  is not in shadow task region!!!! ", size_or_pa);
			}
			// con_tsk = (struct container_task *)phys_to_virt(size_or_pa, MEM_AREA_TEE_CONTAINER);
			con_tsk = (struct container_task *)container_secure_paddr_to_vaddr(size_or_pa);
		} 

		con_tsk->tsk_paddr = tsk_paddr;
		con_tsk->con_nsp = (struct nsproxy *)nsproxy;
		con_tsk->con_cred = (struct cred *)cred;
		con_tsk->con_fs = (struct fs_struct *)fs;
		con_tsk->normal_next = NULL;
		struct container_tsk_head *head = task_hash(tsk_paddr);

		tsk_exceptions = cpu_spin_lock_xsave(&(head->slh_lock));
		SLIST_INSERT_HEAD_CONTAINER(head, con_tsk, next);
		cpu_spin_unlock_xrestore(&(head->slh_lock), tsk_exceptions);

		if(!(con_tsk->con_nsp))
			EMSG("con_nsp is null con_tsk %#lx, nsproxy %#lx, nsproxy_pa %#lx ============================= ", con_tsk, nsproxy, nsproxy_pa);
    	args->a0 = OPTEE_SMC_RETURN_OK;

	}

	if(con_tsk && (flags & CONTAINER_NSPROXY)){
		struct nsproxy *normal_nsp;
		struct cred *init_cred;
		uint32_t nsp_exceptions;
		struct mobj *con_nsp_mobj;
		struct mobj *con_cred_mobj;
		struct container_nsproxy * con_nsp;
		paddr_t normal_nsp_paddr;

		ns_count++;

		if(!in_container_range(con_paddr, NSPROXY)){
			DMSG("flag %#lx con_paddr %#lx  is not in NSPROXY region!!!! ", flags, con_paddr);
		}
		con_nsp = (struct container_nsproxy *)phys_to_virt(con_paddr, MEM_AREA_TEE_CONTAINER);
		// con_nsp = (struct container_nsproxy *)container_secure_paddr_to_vaddr(con_paddr);

		if(nsproxy_pa && !in_container_range(nsproxy_pa, NSPROXY)){

			// map nsproxy to secure world
			con_nsp_mobj = map_normal_memory_to_shm(nsproxy_pa, sizeof(struct nsproxy));
			normal_nsp = mobj_get_va(con_nsp_mobj, 0);
		}else{
			EMSG("nsproxy_pa %#lx, something is wrong");
		}

		if(cred_pa && !in_container_range(cred_pa, CRED)){

			// map contaienr init cred to secure world
			con_cred_mobj = map_normal_memory_to_shm(cred_pa, sizeof(struct cred));
			init_cred = mobj_get_va(con_cred_mobj, 0);
		}
			
		// DMSG("con_tsk %#lx, paddr %#lx, normal_nsp %#lx, normal_nsp_paddr %#lx, init_cred->uid %d, init_cred->cap_effective %#lx, cpu %d", con_tsk, tsk_paddr, normal_nsp, normal_nsp_paddr, init_cred->uid, init_cred->cap_effective, get_core_pos());
		
		con_nsp->paddr = size_or_pa;

		if(flags & CONTAINER_TSK)
			con_nsp->paddr = nsproxy_pa;

		memcpy(&(con_nsp->k_nsp), normal_nsp, sizeof(struct nsproxy));
		memcpy(&(con_nsp->init_con_cred), init_cred, sizeof(struct cred));
			
		con_nsp->normal_next = NULL;

		struct container_nsp_head *head = nsproxy_hash(con_nsp->paddr);
		nsp_exceptions = cpu_spin_lock_xsave(&nsproxy_slist_lock);
		SLIST_INSERT_HEAD_CONTAINER(head, con_nsp, next);
		cpu_spin_unlock_xrestore(&nsproxy_slist_lock, nsp_exceptions);
		con_nsp->k_nsp.count = 1;
		con_tsk->con_nsp = (struct nsproxy *)(con_paddr + offsetof(struct container_nsproxy, k_nsp) + con_normal_vaddr_paddr_off);

		// DMSG("nsp_count %d, con_nsp %#lx, nsproxy paddr %#lx, con_nsp->k_nsp %#lx, uts: %#lx, k_nsp2 %#lx, con_tsk %#lx, con_tsk->con_nsp: %#lx", ns_count, con_nsp, con_nsp->paddr, con_nsp->k_nsp, con_nsp->k_nsp.uts_ns, &(con_nsp->k_nsp), con_tsk, con_tsk->con_nsp);

		if(!(con_tsk->con_nsp))
			EMSG("CONTAINER_NSPROXY con_nsp is null ============================= ");
		if(con_nsp_mobj)
			mobj_free(con_nsp_mobj);
		
		if(con_cred_mobj)
			mobj_free(con_cred_mobj);
    	args->a0 = OPTEE_SMC_RETURN_OK;
	}

	if(flags & CONTAINER_CRED){
		struct cred *shm_cred, *normal_cred;
		uint32_t cred_exceptions;
		struct mobj *con_cred_mobj;

		struct container_cred * con_cred;
		paddr_t shm_cred_paddr, normal_cred_paddr;

		cred_count++;
		con_cred_mobj = NULL;

		if(!in_container_range(con_paddr, CRED)){
			DMSG("flag %#lx con_paddr %#lx  is not in CRED region!!!! ", flags, con_paddr);
		}
		// con_cred = (struct container_cred *)phys_to_virt(con_paddr, MEM_AREA_TEE_CONTAINER);
		con_cred = (struct container_cred *)container_secure_paddr_to_vaddr(con_paddr);

		if(cred_pa && !in_container_range(cred_pa, CRED)){
			
			// map cred to secure world
			con_cred_mobj = map_normal_memory_to_shm(cred_pa, sizeof(struct cred));
			normal_cred = mobj_get_va(con_cred_mobj, 0);
			cred_copy_count++;

		}else if(cred_pa){
			if(!in_container_range(cred_pa, CRED)){
				DMSG("flag %#lx cred_pa %#lx  is not in CRED region!!!! ", flags, cred_pa);
			}
			// normal_cred = (struct cred *)phys_to_virt(cred_pa, MEM_AREA_TEE_CONTAINER);
			normal_cred = (struct cred *)container_secure_paddr_to_vaddr(cred_pa);
		}
		
		// shm_cred_paddr = cred;
		// shm_cred = (struct cred *)phys_to_virt(shm_cred_paddr, MEM_AREA_NSEC_SHM);

		// memcpy(&(con_cred->k_cred), shm_cred, sizeof(struct cred));
		con_cred->paddr = size_or_pa;

		memcpy(&(con_cred->k_cred), normal_cred, sizeof(struct cred));

		con_cred->normal_next = NULL;

		struct container_cred_head *head = cred_hash(con_cred->paddr);

		cred_exceptions = cpu_spin_lock_xsave(&(head->slh_lock));
		SLIST_INSERT_HEAD_CONTAINER(head, con_cred, next);
		cpu_spin_unlock_xrestore(&(head->slh_lock), cred_exceptions);
		if(con_cred->k_cred.uid.val == 0 || con_cred->k_cred.euid.val == 0)
			DMSG("cred_count: %d, cred illeagel !!! cred_copy_count: %d, flag %#lx, paddr %#lx, con_cred %#lx, uid %d, cred paddr %#lx, size_or_pa %#lx, con_cred->paddr %#lx", cred_count, cred_copy_count, flags, tsk_paddr,  con_cred, con_cred->k_cred.uid, cred, size_or_pa, con_cred->paddr);

		con_cred->k_cred.usage = 1;
		if(con_cred_mobj)
			mobj_free(con_cred_mobj);
    	args->a0 = OPTEE_SMC_RETURN_OK;
	}

	if(con_tsk && (flags & CONTAINER_FS)){
		struct fs_struct *normal_fs;
		struct container_fs *con_fs;
		struct mobj *con_fs_mobj;

		con_fs_mobj = NULL;

		if(!in_container_range(con_paddr, FS)){
			DMSG("flag %#lx con_paddr %#lx  is not in FS region!!!! ", flags, con_paddr);
		}
		fs_count ++;
		// con_fs = (struct fs_struct *)phys_to_virt(con_paddr, MEM_AREA_TEE_CONTAINER);
		con_fs = (struct container_fs *)container_secure_paddr_to_vaddr(con_paddr); 

		if(fs_pa && !in_container_range(fs_pa, FS)){
			
			// map fs to secure world
			con_fs_mobj = map_normal_memory_to_shm(fs_pa, sizeof(struct fs_struct));
			normal_fs = mobj_get_va(con_fs_mobj, 0);

		}else if(fs_pa){
			if(!in_container_range(fs_pa, FS)){
				DMSG("flag %#lx fs_pa %#lx  is not in FS region!!!! ", flags, fs_pa);
			}
			// normal_fs = (struct fs_struct *)phys_to_virt(fs_pa, MEM_AREA_TEE_CONTAINER);
			normal_fs = (struct fs_struct *)container_secure_paddr_to_vaddr(fs_pa);

		}
		
		memcpy(&(con_fs->fs), normal_fs, sizeof(struct fs_struct));

		con_fs->fs.users = 1;
		con_fs->fs.in_exec = 0;
		con_fs->paddr = size_or_pa;

		if(flags & CONTAINER_TSK)
			con_fs->paddr = fs_pa;

		con_tsk->con_fs = (struct fs_struct *)(con_paddr + con_normal_vaddr_paddr_off);
		
		if(con_fs_mobj)
			mobj_free(con_fs_mobj);
    	args->a0 = OPTEE_SMC_RETURN_OK;
	}
out:	
    return;
}
void tee_entry_container_data_destory(struct thread_smc_args *args)
{
	paddr_t free_paddr;
	unsigned int flags;
	static int all_count, tsk_count, ns_count, cred_count;

	free_paddr = args->a1;
	flags = args->a2;

	args->a0 = OPTEE_SMC_RETURN_EBADADDR;
	
	error_paddr = free_paddr;
	// DMSG("freeeeeee  free_paddr %#lx, flags %#lx //////////////////// ", free_paddr, flags);

	if(!in_container_region(free_paddr)){
		EMSG("free addr %#lx is not in container region!!!", free_paddr);
		return;
	}
	all_count++;
	// if(all_count % 1000 == 0)
	// 	DMSG("free data: all_count %d, tsk_count %d, ns_count %d, cred_count %d", all_count, tsk_count, ns_count, cred_count);


	if(flags & CONTAINER_TSK){
		struct container_task *con_tsk;
		uint32_t tsk_exceptions;

		if(!in_container_range(free_paddr, TSK)){
			EMSG("free addr %#lx is not in container tsk region!!!", free_paddr);
			return;
		}
		tsk_count++;
		// con_tsk = phys_to_virt(free_paddr, MEM_AREA_TEE_CONTAINER);
		con_tsk = container_secure_paddr_to_vaddr(free_paddr);
		// DMSG("start freeeeeeeeeeeee   con_tsk %#lx, free_paddr %#lx, tsk_paddr %#lx, con_tsk_mm %#lx, cpu %d ", con_tsk, free_paddr, con_tsk->tsk_paddr, con_tsk_mm, get_core_pos());

		// con_tsk_mm = tee_mm_find(&tee_mm_con_tsk, free_paddr);
		
		struct container_tsk_head *head = task_hash(con_tsk->tsk_paddr);

		tsk_exceptions = cpu_spin_lock_xsave(&(head->slh_lock));
		SLIST_REMOVE_CONTAINER(head, con_tsk, container_task, next);
		cpu_spin_unlock_xrestore(&(head->slh_lock), tsk_exceptions);

		// DMSG("freeeeeee  free_paddr %#lx, con_tsk %#lx, con_nsp %#lx success ", free_paddr, con_tsk, con_tsk->con_nsp);
		args->a0 = OPTEE_SMC_RETURN_OK;
	}

	if(flags & CONTAINER_NSPROXY){
		struct container_nsproxy *con_nsp;
		uint32_t nsp_exceptions;


		if(!in_container_range(free_paddr, NSPROXY)){
			EMSG("free addr %#lx is not in container nsproxy region!!!", free_paddr);
			return;
		}
		ns_count++;
		con_nsp = phys_to_virt(free_paddr, MEM_AREA_TEE_CONTAINER);
		// con_nsp = container_secure_paddr_to_vaddr(free_paddr);

		struct container_nsp_head *head = nsproxy_hash(con_nsp->paddr);
		nsp_exceptions = cpu_spin_lock_xsave(&nsproxy_slist_lock);
		SLIST_REMOVE_CONTAINER(head, con_nsp, container_nsproxy, next);
		cpu_spin_unlock_xrestore(&nsproxy_slist_lock, nsp_exceptions);

		// DMSG("freeeeeee con_nsp %#lx, free_paddr %#lx, success ", con_nsp, free_paddr);

		args->a0 = OPTEE_SMC_RETURN_OK;
	}

	if(flags & CONTAINER_CRED){
		struct container_cred *con_cred;
		uint32_t cred_exceptions;

		if(!in_container_range(free_paddr, CRED)){
			EMSG("free addr %#lx is not in container cred region!!!", free_paddr);
			return;
		}
		cred_count++;
		// con_cred = phys_to_virt(free_paddr, MEM_AREA_TEE_CONTAINER);
		con_cred = container_secure_paddr_to_vaddr(free_paddr);

		struct container_cred_head *head = cred_hash(con_cred->paddr);
		// DMSG("freeeeeee con_cred %#lx, free_paddr %#lx, con_cred->paddr %#lx, success ", con_cred, free_paddr, con_cred->paddr);
		cred_exceptions = cpu_spin_lock_xsave(&(head->slh_lock));
		SLIST_REMOVE_CONTAINER(head, con_cred, container_cred, next);
		cpu_spin_unlock_xrestore(&(head->slh_lock), cred_exceptions);
		con_cred->paddr = 0;
		
		args->a0 = OPTEE_SMC_RETURN_OK;
	}
	
	return;
}


// static unsigned int count_lock = SPINLOCK_UNLOCK;
// static unsigned int count_dec_lock = SPINLOCK_UNLOCK;
// static unsigned int count_inc_lock = SPINLOCK_UNLOCK;
#define INTERVAL 100

void tee_entry_uint64_dec(struct thread_smc_args *args)
{
    paddr_t paddr;
    uint32_t *vaddr;
    uint32_t ns_count;
	TEE_Time time;
    paddr = args->a1;
    ns_count = args->a2;
	// int id = get_core_pos();

    args->a0 = OPTEE_SMC_RETURN_EBADADDR;
	// DMSG("!!!!!!!!!!!! paddr %#lx", paddr);
	
	if(!in_container_region(paddr))
		EMSG("ERROR PADDR!!");

	// vaddr = (uint32_t *)phys_to_virt(paddr, MEM_AREA_TEE_CONTAINER);
	vaddr = (uint32_t *)container_secure_paddr_to_vaddr(paddr);
	error_paddr = vaddr;
	// tee_time_get_sys_time(&time);
	// if(ns_count % INTERVAL == 0)
	// 	DMSG("cpu %zu, time %ld ms, vaddr %#lx, *vaddr %d, ns_count %d", id, (time.seconds * 1000 + time.millis),vaddr, *vaddr, ns_count);
	// udelay(250);
	// exceptions = cpu_spin_lock_xsave(&count_lock);
	// (*vaddr)--;
	// cpu_spin_unlock_xrestore(&count_lock, exceptions);

	atomic_dec32(vaddr);
	args->a2 = *vaddr;

	// if(ns_count % 100 == 0)
	// 	DMSG("cpu %zu, vaddr %#lx, *vaddr %d, ns_count %d", get_core_pos(), vaddr, *vaddr, ns_count);
	// cpu_spin_unlock(&count_lock);

	args->a0 = OPTEE_SMC_RETURN_OK;
	args->a1 = ns_count;

	return;
}


void tee_entry_uint64_inc(struct thread_smc_args *args)
{
    paddr_t paddr;
    uint32_t *vaddr;
	uint32_t ns_count;
	TEE_Time time;
    paddr = args->a1;
	ns_count = args->a2;

    args->a0 = OPTEE_SMC_RETURN_EBADADDR;
	// DMSG("!!!!!!!!!!!! paddr %#lx", paddr);
	error_paddr = paddr;
	if(!in_container_region(paddr))
		EMSG("ERROR PADDR!!");
	vaddr = (uint32_t *)phys_to_virt(paddr, MEM_AREA_TEE_CONTAINER);
	// vaddr = (uint32_t *)container_secure_paddr_to_vaddr(paddr);
	
	tee_time_get_sys_time(&time);

	atomic_inc32(vaddr);
	args->a2 = *vaddr;  
	// (*vaddr)++;
	// cpu_spin_unlock(&count_lock);
	args->a0 = OPTEE_SMC_RETURN_OK;
	args->a1 = ns_count;
	
	return;
}