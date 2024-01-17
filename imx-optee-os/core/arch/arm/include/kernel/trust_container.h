/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, xsyin Limited
 */
#ifndef TRUST_CONTAINER_H
#define TRUST_CONTAINER_H

#include <compiler.h>
#include <stdint.h>
#include <types_ext.h>
#include <mm/core_mmu.h>
#include <kernel/trust_container_def.h>
#include <mm/mobj.h>  // mobj_mapped_shm_alloc


#define UID_GID_MAP_MAX_BASE_EXTENTS 5
#define __NEW_UTS_LEN 64


typedef struct {
	uint32_t val;
} kuid_t;

typedef struct {
	uint32_t val;
} kgid_t;

typedef struct kernel_cap_struct {
	uint32_t cap[2];
} kernel_cap_t;

struct uid_gid_extent {
	uint32_t first;
	uint32_t lower_first;
	uint32_t count;
};

struct uid_gid_map {	/* 64 bytes -- 1 cache line */
	uint32_t nr_extents;
	union {
		struct uid_gid_extent extent[UID_GID_MAP_MAX_BASE_EXTENTS];
		struct {
			struct uid_gid_extent *forward;
			struct uid_gid_extent *reverse;
		};
	};
};

struct ns_common {
	unsigned long stashed;
	const unsigned long *ops;
	unsigned int inum;
};

struct user_namespace {
	struct uid_gid_map	uid_map;
	struct uid_gid_map	gid_map;
	struct uid_gid_map	projid_map;
	int		count;
	struct user_namespace	*parent;
	int			level;
	kuid_t			owner;
	kgid_t			group;
	struct ns_common	ns;
	unsigned long		flags;
	char padding_end[0xb8];
} ;

struct cred {
	int	usage;
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
	char padding_j_u[56];
	struct user_namespace *user_ns;
	char padding_end[24];
};


typedef struct refcount_struct {
	int refs;
} refcount_t;

struct kref {
	refcount_t refcount;
};

struct new_utsname {
	char sysname[__NEW_UTS_LEN + 1];
	char nodename[__NEW_UTS_LEN + 1];
	char release[__NEW_UTS_LEN + 1];
	char version[__NEW_UTS_LEN + 1];
	char machine[__NEW_UTS_LEN + 1];
	char domainname[__NEW_UTS_LEN + 1];
};

struct uts_namespace {
	struct kref kref;
	struct new_utsname name;
	struct user_namespace *user_ns;
	unsigned long *ucounts;
	struct ns_common ns;
};

struct nsproxy {
	int count;
	struct uts_namespace *uts_ns;
	unsigned long *ipc_ns;
	struct mnt_namespace *mnt_ns;
	unsigned long *pid_ns_for_children;
	unsigned long 	     *net_ns;
	unsigned long *cgroup_ns;
};

struct task_struct {
	char padding_cred[0x5f8];
	struct cred   *real_cred;
	struct cred    *cred;
	char padding_ns[0x30];
	struct fs_struct *fs;
	unsigned long *files;
	/* Namespaces: */
	struct nsproxy			*nsproxy;

};

struct list_head {
	struct list_head *next, *prev;
};

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

struct mnt_namespace {
	int		count;
	struct ns_common	ns;
	struct mount *	root;
	struct list_head	list;
	struct user_namespace	*user_ns;
	char paddind_ucounts[0x28];
	uint64_t event;
	unsigned int		mounts; /* # of mounts in the namespace */
	unsigned int		pending_mounts;
};

struct path {
	struct vfsmount *mnt;
	unsigned long *dentry;
};

struct vfsmount {
	unsigned long *mnt_root;	/* root of the mounted tree */
	unsigned long *mnt_sb;	/* pointer to superblock */
	int mnt_flags;
};


struct fs_struct {
	int users;
	unsigned int lock;
	unsigned int seq;
	int umask;
	int in_exec;
	struct path root, pwd;
}; 

struct container_fs{
	struct fs_struct fs;
	unsigned long paddr;
};
// struct mnt_namespace {
// 	atomic_t		count;
// 	struct ns_common	ns;
// 	struct mount *	root;
// 	struct list_head	list;
// 	struct user_namespace	*user_ns;
// 	struct ucounts		*ucounts;
// 	u64			seq;	/* Sequence number to prevent loops */
// 	wait_queue_head_t poll;
// 	u64 event;
// 	unsigned int		mounts; /* # of mounts in the namespace */
// 	unsigned int		pending_mounts;
// }
struct fs_pin {
	unsigned long lock;
	struct list_head	head;
	int			done;
	struct hlist_node	s_list;
	struct hlist_node	m_list;
	void (*kill)(struct fs_pin *);
};

struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	unsigned long *mnt_mountpoint;
	struct vfsmount mnt;
	char padding_mnt_mount[0x18];
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
	unsigned long *mnt_mp;
	struct hlist_node mnt_mp_list;	/* list mounts with the same mountpoint */
	struct list_head mnt_umounting; /* list entry for umount propagation */
	char padding_mnt_id[0xc];
	int mnt_id;			/* mount identifier */
	int mnt_group_id;		/* peer group identifier */
	int mnt_expiry_mark;		/* true if marked for expiry */
	struct hlist_head mnt_pins;
	struct fs_pin mnt_umount;
	unsigned long *mnt_ex_mountpoint;
};

struct container_user_ns
{
	struct user_namespace user_ns;
	unsigned long paddr;
};

struct container_mnt_ns
{
	struct mnt_namespace mnt_ns;
	unsigned long paddr;
};

struct container_mount
{
	struct mount mnt;
	unsigned long paddr;
};

struct container_task
{
	struct container_task *normal_next;
	SLIST_ENTRY(container_task) next;
	unsigned long pgd;
	unsigned long tsk_paddr;
	struct cred *con_cred;
	struct nsproxy *con_nsp;
    struct fs_struct *con_fs;
};


struct container_cred{
	struct container_cred *normal_next;
	SLIST_ENTRY(container_cred) next;
	struct cred k_cred;
	unsigned long paddr;
};

struct container_nsproxy{
	struct container_nsproxy *normal_next;
	SLIST_ENTRY(container_nsproxy) next;
	struct nsproxy k_nsp;
	unsigned long paddr;
	struct cred init_con_cred;
};

static inline void INIT_LIST_HEAD(struct list_head *list, struct list_head *head)
{
    list->next = list->prev = head;
}

void tee_entry_init_container_region(struct thread_smc_args *args);
void tee_entry_container_data_init(struct thread_smc_args *args);
void tee_entry_container_data_destory(struct thread_smc_args *args);
void tee_entry_update_container_region(struct thread_smc_args *args);
void tee_entry_memcpy_container_region(struct thread_smc_args *args);
void tee_entry_uint64_dec(struct thread_smc_args *args);
void tee_entry_uint64_inc(struct thread_smc_args *args);

struct mobj *map_normal_memory_to_shm(paddr_t normal_paddr, size_t size);
struct container_task *get_container_task(paddr_t tsk);
struct container_cred *get_container_cred(paddr_t k_cred);
struct container_nsproxy *get_container_nsproxy(paddr_t k_nsp);


#endif /*TRUST_CONTAINER_H*/
