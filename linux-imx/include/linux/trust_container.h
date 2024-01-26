/* SPDX-License-Identifier: GPL-2.0 */

/*
 # created by xsyin 2022-7-24
 # map the secure container region 0xffff 7dff fcc0 0000 ~ 0xffff 7dff fec0 0000
 # get, read, write that region
*/
#ifndef __TRUST_CONTAINER_H__
#define __TRUST_CONTAINER_H__


#include <linux/nsproxy.h>
#include <linux/cred.h>
#include <linux/llist.h>
#include <linux/mount.h>
#include <linux/fs_struct.h>
#include <linux/mnt_namespace.h>
#include <linux/user_namespace.h>
#include <linux/genalloc.h>
#include <linux/trust_container_def.h>

struct mount;

struct container_task
{
	struct llist_node tsk_list;
	struct container_task *secure_next; // next vaddr in secure world
	unsigned long pgd;
	unsigned long tsk_paddr;
	struct cred *con_cred;
	struct nsproxy *con_nsp;
    struct fs_struct *con_fs;
};

int init_secure_container_region(void);

struct gen_pool *container_pool_create(const char *name, size_t s);
unsigned long container_pool_alloc(struct gen_pool *genpool, size_t s);
void container_pool_free(struct gen_pool *genpool, void *vaddr, size_t s);

bool container_data_init(unsigned int flags, void *con_vaddr, struct task_struct *p, unsigned long s, unsigned long ns_paddr, unsigned long cred_paddr, unsigned long fs);
bool container_data_destory(const void *vaddr, const unsigned int flags);

struct container_task *get_container_task(struct task_struct *tsk);
struct container_cred *get_container_cred(unsigned long cred_paddr);
struct container_nsproxy *get_container_nsproxy(unsigned long nsp_paddr);

bool copy_container_data_to_region(struct task_struct *tsk, int flag);
bool copy_user_ns_data_to_region(struct task_struct *tsk, struct cred *cred);
bool copy_mnt_ns_data_to_region(struct mnt_namespace **mnt_ns);
bool copy_mount_data_to_region(struct mount **mnt);
bool container_memcpy(void *dest, void *source, size_t size);
int get_container_data_flag(struct task_struct *tsk);
int polling_checker(void);

#endif
