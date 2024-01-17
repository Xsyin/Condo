/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, xsyin Limited
 */
#ifndef TRUST_CONTAINER_DEF_H
#define TRUST_CONTAINER_DEF_H

#include <compiler.h>
#include <stdint.h>
#include <types_ext.h>
#include <sm/optee_smc.h>
#include <platform_config.h>   // TEE_CONTAINER_BASE

#define OPTEE_SMC_FUNCID_CONTAINER_REGION_UPDATE   15
#define OPTEE_SMC_CONTAINER_REGION_UPDATE \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_CONTAINER_REGION_UPDATE)

#define OPTEE_SMC_FUNCID_INIT_CONTAINER_REGION   16
#define OPTEE_SMC_INIT_CONTAINER_REGION \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_INIT_CONTAINER_REGION)

#define OPTEE_SMC_FUNCID_CONTAINER_REGION_MEMCPY   17
#define OPTEE_SMC_CONTAINER_REGION_MEMCPY \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_CONTAINER_REGION_MEMCPY)

#define OPTEE_SMC_FUNCID_UINT64_ATOMIC_DEC   18
#define OPTEE_SMC_UINT64_ATOMIC_DEC \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_UINT64_ATOMIC_DEC)

#define OPTEE_SMC_FUNCID_UINT64_ATOMIC_INC   19
#define OPTEE_SMC_UINT64_ATOMIC_INC \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_UINT64_ATOMIC_INC)

#define OPTEE_SMC_FUNCID_CONTAINER_DATA_INIT   20
#define OPTEE_SMC_CONTAINER_DATA_INIT \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_CONTAINER_DATA_INIT)

#define OPTEE_SMC_FUNCID_CONTAINER_DATA_DESTORY   21
#define OPTEE_SMC_CONTAINER_DATA_DESTORY \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_CONTAINER_DATA_DESTORY)

#define UL(x)     ((unsigned long)(x))
#define TSK_OFFSET		(UL(0xFFFF7FFFC0000000))
#define SZ_1M        0x100000
#define SZ_2M        0x200000
#define SZ_4M        0x400000
#define SZ_8M        0x800000
#define SZ_16M       0x1000000
#define SZ_32M       0x2000000

// instruction bit
#define STP_STR_INST_BIT_SHIFT    30
#define STP_STR_INST_BIT_MASK     (UL(0x3) << STP_STR_INST_BIT_SHIFT)
#define get_stp_str_bit_instr(instr) (((instr)& STP_STR_INST_BIT_MASK) >> STP_STR_INST_BIT_SHIFT)

#define STP_INST_32                0x0
#define STP_INST_64                0x2

#define STR_INST_8                 0x0
#define STR_INST_16                0x1
#define STR_INST_32                0x2
#define STR_INST_64                0x3

// DC inst
#define DC_INST_SHIFT       5
#define DC_INST_MASK    (UL(0x7ffffff) << DC_INST_SHIFT)
#define get_dc_inst(instr) (((instr)& DC_INST_MASK) >> DC_INST_SHIFT)
#define DC_ZVA_INST        0x6a85ba1

#define DC_FLAG            0x1000
#define REG_64              0x1
#define REG_32              0x2
#define REG_16              0x4
#define REG_8               0x8
#define STR_FLAG            0x10
#define STP_FLAG            0x20

#define stp_flag(bit)         (STP_FLAG | REG_##bit)
#define str_flag(bit)         (STR_FLAG | REG_##bit)


#define CONTAINER_REGION_SIZE          TEE_CONTAINER_SIZE    // 0x4000000
#define CONTAINER_REGION_PADDR_START   TEE_CONTAINER_BASE   // 0xfa000000    f7600000
#define CONTAINER_REGION_PADDR_END   (CONTAINER_REGION_PADDR_START+CONTAINER_REGION_SIZE)   // 0xfe000000

#define CONTAINER_REGION_HASH_SIZE          SZ_1M
#define CONTAINER_REGION_HTSK_START   CONTAINER_REGION_PADDR_START   // 0xfa000000
#define CONTAINER_REGION_HTSK_SIZE   SZ_2M   
#define CONTAINER_REGION_HTSK_END   (CONTAINER_REGION_HTSK_START+CONTAINER_REGION_HTSK_SIZE)  // 0xfa200000

#define CONTAINER_REGION_HCRED_START   CONTAINER_REGION_HTSK_END    // 0xfa200000
#define CONTAINER_REGION_HCRED_SIZE     SZ_2M
#define CONTAINER_REGION_HCRED_END   (CONTAINER_REGION_HCRED_START+CONTAINER_REGION_HCRED_SIZE) // 0xfa400000

#define CONTAINER_REGION_HNSPROXY_START   CONTAINER_REGION_HCRED_END  // 0xfa400000
#define CONTAINER_REGION_HNSPROXY_END   (CONTAINER_REGION_HNSPROXY_START+CONTAINER_REGION_HASH_SIZE)

#define CONTAINER_REGION_HMOUNT_START   CONTAINER_REGION_HNSPROXY_END  // 0xfa500000
#define CONTAINER_REGION_HMOUNT_END   (CONTAINER_REGION_HMOUNT_START+CONTAINER_REGION_HASH_SIZE)

#define CONTAINER_REGION_HFS_START   CONTAINER_REGION_HMOUNT_END  // 0xfa600000
#define CONTAINER_REGION_HFS_END   (CONTAINER_REGION_HFS_START+CONTAINER_REGION_HASH_SIZE)

#define CONTAINER_REGION_HMNT_NS_START   CONTAINER_REGION_HFS_END  // 0xfa700000
#define CONTAINER_REGION_HMNT_NS_END   (CONTAINER_REGION_HMNT_NS_START+CONTAINER_REGION_HASH_SIZE)

#define CONTAINER_REGION_HUSER_NS_START   CONTAINER_REGION_HMNT_NS_END   // 0xfa800000
#define CONTAINER_REGION_HUSER_NS_END   (CONTAINER_REGION_HUSER_NS_START+CONTAINER_REGION_HASH_SIZE)

#define CONTAINER_REGION_TSK_SIZE          (SZ_16M - SZ_4M)   // 0xc00000
#define CONTAINER_REGION_TSK_START   CONTAINER_REGION_HUSER_NS_END    // 0xfa900000
#define CONTAINER_REGION_TSK_END   (CONTAINER_REGION_TSK_START+CONTAINER_REGION_TSK_SIZE)  // 
#define CONTAINER_TSK               0x00000001


#define CONTAINER_REGION_CRED_SIZE          (SZ_32M)
#define CONTAINER_REGION_CRED_START   CONTAINER_REGION_TSK_END      // 0xfb500000 
#define CONTAINER_REGION_CRED_END   (CONTAINER_REGION_CRED_START+CONTAINER_REGION_CRED_SIZE)   // 0xfd500000
#define CONTAINER_CRED               0x00000002

#define CONTAINER_REGION_NSPROXY_SIZE          (SZ_4M)
#define CONTAINER_REGION_NSPROXY_START   CONTAINER_REGION_CRED_END  // 0xfd500000
#define CONTAINER_REGION_NSPROXY_END   (CONTAINER_REGION_NSPROXY_START+CONTAINER_REGION_NSPROXY_SIZE)  // 0xfd900000
#define CONTAINER_NSPROXY               0x00000004

#define CONTAINER_REGION_FS_SIZE          (SZ_1M)
#define CONTAINER_REGION_FS_START   CONTAINER_REGION_NSPROXY_END  // 0xfd900000
#define CONTAINER_REGION_FS_END   (CONTAINER_REGION_FS_START+CONTAINER_REGION_FS_SIZE)  // 0xfda00000
#define CONTAINER_FS               0x00000008

#define CONTAINER_REGION_MOUNT_SIZE          SZ_4M
#define CONTAINER_REGION_MOUNT_START       CONTAINER_REGION_FS_END// 0xfda00000
#define CONTAINER_REGION_MOUNT_END   (CONTAINER_REGION_MOUNT_START+CONTAINER_REGION_MOUNT_SIZE)  // 0xfde00000
#define CONTAINER_MOUNT               0x00000010

#define CONTAINER_REGION_MNT_NS_SIZE          (SZ_1M)
#define CONTAINER_REGION_MNT_NS_START   CONTAINER_REGION_MOUNT_END   // 0xfde00000
#define CONTAINER_REGION_MNT_NS_END   (CONTAINER_REGION_MNT_NS_START+CONTAINER_REGION_MNT_NS_SIZE) // 0xfdf00000
#define CONTAINER_MNT_NS               0x00000020


#define CONTAINER_REGION_USER_NS_SIZE          (SZ_1M)
#define CONTAINER_REGION_USER_NS_START   CONTAINER_REGION_MNT_NS_END  // 0xfdf00000
#define CONTAINER_REGION_USER_NS_END   (CONTAINER_REGION_USER_NS_START+CONTAINER_REGION_USER_NS_SIZE)   // 0xfe000000
#define CONTAINER_USER_NS               0x00000040

#define in_container_range(paddr, region) (((unsigned long)paddr >= CONTAINER_REGION_##region##_START) && ((unsigned long)paddr < CONTAINER_REGION_##region##_END))
#define in_container_region(paddr) (((unsigned long)paddr >= CONTAINER_REGION_PADDR_START) && ((unsigned long)paddr < CONTAINER_REGION_PADDR_END))


#define mask_value(val, bit)   ((unsigned long)(val) & ((UL(1) << bit) -1 ))

// TO identify ldr which, nsproxy: 0x4, cred: 0x2
//  63 .... 32  ||31 ........4 || 3..0
//  TASK[31:0]  || CRED[31:0]  || FLAG
// #define TASK_CONST       UL(0xffff800000000000)
// #define CON_CONST       UL(0xffff7dff00000000)
// #define FLAG_SHIFT        4
// #define FLAG_MASK        UL(0xf)
// #define TSK_SHIFT        32
// #define get_flag(value)   ((unsigned long)(value) & FLAG_MASK)
// #define get_task(value)   (TASK_CONST | ((unsigned long)value >> TSK_SHIFT))
// #define get_con_value(value)   ((CON_CONST | mask_value(value, TSK_SHIFT)) & ~((UL(1) << FLAG_SHIFT)-1))
// #define mask_con_value(region, vaddr, tsk) (UL(CONTAINER_##region) | mask_value(vaddr, TSK_SHIFT) | (mask_value(tsk, TSK_SHIFT) << TSK_SHIFT))

static inline unsigned long roundup_pow_of_two(unsigned long n)
{
	int i = 0;
	while((UL(1) << i) < n)
		i++;
	return (UL(1) << i);

}

// TO identify ldr which, nsproxy: 0x4, cred: 0x2
//  63...56  || 55...48 || 47 ....0
//  0x 000   || FLAG    || TASK[47:0]
#define TASK_CONST       0xffff000000000000
#define CON_CONST       0xffff000000000000
#define FLAG_SHIFT        48
#define FLAG_MASK        (0xffUL << FLAG_SHIFT)
#define get_flag(value)   (((unsigned long)(value) & FLAG_MASK) >> FLAG_SHIFT)
#define get_task(value)   (TASK_CONST | mask_value(value, FLAG_SHIFT))
#define get_con_value(value)   (CON_CONST | mask_value(value, FLAG_SHIFT))
#define mask_con_value(region, con_vaddr) ((UL(CONTAINER_##region) << FLAG_SHIFT) | mask_value(con_vaddr, FLAG_SHIFT))
#define get_con_struct(vaddr, size) ((unsigned long)(vaddr) & ~(roundup_pow_of_two(size)-1))


#endif /*TRUST_CONTAINER_DEF_H*/
