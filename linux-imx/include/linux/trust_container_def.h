/* SPDX-License-Identifier: GPL-2.0 */

/*
 # created by xsyin 2022-7-24
 # map the secure container region
 # get, read, write that region
*/
#ifndef __TRUST_CONTAINER_DEF_H__
#define __TRUST_CONTAINER_DEF_H__

#include <linux/arm-smccc.h>
#include <linux/types.h>
#include <linux/log2.h>
#include <asm/fixmap.h>
#include <asm/sysreg.h>
#include <asm/system_misc.h>
#include <linux/ktime.h>

extern u64 switch_time_a;
extern unsigned long switch_count_a;
extern int is_container;
extern struct nsproxy *container_ns;
extern struct cred *container_cred;


#define INTERVAL  2000

#if 0
#ifndef COUNT_SWITCH_INTERVAL
#define COUNT_SWITCH_INTERVAL
#endif
#else
#ifdef COUNT_SWITCH_INTERVAL
#undef COUNT_SWITCH_INTERVAL
#endif
#endif

#if 1
#ifndef CVE_2017_5123_POC
#define CVE_2017_5123_POC
#endif
#else
#ifdef CVE_2017_5123_POC
#undef CVE_2017_5123_POC
#endif
#endif

#if 1
#ifndef CONTAINER_FLUSH_NULL
#define CONTAINER_FLUSH_NULL
#endif
#else
#ifdef CONTAINER_FLUSH_NULL
#undef CONTAINER_FLUSH_NULL
#endif
#endif

#if 1
#ifndef CON_CRED
#define CON_CRED
#endif
#else
#ifdef CON_CRED
#undef CON_CRED
#endif
#endif

#if 1
#ifndef CON_USER_NS
#define CON_USER_NS
#endif
#else
#ifdef CON_USER_NS
#undef CON_USER_NS
#endif
#endif

#if 1
#ifndef CON_FS
#define CON_FS
#endif
#else
#ifdef CON_FS
#undef CON_FS
#endif
#endif

#if 1
#ifndef CON_MNT_NS
#define CON_MNT_NS
#endif
#else
#ifdef CON_MNT_NS
#undef CON_MNT_NS
#endif
#endif

#if 1
#ifndef CON_MOUNT
#define CON_MOUNT
#endif
#else
#ifdef CON_MOUNT
#undef CON_MOUNT
#endif
#endif

// #define pr_alert(...)
// #define pr_info(...)

#define OPTEE_SMC_RETURN_OK		0x0

#define OPTEE_SMC_FAST_CALL_VAL(func_num) \
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, ARM_SMCCC_SMC_32, \
			   ARM_SMCCC_OWNER_TRUSTED_OS, (func_num))

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

// AARCH64 Instruction encoding: reference to https://github.com/CAS-Atlantic/AArch64-Encoding

// STR <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
// STP <Xt1>, <Xt2>, [<Xn|SP>], #<imm>
// reg id
#define Rt_SHIFT           0
#define Rt_MASK            (0x1fUL << Rt_SHIFT)
#define Rn_SHIFT           5
#define Rn_MASK            (0x1fUL << Rn_SHIFT)
#define Rt2_SHIFT           10
#define Rt2_MASK            (0x1fUL << Rt2_SHIFT)

#define imm9_SHIFT          12
// #define imm9_SIGN_SHIFT      55
#define imm9_MASK            (0x1ffUL << imm9_SHIFT)
#define imm7_SHIFT          15
// #define imm7_SIGN_SHIFT        57
#define imm7_MASK            (0x7fUL << imm7_SHIFT)
#define imm12_SHIFT          10
#define imm12_MASK            (0xfffUL << imm12_SHIFT)
#define Rs_SHIFT            16
#define Rs_MASK            (0x1fUL << Rs_SHIFT)
#define get_operand_id(instr, i)  ((instr & i##_MASK) >> i##_SHIFT)
// #define get_signed_imm(instr, i) ((((instr & i##_MASK) >> i##_SHIFT ) << i##_SIGN_SHIFT) >> i##_SIGN_SHIFT)
#define get_unsigned_imm(instr, i) ((instr & i##_MASK) >> i##_SHIFT )

#define mask_value(val, bit)   ((unsigned long)(val) & ((UL(1) << bit) -1 ))

// all loads and stores inst bit27=1 && bit25=0  0x110  0x100
#define LDR_STORE_INST_SHIFT     25
#define LDR_STORE_INST_MASK   (UL(7) << LDR_STORE_INST_SHIFT)
#define LDR_STORE_INST_1       0x6
#define LDR_STORE_INST_2       0x4
#define is_ldr_store_instr(instr) (((instr)& LDR_STORE_INST_MASK) >> LDR_STORE_INST_SHIFT)

// load/store exclusive bit[29:24] = 8
#define STP_STR_X_L_INST_SHIFT    24
#define STP_STR_X_L_INST_MASK      (UL(0x3f) << STP_STR_X_L_INST_SHIFT)
#define is_stp_str_x_l_instr(instr) (((instr)& STP_STR_X_L_INST_MASK) >> STP_STR_X_L_INST_SHIFT)
#define STP_STR_X_L_INST          8


// each load/ store exclusive
#define STP_OR_STR_X_INST_SHIFT    21
#define STP_OR_STR_X_INST_MASK      (UL(0x1) << STP_OR_STR_X_INST_SHIFT)
 // 1 is stp, 0 is str 
#define is_stp_x_instr(instr) (((instr)& STP_OR_STR_X_INST_MASK) >> STP_OR_STR_X_INST_SHIFT)
#define STR_X_OR_L_INST_SHIFT    	23
#define STR_X_OR_L_INST_MASK      (UL(0x1) << STR_X_OR_L_INST_SHIFT)
 // 1 is stlr, 0 is stxr, stlxr, stlxp, stxp, , L is no need to write Rs
#define is_str_l_instr(instr) (((instr)& STR_X_OR_L_INST_MASK) >> STR_X_OR_L_INST_SHIFT)

// instruction bit
#define INST_BIT_SHIFT    30
#define INST_BIT_MASK     (UL(0x3) << INST_BIT_SHIFT)
#define get_bit_instr(instr) (((instr)& INST_BIT_MASK) >> INST_BIT_SHIFT)


#define STP_STR_X_INST_8         0x0
#define STP_STR_X_INST_16        0x1
#define STP_STR_X_INST_32        0x2
#define STP_STR_X_INST_64        0x3

#define REG_64              0x1
#define REG_32              0x2
#define REG_16              0x4
#define REG_8               0x8
#define STR_FLAG            0x10
#define STP_FLAG            0x20

// not exclusive, 
#define STP_STR_INST_SHIFT    27
#define STP_STR_INST_MASK     (UL(0x7) << STP_STR_INST_SHIFT)
#define get_stp_str_instr(instr) (((instr)& STP_STR_INST_MASK) >> STP_STR_INST_SHIFT)
#define STP_INST    5
#define STR_INST    7

// stp instruction, no variant
#define STP_INST_SHIFT             22
#define STP_INST_MASK              (UL(0xff) << STP_INST_SHIFT)
#define get_stp_instr(instr) (((instr)& STP_INST_MASK) >> STP_INST_SHIFT)

// STNP, STP
#define STP_INST_32                0x0
#define STP_INST_64                0x2

// STP post-index or pre-index mode
#define STP_POST_OR_PRE_INDEX_SHIFT    23
#define STP_POST_OR_PRE_INDEX_MASK     (UL(0x3) << STP_POST_OR_PRE_INDEX_SHIFT)
#define get_stp_post_or_pre_index(instr) (((instr)& STP_POST_OR_PRE_INDEX_MASK) >> STP_POST_OR_PRE_INDEX_SHIFT)
#define STP_POST_INDEX_INST        0x1
#define STP_PRE_INDEX_INST         0x3


#define STR_INST_8                 0x0
#define STR_INST_16                0x1
#define STR_INST_32                0x2
#define STR_INST_64                0x3

// str bit[25:24] = 1 store register unsigned imm  STR <Xt>, [<Xn|SP>{, #<imm12>}]
#define STR_USIGNED_IMM_SHIFT         24
#define STR_USIGNED_IMM_MASK         (UL(0x3) << STR_USIGNED_IMM_SHIFT)
// 1 is unsigned imm str
#define is_str_unsigned_imm_inst(instr) (((instr)& STR_USIGNED_IMM_MASK) >> STR_USIGNED_IMM_SHIFT)


// STR post-index or pre-index mode
#define STR_POST_OR_PRE_INDEX_SHIFT    10
#define STR_POST_OR_PRE_INDEX_MASK     (UL(0x3) << STR_POST_OR_PRE_INDEX_SHIFT)
#define get_str_post_or_pre_index(instr) (((instr)& STR_POST_OR_PRE_INDEX_MASK) >> STR_POST_OR_PRE_INDEX_SHIFT)
#define STR_POST_INDEX_INST        0x1
#define STR_PRE_INDEX_INST         0x3

// DC inst
#define DC_INST_SHIFT       5
#define DC_INST_MASK    (UL(0x7ffffff) << DC_INST_SHIFT)
#define get_dc_inst(instr) (((instr)& DC_INST_MASK) >> DC_INST_SHIFT)
#define DC_ZVA_INST        0x6a85ba1

#define DC_FLAG            0x1000


// container safe region layout

#define CONTAINER_REGION_VADDR_START   CONTAINER_BEGIN  // 0xffff7dfffac00000
#define CONTAINER_REGION_VADDR_END     CONTAINER_END
#define CONTAINER_REGION_SIZE          (SZ_64M)
#define CONTAINER_REGION_PADDR_START   0xfa000000
#define CONTAINER_REGION_PADDR_END   (CONTAINER_REGION_PADDR_START+CONTAINER_REGION_SIZE)
#define CONTAINER_REGION_VADDR_PADDR_OFFSET   (CONTAINER_REGION_VADDR_START-CONTAINER_REGION_PADDR_START)

#define CONTAINER_REGION_HASH_SIZE          SZ_1M

#define CONTAINER_REGION_HTSK_START   CONTAINER_REGION_VADDR_START
#define CONTAINER_REGION_HTSK_SIZE   SZ_2M
#define CONTAINER_REGION_HTSK_END   (CONTAINER_REGION_HTSK_START+CONTAINER_REGION_HTSK_SIZE)

#define CONTAINER_REGION_HCRED_START   CONTAINER_REGION_HTSK_END
#define CONTAINER_REGION_HCRED_SIZE   SZ_2M
#define CONTAINER_REGION_HCRED_END   (CONTAINER_REGION_HCRED_START+CONTAINER_REGION_HCRED_SIZE)

#define CONTAINER_REGION_HNSPROXY_START   CONTAINER_REGION_HCRED_END
#define CONTAINER_REGION_HNSPROXY_END   (CONTAINER_REGION_HNSPROXY_START+CONTAINER_REGION_HASH_SIZE)

#define CONTAINER_REGION_HMOUNT_START   CONTAINER_REGION_HNSPROXY_END
#define CONTAINER_REGION_HMOUNT_END   (CONTAINER_REGION_HMOUNT_START+CONTAINER_REGION_HASH_SIZE)

#define CONTAINER_REGION_HFS_START   CONTAINER_REGION_HMOUNT_END
#define CONTAINER_REGION_HFS_END   (CONTAINER_REGION_HFS_START+CONTAINER_REGION_HASH_SIZE)

#define CONTAINER_REGION_HMNT_NS_START   CONTAINER_REGION_HFS_END
#define CONTAINER_REGION_HMNT_NS_END   (CONTAINER_REGION_HMNT_NS_START+CONTAINER_REGION_HASH_SIZE)

#define CONTAINER_REGION_HUSER_NS_START   CONTAINER_REGION_HMNT_NS_END
#define CONTAINER_REGION_HUSER_NS_END   (CONTAINER_REGION_HUSER_NS_START+CONTAINER_REGION_HASH_SIZE)

#define CONTAINER_REGION_TSK_SIZE          (SZ_16M - SZ_4M)
#define CONTAINER_REGION_TSK_START   CONTAINER_REGION_HUSER_NS_END   // 0xffff7dfffb500000
#define CONTAINER_REGION_TSK_END   (CONTAINER_REGION_TSK_START+CONTAINER_REGION_TSK_SIZE)
#define CONTAINER_TSK               0x00000001

#define CONTAINER_REGION_CRED_SIZE          (SZ_32M)
#define CONTAINER_REGION_CRED_START   CONTAINER_REGION_TSK_END    // 0xffff7dfffc100000
#define CONTAINER_REGION_CRED_END   (CONTAINER_REGION_CRED_START+CONTAINER_REGION_CRED_SIZE)
#define CONTAINER_CRED               0x00000002

#define CONTAINER_REGION_NSPROXY_SIZE          (SZ_4M)
#define CONTAINER_REGION_NSPROXY_START   CONTAINER_REGION_CRED_END  // 0xffff7dfffe100000
#define CONTAINER_REGION_NSPROXY_END   (CONTAINER_REGION_NSPROXY_START+CONTAINER_REGION_NSPROXY_SIZE)
#define CONTAINER_NSPROXY               0x00000004

#define CONTAINER_REGION_FS_SIZE          (SZ_1M)                    // used in spinlock.h
#define CONTAINER_REGION_FS_START   CONTAINER_REGION_NSPROXY_END // 0xffff7dfffe500000
#define CONTAINER_REGION_FS_END   (CONTAINER_REGION_FS_START+CONTAINER_REGION_FS_SIZE)
#define CONTAINER_FS               0x00000008

#define CONTAINER_REGION_MOUNT_SIZE          SZ_4M
#define CONTAINER_REGION_MOUNT_START   CONTAINER_REGION_FS_END // 
#define CONTAINER_REGION_MOUNT_END   (CONTAINER_REGION_MOUNT_START+CONTAINER_REGION_MOUNT_SIZE)
#define CONTAINER_MOUNT               0x00000010

#define CONTAINER_REGION_MNT_NS_SIZE          (SZ_1M)
#define CONTAINER_REGION_MNT_NS_START   CONTAINER_REGION_MOUNT_END
#define CONTAINER_REGION_MNT_NS_END   (CONTAINER_REGION_MNT_NS_START+CONTAINER_REGION_MNT_NS_SIZE)
#define CONTAINER_MNT_NS               0x00000020


#define CONTAINER_REGION_USER_NS_SIZE          (SZ_1M)
#define CONTAINER_REGION_USER_NS_START   CONTAINER_REGION_MNT_NS_END
#define CONTAINER_REGION_USER_NS_END   (CONTAINER_REGION_USER_NS_START+CONTAINER_REGION_USER_NS_SIZE)
#define CONTAINER_USER_NS               0x00000040


#define container_virt_to_phys(x) ((unsigned long)(x)- (CONTAINER_REGION_VADDR_START-CONTAINER_REGION_PADDR_START))
#define container_phys_to_virt(x) ((unsigned long)(x)+ (CONTAINER_REGION_VADDR_START-CONTAINER_REGION_PADDR_START))
#define in_container_range(addr, region) (((unsigned long)(addr) >= CONTAINER_REGION_##region##_START) && ((unsigned long)(addr) < CONTAINER_REGION_##region##_END))
#define in_container_region(addr) (((unsigned long)(addr) >= CONTAINER_REGION_VADDR_START) && ((unsigned long)(addr) < CONTAINER_REGION_VADDR_END))

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
// #define mask_value_chg_tsk(vaddr, tsk) (mask_value(vaddr, TSK_SHIFT) | (mask_value(tsk, TSK_SHIFT) << TSK_SHIFT))
// #define is_normal_mem_val(vaddr) (((unsigned long)(vaddr) & ~((UL(1) << TSK_SHIFT)-1)) == TASK_CONST)


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

#define NORMAL_CONST       UL(0xffff800000000000)
#define NORMAL_SHIFT        32
#define is_normal_mem_val(vaddr) (((unsigned long)(vaddr) & ~((UL(1) << NORMAL_SHIFT)-1)) == NORMAL_CONST)

#endif
