
struct sigcontext {
    unsigned long r8, r9, r10, r11, r12, r13, r14, r15;
    unsigned long rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip, eflags;
    unsigned short cs, gs, fs, __pad0;
    unsigned long err, trapno, oldmask, cr2;
    unsigned long fpstate;
    unsigned long reserved1[8];
};

struct ucontext {
    unsigned long uc_flags;
    struct ucontext *uc_link;
    void *ss_sp;
    int ss_flags;
    unsigned long ss_size;
    struct sigcontext uc_mcontext;
    unsigned long uc_sigmask;
};

#define FLAG_LEN 43
#define PHASE_COUNT 4
#define SEMANTIC_STAGE_COUNT (FLAG_LEN * PHASE_COUNT)
#define STAGE_EXPANSION 10U
#define PHYSICAL_STAGE_COUNT (SEMANTIC_STAGE_COUNT * STAGE_EXPANSION)
#define STAGE_COUNT (PHYSICAL_STAGE_COUNT + 1)
#define VIRTUAL_PHASE_WIDTH 16
#define VIRTUAL_LANE_COUNT (PHASE_COUNT * VIRTUAL_PHASE_WIDTH)
#define STATEFUL_VM_REAL_ROUNDS 9U
#define STATEFUL_VM_TOTAL_ROUNDS 40U
#define FORTY_ROUND_NOISE_COUNT ((unsigned long)FLAG_LEN * (STATEFUL_VM_TOTAL_ROUNDS - STATEFUL_VM_REAL_ROUNDS))
#define TARGET_VM_REAL_ROUNDS 7U
#define TARGET_VM_TOTAL_ROUNDS 40U
#define TARGET_VM_NOISE_COUNT ((unsigned long)FLAG_LEN * 2UL * (TARGET_VM_TOTAL_ROUNDS - TARGET_VM_REAL_ROUNDS))
#define TARGET_DECODE_DISPATCH_COUNT ((unsigned long)FLAG_LEN * 2UL)
#define MIX_VM_REAL_ROUNDS 5U
#define MIX_VM_TOTAL_ROUNDS 40U
#define MIX_VM_NOISE_COUNT ((unsigned long)FLAG_LEN * (MIX_VM_TOTAL_ROUNDS - MIX_VM_REAL_ROUNDS))
#define U64(x) x##ULL

#define AT_FDCWD (-100)
#define CLONE_VM      0x00000100UL
#define CLONE_FS      0x00000200UL
#define CLONE_FILES   0x00000400UL
#define CLONE_SIGHAND 0x00000800UL
#define CLONE_THREAD  0x00010000UL
#define WATCHDOG_STACK_SIZE 16384

#define SYS_EVENTFD2        290
#define SYS_TIMERFD_CREATE  283
#define SYS_TIMERFD_SETTIME 286
#define SYS_EPOLL_CREATE1   291
#define SYS_EPOLL_CTL       233
#define SYS_EPOLL_WAIT      232
#define SYS_FUTEX           202
#define SYS_RT_SIGACTION    13
#define SYS_SIGALTSTACK     131
#define SYS_MMAP            9
#define SYS_MPROTECT        10
#define SYS_IOCTL           16
#define SYS_USERFAULTFD     323
#define SYS_MEMFD_CREATE    319
#define SYS_LSEEK           8
#define SYS_PROCESS_VM_WRITEV 311
#define SYS_PRCTL           157
#define SYS_GETPID          39
#define SYS_CLONE           56

#define SIGCHLD_ABYSS       17UL
#define PR_SET_PTRACER_ABYSS 0x59616d61UL

#define EPOLL_CTL_ADD 1
#define EPOLLIN       0x001U

#define FUTEX_WAIT    0
#define FUTEX_WAKE    1

#define EFD_NONBLOCK  0x800
#define TFD_NONBLOCK  0x800
#define CLOCK_MONOTONIC 1

#define PROT_NONE      0x0
#define PROT_READ      0x1
#define PROT_WRITE     0x2
#define PROT_EXEC      0x4
#define MAP_PRIVATE    0x02
#define MAP_ANONYMOUS  0x20
#define MFD_CLOEXEC    0x0001U
#define SEEK_SET_ABYSS 0
#define MAP_FAILED_ABYSS ((void *)-1L)

#define UFFD_PAGE_SIZE 4096UL
#define HANDLER_TABLE_BYTES ((((HT_DESC_BASE + PHYSICAL_STAGE_COUNT) * 8UL + UFFD_PAGE_SIZE - 1UL) / UFFD_PAGE_SIZE) * UFFD_PAGE_SIZE)
#define TARGET_DELTA_BYTES ((((STAGE_COUNT + 2UL) * 8UL + UFFD_PAGE_SIZE - 1UL) / UFFD_PAGE_SIZE) * UFFD_PAGE_SIZE)
#define UFFD_API_ABYSS U64(0xAA)
#define UFFD_EVENT_PAGEFAULT 0x12
#define UFFDIO_REGISTER_MODE_MISSING U64(1)
#define UFFDIO_API_ABYSS      0xC018AA3FUL
#define UFFDIO_REGISTER_ABYSS 0xC020AA00UL
#define UFFDIO_COPY_ABYSS     0xC028AA03UL

#define SIGILL        4
#define SIGSEGV       11
#define SA_SIGINFO    0x00000004UL
#define SA_RESTORER   0x04000000UL
#define SA_ONSTACK    0x08000000UL
#define SIGALT_STACK_SIZE 32768

#define VM_EVENT_KEY   U64(0x1001)
#define VM_EVENT_ANTI  U64(0x2002)
#define VM_EVENT_TICK  U64(0x3003)

#define VM_GATE_STAGE_A 3U
#define VM_GATE_STAGE_B 8U
#define VM_GATE_STAGE_C 12U

#define HEARTBEAT_STAGE_A 23U
#define HEARTBEAT_STAGE_B 87U
#define HEARTBEAT_STAGE_C 143U
#define HEARTBEAT_INTERVAL_MS 3000L

#define SILENT_SAMPLE64(EXPR) do { \
    unsigned long _x = (unsigned long)(EXPR); \
    g.dummy_hash ^= (_x & 0UL); \
} while (0)


struct timespec_abyss {
    long tv_sec;
    long tv_nsec;
};

struct timeval_abyss {
    long tv_sec;
    long tv_usec;
};

struct itimerspec_abyss {
    struct timespec_abyss it_interval;
    struct timespec_abyss it_value;
};

struct iovec_abyss {
    void *iov_base;
    unsigned long iov_len;
};

struct epoll_event_abyss {
    unsigned int events;
    unsigned long data;
} __attribute__((packed));

struct stack_abyss {
    void *ss_sp;
    int ss_flags;
    unsigned long ss_size;
};

struct kernel_sigaction_abyss {
    void (*handler)(int, void *, void *);
    unsigned long flags;
    void (*restorer)(void);
    unsigned long mask;
};

struct uffd_msg_abyss {
    unsigned char event;
    unsigned char reserved1;
    unsigned short reserved2;
    unsigned int reserved3;
    union {
        struct {
            unsigned long flags;
            unsigned long address;
            union { unsigned int ptid; } feat;
        } pagefault;
        struct { unsigned long r1, r2, r3; } reserved;
    } arg;
} __attribute__((packed));

struct uffdio_api_abyss {
    unsigned long api;
    unsigned long features;
    unsigned long ioctls;
};

struct uffdio_range_abyss {
    unsigned long start;
    unsigned long len;
};

struct uffdio_register_abyss {
    struct uffdio_range_abyss range;
    unsigned long mode;
    unsigned long ioctls;
};

struct uffdio_copy_abyss {
    unsigned long dst;
    unsigned long src;
    unsigned long len;
    unsigned long mode;
    long copy;
};

struct VMEventNode {
    int fd;
    unsigned long kind;
    unsigned long salt;
};

struct EventRuntime {
    int epfd;
    int key_fd;
    int anti_fd;
    int tick_fd;
    struct VMEventNode key_node;
    struct VMEventNode anti_node;
    struct VMEventNode tick_node;
};

struct EncBlob {
    const unsigned char *data;
    unsigned long len;
    unsigned long seed;
};

struct InputNode {
    volatile unsigned char *sink;
    volatile unsigned char *mirror;
    unsigned char raw_index;
    unsigned char sink_index;
    unsigned char mask;
    unsigned long tag;
    struct InputNode *next;
};

struct InputVault {
    volatile unsigned char raw[96];
    volatile unsigned char lane_a[128];
    volatile unsigned char lane_b[128];
    volatile unsigned char decoy[64];
    struct InputNode nodes[FLAG_LEN];
    volatile unsigned long input_len;
    volatile unsigned long transit_hash;
};

char input_buf[96];
volatile unsigned char *ptr_pool[FLAG_LEN];
volatile unsigned char logical_order[FLAG_LEN];
volatile unsigned char sealed_cache[FLAG_LEN];

struct AbyssState {
    volatile unsigned long entropy[64]; //噪声池
    volatile unsigned long step_counter;
    volatile unsigned long dummy_hash; //假哈希
    volatile unsigned long real_state; //最核心的真实校验状态
    volatile unsigned long fail_acc;
    volatile unsigned long final_guard; //最终 guard
    volatile unsigned long target_key; //解 target / sealed target / stage delta 的核心 key
    volatile unsigned long anti_debug_alarm; //反调试
    volatile unsigned long code_hash_base;
    volatile unsigned long input_digest;
    //Event / Futex 层 事件驱动 VM 的侧通道状态 eventfd/timerfd/epoll 那层会更新 event_*，futex 那层会让某些 stage 等待异步 worker 推进 epoch
    volatile unsigned long event_mask;
    volatile unsigned long event_counter;
    volatile unsigned long event_shadow;
    volatile unsigned long key_epoch;
    volatile unsigned long timer_epoch;
    volatile unsigned long anti_epoch;
    volatile unsigned long event_algo_key;
    volatile unsigned long event_algo_mirror;
    volatile unsigned long event_algo_rounds;
    volatile unsigned long event_algo_ready;

    volatile unsigned int futex_word;
    volatile unsigned int gate_epoch;
    volatile unsigned long gate_waits;
    volatile unsigned long gate_shadow;
    //SIGILL / SIGSEGV 异常流
    volatile unsigned long sigill_count;
    volatile unsigned long sigill_shadow;
    volatile unsigned long sigill_last_rip;
    volatile unsigned long sigill_stage_hint;
    volatile unsigned long sigill_armed;

    volatile unsigned long segv_count;
    volatile unsigned long segv_shadow;
    volatile unsigned long segv_last_rip;
    volatile unsigned long segv_last_rsp;
    volatile unsigned long segv_fault_addr;
    volatile unsigned long segv_stage_hint;
    volatile unsigned long segv_armed;
    volatile unsigned long segv_saved_rsp;
    volatile unsigned long segv_recover_rip;
    //Split-stage 层 把一个 logical char stage 拆成多个 physical phase
    volatile unsigned long split_shadow[FLAG_LEN];
    volatile unsigned long split_counter;
    volatile unsigned long split_last;

    //userfaultfd / target-delta lazy page
    volatile unsigned long uffd_enabled;
    volatile unsigned long uffd_faults;
    volatile unsigned long uffd_last_addr;
    volatile unsigned long uffd_shadow;
    volatile unsigned long uffd_fallback;

    volatile unsigned long td_uffd_enabled;
    volatile unsigned long td_uffd_faults;
    volatile unsigned long td_uffd_last_addr;
    volatile unsigned long td_uffd_shadow;
    volatile unsigned long td_uffd_fallback;
    volatile unsigned long td_page_mix;
    //Heartbeat 反调试层
    volatile unsigned long heartbeat_epoch;
    volatile unsigned long heartbeat_mirror;
    volatile unsigned long heartbeat_cookie;
    volatile unsigned long heartbeat_shadow;
    volatile unsigned long heartbeat_baseline;
    volatile unsigned long heartbeat_last_seen;
    volatile unsigned long heartbeat_bad;
    volatile unsigned long heartbeat_code_hash;
    volatile unsigned long heartbeat_checks;
    volatile unsigned long heartbeat_stage_mix;
    volatile unsigned long heartbeat_key_mix;
    volatile unsigned long heartbeat_target_shadow;
    //RX helper / memfd helper mmap 匿名页 → 解密 helper → mprotect RX → 函数指针调用 memfd_create → 写入 helper → mmap RX → 函数指针调用
    volatile unsigned long rx_helper_ready;
    volatile unsigned long rx_helper_calls;
    volatile unsigned long rx_helper_shadow;
    volatile unsigned long rx_helper_code_hash;
    volatile unsigned long rx_helper_bad;
    volatile unsigned long rx_helper_last_stage;
    volatile unsigned long rx_helper_active_mix;
    volatile unsigned long rx_helper_active_seen;
    volatile unsigned long rx_helper_active_guard;
    volatile unsigned long rx_helper_target_root;
    volatile unsigned long rx_helper_target_shadow;
    volatile unsigned long helper_output_key_mix;

    volatile unsigned long memfd_stage2_ready;
    volatile unsigned long memfd_stage2_calls;
    volatile unsigned long memfd_stage2_shadow;
    volatile unsigned long memfd_stage2_code_hash;
    volatile unsigned long memfd_stage2_bad;
    volatile unsigned long memfd_stage2_last_stage;
    volatile unsigned long memfd_stage2_active_mix;
    volatile unsigned long memfd_stage2_active_seen;
    volatile unsigned long memfd_stage2_active_guard;
    volatile unsigned long memfd_stage2_fd_tag;
    volatile unsigned long memfd_stage2_commit_mix;
    volatile unsigned long memfd_stage2_commit_mirror;
    
    volatile unsigned long memfd_stage2_target_root;
    volatile unsigned long memfd_stage2_target_shadow;
    volatile unsigned long memfd_stage2_target_uses;
    volatile unsigned long memfd_stage2_output_key_mix;

    //process_vm_writev 子进程 lane
    volatile unsigned long pvm_mailbox; //子进程写回的数据
    volatile unsigned long pvm_mirror;
    volatile unsigned long pvm_epoch;
    volatile unsigned long pvm_mix;
    volatile unsigned long pvm_writes;
    volatile unsigned long pvm_child_pid;
    volatile unsigned long pvm_bad;
    volatile unsigned long pvm_fallback;
    volatile unsigned long pvm_code_hash;
    volatile unsigned long pvm_stage_mix;

    // handler table / code island lazy metadata
    volatile unsigned long handler_table_ready;
    volatile unsigned long handler_table_faults;
    volatile unsigned long handler_table_shadow;
    volatile unsigned long handler_table_bad;
    volatile unsigned long handler_table_last_addr;
    volatile unsigned long handler_table_reads;
    volatile unsigned long handler_table_stage_mix;
    volatile unsigned long handler_table_stage_mirror;
    volatile unsigned long handler_table_page_hash;

    // 短生命周期代码岛
    volatile unsigned long code_island_ready;
    volatile unsigned long code_island_calls;
    volatile unsigned long code_island_bad;
    volatile unsigned long code_island_last_stage;
    volatile unsigned long code_island_code_hash;
    volatile unsigned long code_island_active_mix;
    volatile unsigned long code_island_active_seen;
    volatile unsigned long code_island_active_guard;
    volatile unsigned long code_island_wipes;
    volatile unsigned long code_island_shadow;

    //phase / xchar / fake / route 四条真实校验 lane
    volatile unsigned long phase_lane_mix[PHASE_COUNT];
    volatile unsigned long phase_lane_mirror[PHASE_COUNT];
    volatile unsigned long phase_dispatch_count;
    volatile unsigned long phase_dispatch_shadow;
    volatile unsigned long virtual_lane_mix[VIRTUAL_LANE_COUNT];
    volatile unsigned long virtual_lane_mirror[VIRTUAL_LANE_COUNT];
    volatile unsigned long virtual_dispatch_count;
    volatile unsigned long virtual_dispatch_shadow;
    volatile unsigned long virtual_lane_last;
    volatile unsigned long virtual_lane_bad;
    volatile unsigned long diff_scratch_a[8];
    volatile unsigned long diff_scratch_b[8];
    volatile unsigned long diff_scratch_mirror;
    volatile unsigned long diff_scratch_seq;
    volatile unsigned long forty_round_shadow;
    volatile unsigned long forty_round_mirror;
    volatile unsigned long forty_round_counter;
    volatile unsigned long forty_round_gate;
    volatile unsigned long target_vm_shadow;
    volatile unsigned long target_vm_mirror;
    volatile unsigned long target_vm_counter;
    volatile unsigned long target_vm_gate;
    volatile unsigned long target_decode_dispatch_shadow;
    volatile unsigned long target_decode_dispatch_mirror;
    volatile unsigned long target_decode_dispatch_counter;
    volatile unsigned long target_decode_dispatch_gate;
    volatile unsigned long target_decode_decoy_scratch[8];
    volatile unsigned long mix_vm_shadow;
    volatile unsigned long mix_vm_mirror;
    volatile unsigned long mix_vm_counter;
    volatile unsigned long mix_vm_gate;
    volatile unsigned long diff_dispatch_shadow;
    volatile unsigned long diff_dispatch_mirror;
    volatile unsigned long diff_dispatch_counter;
    volatile unsigned long diff_dispatch_gate;
    volatile unsigned long diff_decoy_scratch[8];
    volatile unsigned long apply_dispatch_shadow;
    volatile unsigned long apply_dispatch_mirror;
    volatile unsigned long apply_dispatch_counter;
    volatile unsigned long apply_dispatch_gate;
    volatile unsigned long apply_decoy_scratch[8];

    volatile unsigned long xchar_mix;
    volatile unsigned long xchar_mirror;
    volatile unsigned long xchar_count;
    volatile unsigned long xchar_last;

    volatile unsigned long fake_lane_mix;
    volatile unsigned long fake_lane_mirror;
    volatile unsigned long fake_lane_count;
    volatile unsigned long fake_lane_last;
    volatile unsigned long fake_lane_bad;

    volatile unsigned long route_roll_mix;
    volatile unsigned long route_roll_mirror;
    volatile unsigned long route_roll_count;
    volatile unsigned long route_roll_last;
    volatile unsigned long route_roll_bad;
    //加密后的 target delta 表
    volatile unsigned long enc_target_deltas[STAGE_COUNT];
};

struct AbyssState g;
static struct InputVault input_vault;
static struct EventRuntime evrt;
static volatile unsigned long *handler_table_lazy_words;
static unsigned char *handler_table_page;

#define HT_DESC_BASE 128U
#define HTF_META      U64(0x0000000000000001)
#define HTF_FUTEX     U64(0x0000000000000002)
#define HTF_SIGILL    U64(0x0000000000000004)
#define HTF_SEGV      U64(0x0000000000000008)
#define HTF_HEARTBEAT U64(0x0000000000000010)
#define HTF_RX        U64(0x0000000000000020)
#define HTF_MEMFD     U64(0x0000000000000040)
#define HTF_PVM       U64(0x0000000000000080)
#define HTF_PHASE     U64(0x0000000000000100)
#define HTF_ISLAND    U64(0x0000000000000200)

#include "ghost_step30_generated.h"

static const unsigned long generated_stage_ctx_desc[SEMANTIC_STAGE_COUNT] = {
    U64(0x4F6D79B9DABC3C4F), U64(0xED34F372599EBBE0), U64(0x0BFC6D2CDAC13376), U64(0xA987E6E55D3DB697),
    U64(0xC64F609FDC011616), U64(0x6416DA585C1894A3), U64(0x82DE5412DF5D13C4), U64(0x20E1CDCB5FE08967),
    U64(0x5EA94785D8453CE2), U64(0xFF70C13E58A6C209), U64(0x1D383AF8DDA94198), U64(0xBBC3B4B15304DF07),
    U64(0xD98B2E6BD62E7745), U64(0x7652A82455B9FEF9), U64(0x941A21DEDE0E6049), U64(0x322D9B975C8D1193),
    U64(0x50F51551DFD6FD3D), U64(0xCEBC8F0A5EE748AB), U64(0x6F4408C4DCBDD2D2), U64(0x8D0F827D59F7255F),
    U64(0x2BD6FC37DCDD96FF), U64(0x499E75F05A660505), U64(0xE7A1EFAAC78573BA), U64(0x046969634147D80B),
    U64(0xA230E31DC47D7D56), U64(0xC0F85CD6401490D0), U64(0x7E83D690C68F216F), U64(0x9F4B50495AB24D9A),
    U64(0x3D12CA03DFADF43D), U64(0x5BDA43BC58896C8F), U64(0xF9EDBD76DECA80C1), U64(0x17B5372F5B542261),
    U64(0xB47CB0E9DB5BBFF4), U64(0xD2042AA255761807), U64(0x70CFA45CD280F293), U64(0xEE971E155043570C),
    U64(0x0F5E97CFD40E165B), U64(0xAD6611885004F6E0), U64(0xCB298B42D02C514B), U64(0x69F104FB54BF2887),
    U64(0x87B87EB5DB41BF10), U64(0x2443F86E59346289), U64(0x420B7228DA5901FB), U64(0xE0D2EBE1596ABE66),
    U64(0x1E9A659BDAAF77F4), U64(0xBCADDF5466131D3A), U64(0xDD75590EE41CA199), U64(0x7B3CD2C760127132),
    U64(0x99C44C81E7010150), U64(0x378FC63A642AAFC8), U64(0x54573FF4E7971D57), U64(0xF21EB9AD679940B6),
    U64(0x10263367E30C8A13), U64(0x8EE9AD205F3DE1A4), U64(0x2CB126DAD9073CC7), U64(0x4D78A0935D127F41),
    U64(0xEB001A4DD768C1EF), U64(0x09CB940654503506), U64(0xA7930DC0D43B6C98), U64(0xC45A8779510DA93A),
    U64(0x62620133D68CEB49), U64(0x80357AEC51920AD3), U64(0x3EFCF4A6D76D4C6A), U64(0x5C846E5F525F8697),
    U64(0xFD4FE819D761C313), U64(0x1B1761D25296FFBA), U64(0xB9DEDB8CD21BBE25), U64(0xD7E655454573726D),
    U64(0x75A9CEFFC5CC0BD7), U64(0x927148B845FAD343), U64(0x3038C272C6DD9F93), U64(0xAEC03C2B43184F32),
    U64(0xCC8BB5E5C09D02B4), U64(0x6D532F9E469105D6), U64(0x8B1AA958C3D0CF7A), U64(0x2922231146199BFC),
    U64(0x47F59CCBC4A86A2B), U64(0xE5BD1684461438A7), U64(0x0244903EC893EC3F), U64(0xA00C09F74DC0D74E),
    U64(0xDED783B1D0D281F1), U64(0x7C9EFD6A541B0F7C), U64(0x9AA67724D5695E8F), U64(0x3B69F0DD54CD621B),
    U64(0x59316A97D5378AAA), U64(0xF7F8E450572CC1D8), U64(0x15805E0AD750FE64), U64(0xB24BD7C351A81CE2),
    U64(0xD013517DD3E24018), U64(0x4EDACB36542E57AD), U64(0xECE244F0A8D5AD3B), U64(0x0AB5BEA92F158942),
    U64(0xAB7D3863AD7BEBFD), U64(0xC904B21C20FF2969), U64(0x67CC2BD6A2080D82), U64(0x8597A58F25096537),
    U64(0x225F1F49A61C41A4), U64(0x4066990223EDA3F6), U64(0xFE2E12BCA2087858), U64(0x1CF18C7527461DEF),
    U64(0xBAB9062FA04E0E1A), U64(0xDB407FE82B722D93), U64(0x790BF9A2ADD8DB3B), U64(0x97D3735B2B85E270),
    U64(0x359AED15AE5B87CE), U64(0x53A266CE2F169B6C), U64(0xF075E088D6CC88B4), U64(0x6E3D5A4153B5751B),
    U64(0x8CC4D3FBD7696DAD), U64(0x2A8C4DB451F444F4), U64(0x4B57C76ED7992A4B), U64(0xE91F4127507D3ACD),
    U64(0x0726BAE1CCB20503), U64(0xA5EE349A4CD1118C), U64(0xC3B1AE54C9959A13), U64(0x6079280D48A98F41),
    U64(0x9E00A1C7C80E8DE7), U64(0x3CC81B804F6FBD75), U64(0x5A93953ACA9FBA8D), U64(0xFB5B0EF342B1B218),
    U64(0x196288ADC031C590), U64(0xB72A02664422CBD1), U64(0xD5FD7C20C4F0EA49), U64(0x7384F5D94107E6D5),
    U64(0x904C6F93C81AEE13), U64(0x0E17E94C4D31D594), U64(0xACDF6306CD84C83B), U64(0xCAE6DCBF4BD5CA73),
    U64(0x68AE5679C895C7D9), U64(0x8971D032490BC172), U64(0x273949ECCADD3BF1), U64(0x45C0C3A54FE93F29),
    U64(0xE3883D5FCA270CB4), U64(0x0053B71856140C35), U64(0xBE1B30D2D6181947), U64(0xDC22AA8B69FA00E0),
    U64(0x7AEA2445EA820773), U64(0x98BD9DFE6E5078A8), U64(0x394517B8EB474B3E), U64(0x570C91716F6655A9),
    U64(0xF5D40B2BE8536CDD), U64(0x139F84E46CB76659), U64(0xB1A6FE9EED3D6AC5), U64(0x2E6E78576A369A0F),
    U64(0x4C31F211EEDE84A8), U64(0xEAF96BCA6FF1B33D), U64(0x0880E584E937A446), U64(0xA9485F3D69BFA8F3),
    U64(0xC713D8F7E2008049), U64(0x65DB52B06B2A9A9C), U64(0x83E2CC6AE9246737), U64(0x21AA46236C505581),
    U64(0x5E7DBFDDEADD4AD5), U64(0xFC0539966B4A2D7B), U64(0x1ACCB350E83016E2), U64(0xB8942D09692CC310),
    U64(0xD95FA6C3E86FE0A9), U64(0x7767207C739AF20D), U64(0x952E9A36F7199440), U64(0x33F613EF4916ADF1),
    U64(0x51B98DA9CC484876), U64(0xCE4107624C0F648F), U64(0x6C08811CCB7C0701), U64(0x8AD3FAD54A1FDB8E),
    U64(0x289B748FCEB300C2), U64(0x46A2EE4849D46A5D), U64(0xE76A6802C84844E3), U64(0x053DE1BB4B50A619),
    U64(0xA3C55B75CE828AAE), U64(0xC18CD52E4CEDDC02), U64(0x7E544EE8CD603677), U64(0x9C1FC8A14D4231EC)
};

/* step36: next physical stage is a permutation chain, not stage+1. */
static const unsigned long generated_stage_next_desc[SEMANTIC_STAGE_COUNT] = {
    U64(0x9FF01266D7517A82), U64(0xED2FCC31B14593D0), U64(0x3B5A86CC2EABC458), U64(0x0890709F1733816A),
    U64(0x56CF2AAA0B424EC6), U64(0xA47AE564F6B72FC3), U64(0xF5B05F378D812089), U64(0xC3EF09C28BA165E1),
    U64(0x111AC39D7CD29257), U64(0x7F51BDA83802BBC5), U64(0x4C8F687B0FB99CC8), U64(0x9A3A2235D1B679C1),
    U64(0xE8719CC095F116B4), U64(0x39AF56934C8227B5), U64(0x07DA00AE6EC86891), U64(0x5511FB794F146D53),
    U64(0xA34CB50BF67FCAEA), U64(0xF0FA6FC681328395), U64(0xDE31D991A19E747E), U64(0x2C6C93AC589211D6),
    U64(0x7D9A4E7F65B93E6D), U64(0x4BD1380A5EB55F25), U64(0x990CF2C49CF7701F), U64(0xE6BBAC978104D5E1),
    U64(0x34F166A279838298), U64(0x022CD17D464A4B83), U64(0x505B8B085128EC0A), U64(0xA19145DAA3E52904),
    U64(0x8FCC3F95F71C260F), U64(0xDD7BE9A09F3777DA), U64(0x2AB6A4737AF0D8AB), U64(0x78EC1E0E307ABD83),
    U64(0x461BC8D921F55AED), U64(0x945682EBE8A9F335), U64(0xE58C7CA698A22426), U64(0x333B377154E821C8),
    U64(0x0176E10C0B096E39), U64(0x6EAC5BDF0276CFF5), U64(0xBCDB15E9E5708095), U64(0x8A16CFA49F6A45E1),
    U64(0xD84DBA77B9FBF2DD), U64(0x29FB740223FADB20), U64(0x77362EDD05953C30), U64(0x456D98E879E719E4),
    U64(0x929B52BAABECF6E5), U64(0xE0D60D75BB5B8728), U64(0xCE0DC70059E24876), U64(0x1FB8B1D344C28D2E),
    U64(0x6DF66BEE1F7BEADB), U64(0xBB2D25B8F5592301), U64(0x8958904BCBB51421), U64(0xD6964A069CBFF132),
    U64(0x24CD04D15F269E5D), U64(0x7278FEEC11F7BF55), U64(0x43B7A8BF142D902F), U64(0x91ED6349ADE3F5C9),
    U64(0xFF18DD048C042247), U64(0xCD5797D75C4E2B5B), U64(0x1A8D41E26A7ECC55), U64(0x68383BBD0CA38922),
    U64(0xB677F64FFD9846F3), U64(0x87A2A01AD5D19735), U64(0xD5D81AD596DEF80E), U64(0x2317D4E06BDD1D85),
    U64(0x71428EB315E83A14), U64(0x5EF8794E6494D3A3), U64(0xAC373318EFD4844D), U64(0xFA62ED2BB08D417B),
    U64(0xCB99A7E66A4C8E82), U64(0x19D711B151E8EF7E), U64(0x6702CC4C11BC605D), U64(0xB4B9861EFB6B254C),
    U64(0x82F77029D27DD290), U64(0xD0222AE4AAC6FB31), U64(0x3E59E4B772A75C5E), U64(0x0F975F4230C1B975),
    U64(0x5DC2091D3863D60F), U64(0xAB79C32FE17F6717), U64(0xF8B4BDFA94572817), U64(0xC6E277B56E5D2D49),
    U64(0x141922402A300AAA), U64(0x62549C131ABB4375), U64(0xB382562DE217B44D), U64(0x813900F8DF74D1B2),
    U64(0xEF74FA8B85067E45), U64(0x3CA3B54636571EDA), U64(0x0AD96F11415B3788), U64(0x5814D92C613F14BE),
    U64(0xA64393FE887D41D6), U64(0xF7F94D89F7268ACA), U64(0xC53438441966D352), U64(0x1363F21736AD6855),
    U64(0x609EAC22518865B8), U64(0x4ED466FCAAC836D4), U64(0x9C03D08F98AA1FDC), U64(0xEDBE8B5ADEDE7CDC),
    U64(0x3BF4451572699947), U64(0x09233F205D4FB29D), U64(0x575EE9F37EE96BBC), U64(0xA495A38D8F9D60E6),
    U64(0xF2C31E58D55D2D84), U64(0xC07EC86BD89B0ED0), U64(0x11B582261FBF47CA), U64(0x7FE37CF161B584C9),
    U64(0x4D1E36839786B186), U64(0x9B55E15E90C59AF5), U64(0xE8835B69989E632A), U64(0x363E1524095ED8E5),
    U64(0x0475CFF77FF23598), U64(0x55A0B9824F4A4690), U64(0xA3DE745C8BB58FCF), U64(0xF1152E6FE832CCA0),
    U64(0xDF40983AED33A9C1), U64(0x2CFE52F5050B62AE), U64(0x7A350C807A74DBB7), U64(0x4860C752A19B30A2),
    U64(0x999FB16D9A525DB9), U64(0xE7D56B38F166FEC2), U64(0x350025CB00F5D7FD), U64(0x02BF9F8671A4B4B4),
    U64(0x50F54A5176BF612B), U64(0xBE2004638A7CEAC9), U64(0x8C5FFE3ED95533DB), U64(0xDD8AA8C986364820),
    U64(0x2BC062841F260590), U64(0x797FDD5765F0D6B6), U64(0x46AA9761829EBFD0), U64(0x94E0413CB9E35C54),
    U64(0xE21F3BCFEF87F962), U64(0x304AF59A1D641253), U64(0x0181A05560624B13), U64(0x6F3F1A60687D000A),
    U64(0xBD6AD432BF72CD06), U64(0x8AA18ECD881FAECF), U64(0xD8DF7898BA59A7C0), U64(0x260A32AB03A2E405),
    U64(0x7441ED666E34112E), U64(0x45FCA73083103A4E), U64(0x932A11C3A1870355), U64(0xE161CB9EC979F83F),
    U64(0xCE9C85A90CFE954C), U64(0x1CCA70644FC0A66D), U64(0x6A012A374386EF3D), U64(0xBBBCE4C1BD57EC2E),
    U64(0x89EA5E9CD7D5495E), U64(0xD72108AFDE93021E), U64(0x255CC37A3DB6FB32), U64(0x728BBD355FB99079),
    U64(0x40C177C7DAB2BDD5), U64(0xAE7C2192B2DDDE30), U64(0xFFAB9BADF08DF70A), U64(0xCDE156780ADC5416),
    U64(0x1B1C000B11DF0189), U64(0x694BFAC6402DCA87), U64(0xB686B49099A49322), U64(0x843C6EA3DB81A812),
    U64(0xD26BD97EC6EBA572), U64(0x23A6930931C1F612), U64(0x71DC4DC40CE75F82), U64(0x5F0B07969F693C32),
    U64(0xAD46F1A1AFF3D923), U64(0xFAFDAC7CCCBD7256), U64(0xC82B660F3310AB65), U64(0x1666D0DA1875A0A6),
    U64(0x679D8A954FD0EDA9), U64(0xB5CB44A79C354E77), U64(0x83063F7294BB07A9), U64(0xD0BDE90DDC80C44A),
    U64(0x3EE8A3D87D6E71AC), U64(0x0C261DEBFA1D5A97), U64(0x5A5DD7A52D12A269), U64(0xAB8882701D2A9B6B)
};

struct StageLocalCtx;



long spawn_watchdog(void (*fn)(), unsigned char *stack, unsigned long stack_size);
unsigned long small_hash_bytes(const unsigned char *p, unsigned long n);
void poison_debug_state(unsigned long reason);
static inline __attribute__((always_inline)) void watchdog_sleep_ms(long ms);
void vm_heartbeat_gate(unsigned int stage);
void init_heartbeat_runtime();
void heartbeat_pulse_thread();
unsigned long heartbeat_target_mask(int n);
unsigned long heartbeat_guard_word();
unsigned char heartbeat_guard_byte(unsigned int stage);
unsigned long raw_stage_delta(int n);
unsigned long decode_target(int n);
void srop_jump_seeded(unsigned long target, unsigned int next_stage);
unsigned long target_delta_guard_word();
unsigned char target_delta_guard_byte(unsigned int stage);
void target_delta_mark_page_ready(unsigned long source_tag);
void build_target_delta_page_image(unsigned char *page);
void init_rx_helper_runtime();
void vm_rx_helper_gate(unsigned int stage);
unsigned long rx_helper_guard_word();
unsigned char rx_helper_guard_byte(unsigned int stage);
unsigned long rx_helper_active_expected_mix();
unsigned long rx_helper_active_expected_guard();
unsigned long rx_helper_target_expected_root();
unsigned long helper_sealed_target_guard_word();
unsigned char helper_sealed_target_byte(unsigned int stage);
void init_memfd_stage2_runtime();
void vm_memfd_stage2_gate(unsigned int stage);
unsigned long memfd_stage2_guard_word();
unsigned char memfd_stage2_guard_byte(unsigned int stage);
unsigned long memfd_stage2_active_expected_mix();
unsigned long memfd_stage2_active_expected_guard();
unsigned long memfd_stage2_commit_expected_mix();
void memfd_stage2_commit_sample(unsigned char logical_stage, unsigned char idx, unsigned char c, unsigned long state, unsigned long micro);
unsigned long memfd_stage2_target_mask(int n);
unsigned long memfd_stage2_target_expected_shadow();
unsigned long memfd_stage2_target_guard_word();
unsigned long helper_output_key_guard_word();
void init_process_vm_child_runtime();
void vm_process_vm_gate(unsigned int stage);
unsigned long process_vm_guard_word();
unsigned char process_vm_guard_byte(unsigned int stage);
void watchdog_process_vm_guard();
void process_vm_child_worker(unsigned long parent_pid);
void clear_page_bytes(unsigned char *p, unsigned long n);
void init_handler_table_runtime();
void vm_handler_table_gate(unsigned int stage, unsigned char logical_stage, unsigned char phase, unsigned char idx, unsigned char c);
unsigned long handler_table_desc_flags(unsigned int stage);
unsigned long handler_table_guard_word();
unsigned char handler_table_guard_byte(unsigned int stage);
int handler_table_try_resolve_fault(unsigned long fault_addr);
static inline __attribute__((always_inline)) unsigned int semantic_stage_of(unsigned int stage);
static inline __attribute__((always_inline)) unsigned int stage_expansion_lane(unsigned int stage);
static inline __attribute__((always_inline)) unsigned int stage_lane_at_rank(unsigned int sem, unsigned int rank);
static inline __attribute__((always_inline)) unsigned int stage_lane_rank(unsigned int sem, unsigned int lane);
static inline __attribute__((always_inline)) unsigned int stage_group_entry(unsigned int sem);
static inline __attribute__((always_inline)) unsigned int stage_real_lane(unsigned int sem);
unsigned char runtime_core_stage_mask(unsigned char logical_stage);
void vm_event_barrier(unsigned int stage);
void init_eventfd_algorithm_gate(void);
unsigned long event_algo_guard_word(void);
unsigned char eventfd_algorithm_stage_mask(struct StageLocalCtx *ctx, unsigned long micro);

void init_code_island_runtime();
void vm_code_island_gate(unsigned int stage);
unsigned long code_island_guard_word();
unsigned char code_island_guard_byte(unsigned int stage);
unsigned long route_roll_expected_mirror();
unsigned long route_roll_guard_word();
unsigned char route_roll_guard_byte(unsigned int stage);

typedef unsigned long (*rx_helper_fn_t)(unsigned long, unsigned long, unsigned long, unsigned long);
static void *rx_helper_page = 0;
static rx_helper_fn_t rx_helper_fn = 0;
static void *memfd_stage2_page = 0;
static rx_helper_fn_t memfd_stage2_fn = 0;
static void *code_island_page = 0;
static rx_helper_fn_t code_island_fn = 0;

static unsigned char watchdog_stack_0[WATCHDOG_STACK_SIZE];
static unsigned char watchdog_stack_1[WATCHDOG_STACK_SIZE];
static unsigned char watchdog_stack_2[WATCHDOG_STACK_SIZE];
static unsigned char watchdog_stack_3[WATCHDOG_STACK_SIZE];
static unsigned char watchdog_stack_4[WATCHDOG_STACK_SIZE];
static unsigned char watchdog_stack_5[WATCHDOG_STACK_SIZE];
static unsigned char watchdog_stack_6[WATCHDOG_STACK_SIZE];
static unsigned char watchdog_stack_7[WATCHDOG_STACK_SIZE];
static unsigned char watchdog_stack_8[WATCHDOG_STACK_SIZE];
static unsigned char sigalt_stack_main[SIGALT_STACK_SIZE] __attribute__((aligned(16)));
static unsigned char uffd_fill_page[UFFD_PAGE_SIZE] __attribute__((aligned(4096)));
static unsigned char target_delta_fill_page[TARGET_DELTA_BYTES] __attribute__((aligned(4096)));
static volatile unsigned long *sealed_lazy_words;
static volatile unsigned long *target_delta_lazy_words;
static int sealed_uffd_fd = -1;

struct RouteProjectionGateShardA {
    unsigned long shadow_a;
    unsigned long seed;
    unsigned char bias_enc;
    unsigned char bias_key;
    unsigned short touch;
};

struct RouteProjectionGateShardB {
    unsigned long shadow_b;
    unsigned long salt;
    unsigned char phase_enc;
    unsigned char phase_key;
    unsigned char lane_enc;
    unsigned char lane_key;
    unsigned short touch;
};

struct RouteProjectionLaneCell {
    unsigned long seed;
    unsigned char salt;
    unsigned char stride;
    unsigned short fold;
};

struct RouteProjectionRuntimeCache {
    unsigned char tap;
    unsigned char phase_noise;
    unsigned char lane_noise;
    unsigned char latch;
    struct RouteProjectionLaneCell lanes[4];
    unsigned long mirror;
    unsigned long decoy;
};

struct RouteProjectionMirrorGate {
    unsigned long shadow;
    unsigned long mirror;
    unsigned char enable_enc;
    unsigned char enable_key;
    unsigned char lane_enc;
    unsigned char lane_key;
    unsigned short fold;
};

struct RouteProjectionEpochGate {
    unsigned long nonce;
    unsigned long mix;
    unsigned char epoch_enc;
    unsigned char epoch_key;
    unsigned short touch;
};

struct RouteProjectionRuntimeShardA {
    unsigned long seed;
    unsigned long mirror;
    unsigned char alpha_enc;
    unsigned char alpha_key;
    unsigned short touch;
};

struct RouteProjectionRuntimeShardB {
    unsigned long fold;
    unsigned long latch_seed;
    unsigned char beta_enc;
    unsigned char beta_key;
    unsigned char arm_enc;
    unsigned char arm_key;
    unsigned short touch;
};


static const unsigned long sealed_packs_a[6] = {
    U64(0x1F04A06DC887F108), U64(0x9E9E8CCC0FA7092A), U64(0xB1464F96B5D20AE8),
    U64(0x5F3E4BA41A5A1305), U64(0x0878B503A7A12544), U64(0x0000000000413392)
};
static const unsigned long sealed_packs_b[6] = {
    U64(0x0000010000010400), U64(0x0002020100030101), U64(0x0000000203020100),
    U64(0x0200000001000300), U64(0x0100010000000100), U64(0x0000000000000201)
};
static volatile struct RouteProjectionGateShardA route_projection_gate_a = {
    U64(0xC3A5C85C97CB3127), U64(0x5F3564959A6C932F), 0x59, 0xa6, 0x6d31
};
static volatile struct RouteProjectionGateShardB route_projection_gate_b = {
    U64(0xB492B66FBE98F273), U64(0xD6E8FEB86659FD93), 0x73, 0x2d, 0x36, 0x91, 0xb17c
};
static volatile struct RouteProjectionRuntimeCache route_projection_cache = {
    0x5a, 0x5e, 0xa7, 0x02,
    {
        { U64(0x9E3779B97F4A7C15), 0x31, 0x07, 0x1021 },
        { U64(0xD1B54A32D192ED03), 0x44, 0x0b, 0x2043 },
        { U64(0xA24BAED4963EE407), 0x59, 0x0d, 0x4085 },
        { U64(0xC2B2AE3D27D4EB4F), 0x6d, 0x11, 0x8109 }
    },
    U64(0x243F6A8885A308D3),
    U64(0x13198A2E03707344)
};
static volatile struct RouteProjectionMirrorGate route_projection_mirror_gate = {
    U64(0x94D049BB133111EB), U64(0x2545F4914F6CDD1D), 0xe2, 0x9b, 0x4c, 0x27, 0x51d3
};
static volatile struct RouteProjectionEpochGate route_projection_epoch_gate = {
    U64(0xB7E151628AED2A6B), U64(0xBF7158809CF4F3C7), 0x7d, 0x22, 0x3c91
};
static volatile struct RouteProjectionRuntimeShardA route_projection_runtime_a = {
    U64(0x6A09E667F3BCC909), U64(0xBB67AE8584CAA73B), 0x64, 0xb2, 0x4a91
};
static volatile struct RouteProjectionRuntimeShardB route_projection_runtime_b = {
    U64(0x3C6EF372FE94F82B), U64(0xA54FF53A5F1D36F1), 0x11, 0xc8, 0x9a, 0x55, 0xd2c7
};
static volatile unsigned long route_projection_runtime_latch = U64(0x510E527FADE682D1);
static const unsigned char route_projection_runtime_targets[4] = {
    0x3e, 0xf7, 0xe2, 0x00
};
static const unsigned char route_projection_orbit_targets[4] = {
    0xd8, 0x68, 0xd6, 0x10
};
static const unsigned long mirror_hint_packs[6] = {
    U64(0xC36C714BF465EDE9), U64(0x4A639D94EA0F76F3), U64(0xBCA80DC307590489),
    U64(0xA6AEA3803E5DEB63), U64(0x8A9944EDDB0F4921), U64(0x00000000003BE538)
};
static const unsigned long route_projection_residue_packs[6] = {
    U64(0x61322402C3EC3496), U64(0x22FB87EEA50922F9), U64(0x56C70C0F14FA24D7),
    U64(0xCC5C08C7D592189A), U64(0x14972CCE3963248A), U64(0x0000000000EF0661)
};

// 假表：故意做得像真正校验表。
static const unsigned char fake_expected_a[FLAG_LEN] = {
    0x7b, 0xab, 0xf1, 0x4d, 0xbf, 0x47, 0xe5, 0x99,
    0x63, 0x43, 0x39, 0x45, 0x67, 0x9f, 0xed, 0x51,
    0xcb, 0x5b, 0x01, 0xbd, 0x8f, 0x77, 0x75, 0x89,
    0xb3, 0xf3, 0x49, 0xb5, 0x37, 0xcf, 0x7d, 0x41,
    0x1b, 0x0b, 0x11, 0x2d, 0x5f, 0xa7, 0x05, 0x79,
    0x03, 0xa3, 0x59
};
static const unsigned char fake_expected_b[FLAG_LEN] = {
    0xde, 0xc4, 0xea, 0x9c, 0xb6, 0x6c, 0x5a, 0x24,
    0x0e, 0xe4, 0xba, 0xac, 0xd6, 0xfc, 0x2a, 0x04,
    0x7e, 0x44, 0xaa, 0x7c, 0x16, 0x2c, 0x3a, 0xe4,
    0xce, 0xa4, 0x9a, 0x6c, 0x36, 0x5c, 0x6a, 0x84,
    0x9e, 0x84, 0xea, 0xdc, 0x36, 0xec, 0x9a, 0xa4,
    0x4e, 0x64, 0x3a
};

static unsigned char enc_success[40] = {
    104, 42, 254, 8, 2, 163, 148, 40, 115, 80,
    203, 225, 60, 220, 130, 87, 64, 118, 184, 157,
    210, 245, 182, 41, 152, 119, 176, 193, 169, 28,
    148, 66, 233, 168, 159, 180, 226, 3, 58, 5
};
static unsigned char enc_fail[38] = {
    104, 42, 254, 8, 2, 163, 148, 43, 100, 95,
    204, 240, 61, 150, 140, 46, 118, 108, 237, 220,
    211, 229, 228, 51, 158, 114, 161, 133, 224, 6,
    220, 73, 166, 128, 142, 168, 191, 122
};
static const unsigned char enc_final_state_output_v5[40] = {
    0x84, 0xe2, 0x58, 0x04, 0x4f, 0x56, 0x05, 0x19, 0x5a, 0x47,
    0xf6, 0xa4, 0x14, 0x1b, 0xe2, 0x96, 0x9e, 0x44, 0xba, 0x01,
    0xe2, 0x31, 0x67, 0xf8, 0x6c, 0xd0, 0x71, 0x6d, 0xb1, 0x44,
    0xbb, 0x42, 0xca, 0x11, 0x35, 0xe2, 0xf8, 0xbe, 0x34, 0xa1
};

// Anti-debug strings are encrypted; decoded only inside watchdog threads.
static const unsigned char enc_status_path_v3[] = {117, 81, 194, 237, 115, 172, 72, 66, 118, 28, 51, 234, 208, 3, 82, 162, 117};
static const unsigned char enc_maps_path_v3[] = {202, 75, 166, 198, 243, 112, 78, 237, 223, 47, 77, 94, 36, 66, 72};
static const unsigned char enc_tracer_key_v3[] = {96, 51, 193, 161, 234, 181, 132, 109, 165, 240};
static const unsigned char enc_frida_v3[] = {101, 51, 137, 75, 200};
static const unsigned char enc_gdb_v3[] = {233, 214, 134};
static const unsigned char enc_lldb_v3[] = {109, 206, 92, 77};
static const unsigned char enc_gumjs_v3[] = {151, 69, 55, 233, 85, 10};
static const unsigned char enc_pin_v3[] = {84, 148, 10};
static const unsigned char enc_preload_v3[] = {173, 54, 16, 90, 72, 181, 203};
static const unsigned char enc_inject_v3[] = {228, 218, 5, 184, 214, 253};
static const unsigned char enc_hook_v3[] = {146, 161, 105, 11};
static const unsigned char enc_prompt_v4[] = {92, 171, 27, 88, 163, 38, 124, 200, 117, 83, 146, 17};
static const unsigned char enc_memfd_stage2_name_v4[] = {41, 61, 129, 247, 120, 155, 117, 228, 182, 175, 85, 0, 126, 205, 156, 72, 39, 253, 142};
void decode_blob(unsigned char *out, const unsigned char *enc, unsigned long len, unsigned long seed);
static inline __attribute__((always_inline)) void burn_stack_bytes(volatile unsigned char *p, unsigned long n);

void sys_write(int fd, const char *buf, unsigned long len) {
    __asm__ volatile ("syscall" : : "a"(1), "D"(fd), "S"(buf), "d"(len) : "rcx", "r11", "memory");
}
long sys_write_ret(int fd, const char *buf, unsigned long len) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(1), "D"(fd), "S"(buf), "d"(len) : "rcx", "r11", "memory");
    return ret;
}
long sys_read(int fd, char *buf, unsigned long len) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(0), "D"(fd), "S"(buf), "d"(len) : "rcx", "r11", "memory");
    return ret;
}
void sys_exit(int status) {
    __asm__ volatile ("syscall" : : "a"(231), "D"(status) : "rcx", "r11", "memory");
    for (;;) { }
}

long sys_openat(int dirfd, const char *path, int flags, int mode) {
    long ret;
    register long r10 __asm__("r10") = mode;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(257), "D"(dirfd), "S"(path), "d"(flags), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}
long sys_close(int fd) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(3), "D"(fd) : "rcx", "r11", "memory");
    return ret;
}
long sys_nanosleep(struct timespec_abyss *req) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(35), "D"(req), "S"(0) : "rcx", "r11", "memory");
    return ret;
}
long sys_gettimeofday(struct timeval_abyss *tv) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(96), "D"(tv), "S"(0) : "rcx", "r11", "memory");
    return ret;
}

long sys_eventfd2(unsigned int initval, int flags) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(SYS_EVENTFD2), "D"(initval), "S"(flags) : "rcx", "r11", "memory");
    return ret;
}

long sys_timerfd_create(int clockid, int flags) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(SYS_TIMERFD_CREATE), "D"(clockid), "S"(flags) : "rcx", "r11", "memory");
    return ret;
}

long sys_timerfd_settime(int fd, int flags, struct itimerspec_abyss *new_value) {
    long ret;
    register long r10 __asm__("r10") = 0;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(SYS_TIMERFD_SETTIME), "D"(fd), "S"(flags), "d"(new_value), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}

long sys_epoll_create1(int flags) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(SYS_EPOLL_CREATE1), "D"(flags) : "rcx", "r11", "memory");
    return ret;
}

long sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event_abyss *event) {
    long ret;
    register long r10 __asm__("r10") = (long)event;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(SYS_EPOLL_CTL), "D"(epfd), "S"(op), "d"(fd), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}

long sys_epoll_wait(int epfd, struct epoll_event_abyss *events, int maxevents, int timeout_ms) {
    long ret;
    register long r10 __asm__("r10") = timeout_ms;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(SYS_EPOLL_WAIT), "D"(epfd), "S"(events), "d"(maxevents), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}

long sys_futex(volatile unsigned int *uaddr, int op, unsigned int val, struct timespec_abyss *timeout) {
    long ret;
    register long r10 __asm__("r10") = (long)timeout;
    register long r8 __asm__("r8") = 0;
    register long r9 __asm__("r9") = 0;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(SYS_FUTEX), "D"(uaddr), "S"(op), "d"((unsigned long)val), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

long sys_futex_wait(volatile unsigned int *uaddr, unsigned int expected, struct timespec_abyss *timeout) {
    return sys_futex(uaddr, FUTEX_WAIT, expected, timeout);
}

long sys_futex_wake(volatile unsigned int *uaddr, unsigned int count) {
    return sys_futex(uaddr, FUTEX_WAKE, count, 0);
}

long sys_sigaltstack(struct stack_abyss *ss, struct stack_abyss *old_ss) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(SYS_SIGALTSTACK), "D"(ss), "S"(old_ss) : "rcx", "r11", "memory");
    return ret;
}

long sys_rt_sigaction(int sig, struct kernel_sigaction_abyss *act, struct kernel_sigaction_abyss *oldact, unsigned long sigsetsize) {
    long ret;
    register unsigned long r10 __asm__("r10") = sigsetsize;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(SYS_RT_SIGACTION), "D"(sig), "S"(act), "d"(oldact), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}

void *sys_mmap(void *addr, unsigned long len, int prot, int flags, int fd, unsigned long off) {
    long ret;
    register long r10 __asm__("r10") = flags;
    register long r8 __asm__("r8") = fd;
    register unsigned long r9 __asm__("r9") = off;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(SYS_MMAP), "D"(addr), "S"(len), "d"(prot), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return (void *)ret;
}

long sys_mprotect(void *addr, unsigned long len, int prot) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(SYS_MPROTECT), "D"(addr), "S"(len), "d"(prot) : "rcx", "r11", "memory");
    return ret;
}

long sys_memfd_create(const char *name, unsigned int flags) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(SYS_MEMFD_CREATE), "D"(name), "S"((unsigned long)flags) : "rcx", "r11", "memory");
    return ret;
}

long sys_lseek(int fd, long off, int whence) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(SYS_LSEEK), "D"(fd), "S"(off), "d"(whence) : "rcx", "r11", "memory");
    return ret;
}

long sys_getpid() {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(SYS_GETPID) : "rcx", "r11", "memory");
    return ret;
}

long sys_prctl(unsigned long option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    long ret;
    register unsigned long r10 __asm__("r10") = arg4;
    register unsigned long r8 __asm__("r8") = arg5;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(SYS_PRCTL), "D"(option), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8)
        : "rcx", "r11", "memory"
    );
    return ret;
}

long sys_clone_process() {
    long ret;
    register unsigned long r10 __asm__("r10") = 0;
    register unsigned long r8 __asm__("r8") = 0;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(SYS_CLONE), "D"(SIGCHLD_ABYSS), "S"(0UL), "d"(0UL), "r"(r10), "r"(r8)
        : "rcx", "r11", "memory"
    );
    return ret;
}

long sys_process_vm_writev(long pid, struct iovec_abyss *local_iov, unsigned long liovcnt,
                           struct iovec_abyss *remote_iov, unsigned long riovcnt, unsigned long flags) {
    long ret;
    register unsigned long r10 __asm__("r10") = (unsigned long)remote_iov;
    register unsigned long r8 __asm__("r8") = riovcnt;
    register unsigned long r9 __asm__("r9") = flags;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(SYS_PROCESS_VM_WRITEV), "D"(pid), "S"(local_iov), "d"(liovcnt), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

long sys_ioctl(int fd, unsigned long request, void *arg) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(SYS_IOCTL), "D"(fd), "S"(request), "d"(arg) : "rcx", "r11", "memory");
    return ret;
}

long sys_userfaultfd(int flags) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(SYS_USERFAULTFD), "D"(flags) : "rcx", "r11", "memory");
    return ret;
}

static inline __attribute__((always_inline)) unsigned long rol64(unsigned long x, int r) {
    return (x << r) | (x >> (64 - r));
}
static inline __attribute__((always_inline)) unsigned char rol8(unsigned char x, int r) {
    return (unsigned char)((x << r) | (x >> (8 - r)));
}

void bogus_syscall_storm() {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(39) : "rcx", "r11", "memory");//getpid
    g.entropy[0] ^= (unsigned long)ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(102) : "rcx", "r11", "memory");//getuid
    g.entropy[1] ^= ((unsigned long)ret << 7);
    __asm__ volatile("syscall" : "=a"(ret) : "a"(96), "D"(0), "S"(0) : "rcx", "r11", "memory");//gettimeofday
    g.entropy[2] += (unsigned long)ret;
}

static inline __attribute__((always_inline)) void OPAQUE_PREDICATE_NOISE(unsigned long var) {
    volatile unsigned long x = var ^ g.dummy_hash;
    if ((((x * x) + x) & 1UL) != 0) {
        g.dummy_hash ^= U64(0xDEADBEEFCAFEBABE);
        __asm__ volatile("nop; nop; nop; nop;" : : : "memory");
        sys_exit(137);
    } else {
        g.step_counter += 1;
        g.dummy_hash ^= U64(0x3141592653589793);
        g.dummy_hash ^= U64(0x3141592653589793);
    }
}

void deep_noise_generator(unsigned long seed) {
    volatile unsigned long x = seed ^ g.dummy_hash;
    for (int i = 0; i < 12; i++) {
        x ^= g.entropy[(i * 7) & 63];
        x = rol64(x + U64(0x9E3779B97F4A7C15), 11);
        OPAQUE_PREDICATE_NOISE(x);
        if ((i & 3) == 1) bogus_syscall_storm();
    }
    g.dummy_hash ^= (x & 0xff);
    g.dummy_hash ^= (x & 0xff);
}

unsigned long xorshift64(unsigned long s) {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
}

static unsigned char mirror_hint_key(unsigned char idx) {
    unsigned long s;
    s = U64(0xF1357AEA2E62A9C5) ^ ((unsigned long)(idx + 3U) * U64(0xC2B2AE3D27D4EB4F));
    s = xorshift64(s ^ rol64(U64(0xD6E8FEB86659FD93) + (unsigned long)idx * U64(0x9E3779B97F4A7C15),
                             (int)(((idx * 5U + 9U) & 31U) + 1U)));
    return (unsigned char)((s >> ((idx & 7U) * 8U)) ^ (s >> 41) ^ (idx * 0x39U + 0x4bU));
}

static unsigned char decode_mirror_hint(unsigned char idx) {
    unsigned char block;
    unsigned char shift;
    unsigned char enc;
    if (idx >= FLAG_LEN) {
        return 0;
    }
    block = (unsigned char)(idx >> 3);
    shift = (unsigned char)((idx & 7U) * 8U);
    enc = (unsigned char)(mirror_hint_packs[block] >> shift);
    return (unsigned char)(enc ^ mirror_hint_key(idx));
}

static unsigned char route_projection_residue_key(unsigned char idx) {
    unsigned long s;
    s = U64(0x6D1E5A77C0DEC0DE) ^ ((unsigned long)(idx + 5U) * U64(0xA24BAED4963EE407));
    s = xorshift64(s + rol64(U64(0x94D049BB133111EB) ^ ((unsigned long)idx * U64(0xD1B54A32D192ED03)),
                            (int)(((idx * 7U + 13U) & 31U) + 1U)));
    s ^= rol64(U64(0xF1357AEA2E62A9C5) + (unsigned long)idx * U64(0x100000001B3),
               (int)(((idx * 11U + 3U) & 31U) + 1U));
    return (unsigned char)((s >> ((idx & 7U) * 8U)) ^ (s >> 43) ^ (idx * 0x5dU + 0x71U));
}

__attribute__((noinline)) static unsigned char route_projection_residue_runtime_mask(unsigned char idx) {
    unsigned long s;

    s = route_projection_runtime_latch;
    s ^= rol64(route_projection_runtime_a.seed + (unsigned long)(idx + 1U) * U64(0xA24BAED4963EE407),
               (int)(((idx * 9U + 5U) & 31U) + 1U));
    s ^= route_projection_runtime_b.fold;
    s ^= rol64(route_projection_epoch_gate.mix ^ ((unsigned long)idx * U64(0x100000001B3)),
               (int)(((idx * 7U + 11U) & 31U) + 1U));
    s = xorshift64(s + route_projection_epoch_gate.nonce +
                   (unsigned long)idx * U64(0xD1B54A32D192ED03));
    return (unsigned char)((s >> ((idx & 7U) * 8U)) ^ (s >> 37) ^ (idx * 0xc7U + 0x5bU));
}

static unsigned char route_projection_residue_byte(unsigned char idx) {
    unsigned char block;
    unsigned char shift;
    unsigned char enc;
    if (idx >= FLAG_LEN) {
        return 0;
    }
    block = (unsigned char)(idx >> 3);
    shift = (unsigned char)((idx & 7U) * 8U);
    enc = (unsigned char)(route_projection_residue_packs[block] >> shift);
    return (unsigned char)(enc ^ route_projection_residue_key(idx) ^ route_projection_residue_runtime_mask(idx));
}

struct StageLocalCtx {
    unsigned long ctx_key;
    unsigned char decoy0;
    unsigned char logical_stage;
    unsigned int ctx_tag;
    unsigned char phase;
    unsigned char decoy1[5];
    unsigned char idx;
    unsigned long ctx_mirror;
    unsigned char c;
    unsigned char enc_logical;
    unsigned char enc_phase;
    unsigned char enc_idx;
    unsigned char enc_c;
    unsigned long shard_a;
    unsigned long shard_b;
};

__attribute__((noinline)) unsigned long stage_ctx_cookie(unsigned int physical_stage,
                                                        unsigned char logical_stage,
                                                        unsigned char phase,
                                                        unsigned char idx,
                                                        unsigned char c) {
    unsigned long x;

    x  = U64(0x4354585345414C31);
    x ^= ((unsigned long)(physical_stage + 1U) * U64(0x9E3779B97F4A7C15));
    x ^= ((unsigned long)(logical_stage + 0x100U) << ((phase & 7U) * 8U));
    x ^= ((unsigned long)(idx + 0x200U) << (((logical_stage ^ c) & 7U) * 8U));
    x ^= rol64(g.target_key ^ g.input_digest ^ g.route_roll_mix, (int)(((idx + 3U) & 31U) + 1U));
    x ^= rol64(g.phase_dispatch_shadow ^ g.virtual_dispatch_shadow, (int)(((phase * 7U + 5U) & 31U) + 1U));
    x = xorshift64(x + U64(0xD1B54A32D192ED03) + c);
    return x | U64(0x0101010101010101);
}

__attribute__((noinline)) void stage_ctx_seal(struct StageLocalCtx *ctx, unsigned int physical_stage) {
    unsigned long k;

    k = stage_ctx_cookie(physical_stage, ctx->logical_stage, ctx->phase, ctx->idx, ctx->c);
    ctx->ctx_key = k;
    ctx->decoy0 = (unsigned char)(k ^ (k >> 19) ^ physical_stage);
    for (unsigned char i = 0; i < 5U; i++) {
        ctx->decoy1[i] = (unsigned char)(rol8((unsigned char)(k >> ((i & 7U) * 8U)), (int)((i & 7U) + 1U)) ^
                                         (unsigned char)(physical_stage + i * 0x31U));
    }
    ctx->enc_logical = (unsigned char)(ctx->logical_stage ^ (unsigned char)k);
    ctx->enc_phase = (unsigned char)(ctx->phase ^ (unsigned char)(k >> 8));
    ctx->enc_idx = (unsigned char)(ctx->idx ^ (unsigned char)(k >> 16));
    ctx->enc_c = (unsigned char)(ctx->c ^ (unsigned char)(k >> 24));
    ctx->ctx_tag = (unsigned int)(xorshift64(k ^ ((unsigned long)ctx->logical_stage << 32) ^
                                             ((unsigned long)ctx->idx << 16) ^ ctx->c) & 0xffffffffU);
    ctx->shard_a = xorshift64(k ^ rol64(g.memfd_stage2_target_root ^ g.rx_helper_target_root,
                                        (int)(((ctx->idx + 7U) & 31U) + 1U)));
    ctx->shard_b = xorshift64(k ^ rol64(g.pvm_mailbox ^ g.pvm_mirror ^ g.handler_table_shadow,
                                        (int)(((ctx->phase + ctx->logical_stage) & 31U) + 1U)));
    ctx->ctx_mirror = ctx->shard_a ^ rol64(ctx->shard_b + k, (int)(((ctx->c ^ ctx->idx) & 31U) + 1U));
}

__attribute__((noinline)) unsigned long stage_ctx_integrity_word(struct StageLocalCtx *ctx) {
    unsigned long bad = 0;
    unsigned long k = ctx->ctx_key;
    unsigned int tag;
    unsigned long mirror;

    if ((unsigned char)(ctx->enc_logical ^ (unsigned char)k) != ctx->logical_stage) bad |= U64(0x43540001);
    if ((unsigned char)(ctx->enc_phase ^ (unsigned char)(k >> 8)) != ctx->phase) bad |= U64(0x43540002);
    if ((unsigned char)(ctx->enc_idx ^ (unsigned char)(k >> 16)) != ctx->idx) bad |= U64(0x43540004);
    if ((unsigned char)(ctx->enc_c ^ (unsigned char)(k >> 24)) != ctx->c) bad |= U64(0x43540008);

    tag = (unsigned int)(xorshift64(k ^ ((unsigned long)ctx->logical_stage << 32) ^
                                    ((unsigned long)ctx->idx << 16) ^ ctx->c) & 0xffffffffU);
    if (tag != ctx->ctx_tag) bad |= U64(0x43540010);

    mirror = ctx->shard_a ^ rol64(ctx->shard_b + k, (int)(((ctx->c ^ ctx->idx) & 31U) + 1U));
    if (mirror != ctx->ctx_mirror) bad |= U64(0x43540020);
    return bad;
}
static unsigned long route_projection_mirror_fold(struct StageLocalCtx *ctx,
                                                  unsigned char v,
                                                  unsigned char target,
                                                  unsigned long micro);
static unsigned long route_projection_hint_fold(struct StageLocalCtx *ctx,
                                                unsigned char v,
                                                unsigned char target,
                                                unsigned long micro);


static const unsigned char generated_stage_order_v2[SEMANTIC_STAGE_COUNT] = {
    0, 66, 71, 87, 117, 99, 9, 24, 16, 26, 152, 129, 22, 153, 138, 55,
    162, 79, 122, 105, 8, 143, 93, 13, 92, 108, 28, 155, 5, 18, 132, 74,
    124, 36, 149, 49, 84, 121, 100, 104, 126, 110, 65, 166, 159, 17, 96, 167,
    113, 59, 85, 27, 147, 6, 95, 63, 134, 150, 12, 80, 154, 48, 139, 88,
    30, 53, 52, 1, 21, 164, 133, 158, 156, 102, 60, 135, 94, 2, 146, 72,
    136, 118, 91, 130, 89, 7, 58, 39, 90, 128, 34, 140, 40, 101, 33, 144,
    46, 56, 47, 125, 15, 160, 3, 165, 70, 75, 82, 119, 31, 32, 77, 62,
    112, 81, 64, 20, 145, 107, 98, 86, 78, 57, 54, 73, 44, 161, 115, 61,
    76, 43, 163, 137, 19, 41, 157, 11, 38, 35, 103, 50, 123, 151, 29, 67,
    116, 37, 68, 142, 83, 141, 4, 10, 42, 114, 45, 97, 120, 131, 69, 111,
    51, 109, 25, 14, 127, 23, 106, 168, 148, 169, 170, 171
};

static const unsigned char rx_helper_blob_enc[] = {
    0xEF, 0x2E, 0x5F, 0xEF, 0x96, 0x57, 0xEF, 0x66, 0x67, 0xAA,
    0xEF, 0xA6, 0x77, 0xEF, 0x96, 0x6F, 0xEF, 0x66, 0x6F, 0xA0,
    0xEF, 0xCE, 0x67, 0x9C, 0x38, 0xFA, 0xA3, 0xEE, 0x1F, 0xB2,
    0xDB, 0xED, 0xD8, 0x1E, 0x9E, 0x90, 0x39, 0xEB, 0x96, 0x67,
    0x64
};
#define RX_HELPER_BLOB_LEN ((unsigned long)sizeof(rx_helper_blob_enc))
#define RX_HELPER_XOR_KEY 0xA7U
#define RX_HELPER_EXPECTED_HASH U64(0xAE8E7EA96FA46771)

unsigned long rx_helper_fallback(unsigned long a, unsigned long b, unsigned long c, unsigned long d) {
    unsigned long x = a ^ b;
    x = rol64(x, 13);
    x += c;
    x ^= d;
    x = rol64(x, 57); // ror 7
    x *= U64(0x45D9F3B);
    x ^= U64(0x9E3779B97F4A7C15);
    return x;
}

unsigned long rx_helper_hash_bytes(const unsigned char *p, unsigned long n) {
    unsigned long h = U64(0xA24BAED4963EE407);
    for (unsigned long i = 0; i < n; i++) {
        h ^= (unsigned long)p[i] + ((unsigned long)i * U64(0x100000001B3));
        h = rol64(h * U64(0x9E3779B97F4A7C15) + U64(0xD1B54A32D192ED03), (int)((i & 31) + 1));
        h ^= h >> 27;
    }
    return h;
}

unsigned long rx_helper_call(unsigned int stage, unsigned long x, unsigned long y, unsigned long z) {
    unsigned long salt = U64(0xA55A5AA55AA5A55A) ^ ((unsigned long)stage * U64(0x9E3779B97F4A7C15));
    unsigned long out;
    if (rx_helper_fn && g.rx_helper_ready) {
        out = rx_helper_fn(x, y, z, salt);
    } else {
        out = rx_helper_fallback(x, y, z, salt);
        g.rx_helper_bad |= U64(0x101);
    }
    g.rx_helper_calls += 1;
    g.rx_helper_last_stage = stage;
    g.rx_helper_shadow ^= rol64(out ^ x ^ y ^ z ^ salt ^ g.rx_helper_calls, ((stage + (unsigned char)out) & 31) + 1);
    return out;
}

void init_rx_helper_runtime() {
    unsigned char *dst;
    void *page = sys_mmap(0, UFFD_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!page || page == MAP_FAILED_ABYSS || (long)page < 0) {
        g.rx_helper_bad |= U64(0x201);
        rx_helper_fn = 0;
        return;
    }

    dst = (unsigned char *)page;
    for (unsigned long i = 0; i < RX_HELPER_BLOB_LEN; i++) {
        dst[i] = (unsigned char)(rx_helper_blob_enc[i] ^ RX_HELPER_XOR_KEY);
    }
    for (unsigned long i = RX_HELPER_BLOB_LEN; i < 128; i++) {
        dst[i] = 0xCC;
    }

    g.rx_helper_code_hash = rx_helper_hash_bytes(dst, RX_HELPER_BLOB_LEN);
    if (g.rx_helper_code_hash != RX_HELPER_EXPECTED_HASH) {
        g.rx_helper_bad |= U64(0x202);
    }

    if (sys_mprotect(page, UFFD_PAGE_SIZE, PROT_READ | PROT_EXEC) != 0) {
        g.rx_helper_bad |= U64(0x203);
        rx_helper_fn = 0;
        return;
    }

    rx_helper_page = page;
    rx_helper_fn = (rx_helper_fn_t)page;
    g.rx_helper_ready = 1;
    {
        unsigned long init_out = rx_helper_call(0xE1U, U64(0x1122334455667788), g.real_state, g.target_key);
        g.rx_helper_shadow ^= init_out;
        g.rx_helper_target_root = xorshift64(init_out ^ g.rx_helper_code_hash ^
                                            rol64(g.target_key, 23) ^
                                            U64(0x5258544754524F54));
        g.rx_helper_target_shadow = g.rx_helper_target_root ^ rx_helper_target_expected_root();
        g.helper_output_key_mix ^= rol64(g.rx_helper_target_root ^ init_out, 17);
    }
}

int vm_stage_needs_rx_helper(unsigned int stage) {
    return (handler_table_desc_flags(stage) & HTF_RX) != 0;
}

void vm_rx_helper_gate(unsigned int stage) {
    unsigned long a, b, c, r, x;
    if (!vm_stage_needs_rx_helper(stage)) return;
    a = g.real_state ^ ((unsigned long)stage * U64(0xD6E8FEB86659FD93));
    b = g.split_shadow[(stage / PHASE_COUNT) % FLAG_LEN] ^ g.heartbeat_key_mix;
    c = g.event_shadow ^ g.gate_shadow ^ g.uffd_shadow ^ g.td_uffd_shadow;
    r = rx_helper_call(stage, a, b, c);

    x = r ^ rol64(a, 7) ^ rol64(b, 19) ^ rol64(c, 31);
    x ^= ((unsigned long)stage * U64(0xA24BAED4963EE407)) + g.rx_helper_calls;
    x = xorshift64(x + g.rx_helper_code_hash + U64(0xC0DEC0DEC0DEC0DE));
    g.rx_helper_active_mix ^= rol64(x, ((stage + (unsigned char)x) & 31) + 1);
    g.rx_helper_active_mix = xorshift64(g.rx_helper_active_mix + U64(0x9E3779B97F4A7C15) + stage);
    g.rx_helper_active_seen ^= (U64(1) << (stage & 63));
    g.rx_helper_active_guard ^= rol64(g.rx_helper_active_mix ^ r ^ stage, ((stage & 31) + 1));
}

unsigned long rx_helper_active_expected_mix() {
    return U64(0x5DFECEB18B7EA3CC);
}

unsigned long rx_helper_active_expected_guard() {
    return U64(0x65FF1D87C675E9A6);
}

unsigned long rx_helper_target_expected_root() {
    unsigned long salt = U64(0xA55A5AA55AA5A55A) ^ ((unsigned long)0xE1U * U64(0x9E3779B97F4A7C15));
    unsigned long out = U64(0x1122334455667788) ^ U64(0x8BD642F9D5A34C17);
    out = rol64(out, 13);
    out += g.target_key;
    out ^= salt;
    out = rol64(out, 57);
    out *= U64(0x45D9F3B);
    out ^= U64(0x9E3739B97F4A7C15);
    unsigned long root = xorshift64(out ^ RX_HELPER_EXPECTED_HASH ^
                                    rol64(g.target_key, 23) ^
                                    U64(0x5258544754524F54));
    return root;
}

unsigned long helper_output_key_guard_word() {
    unsigned long bad = 0;
    if (!g.rx_helper_target_root || (g.rx_helper_target_root != rx_helper_target_expected_root())) bad |= U64(0x5151);
    if (g.rx_helper_target_shadow != (g.rx_helper_target_root ^ rx_helper_target_expected_root())) bad |= U64(0x5152);
    if (!g.memfd_stage2_target_root) bad |= U64(0x5154);
    if (g.memfd_stage2_target_shadow != memfd_stage2_target_expected_shadow()) bad |= U64(0x5155);
    return bad;
}

unsigned long helper_sealed_target_guard_word() {
    return helper_output_key_guard_word();
}

unsigned char helper_sealed_target_byte(unsigned int stage) {
    unsigned long bad = helper_sealed_target_guard_word();
    if (!bad) return 0;
    bad = xorshift64(bad ^ ((unsigned long)stage * U64(0x9E3779B97F4A7C15)) ^
                    g.rx_helper_target_root ^ rol64(g.memfd_stage2_target_root, 11));
    return (unsigned char)((bad >> ((stage & 7) * 8)) | 1U);
}

unsigned long rx_helper_guard_word() {
    unsigned long bad = g.rx_helper_bad;
    if (!g.rx_helper_ready || !rx_helper_fn || !rx_helper_page) bad |= U64(0x301);
    if (g.rx_helper_code_hash != RX_HELPER_EXPECTED_HASH) bad |= U64(0x302);
    if (g.rx_helper_calls < 5UL) bad |= U64(0x303);
    if (g.rx_helper_last_stage != 169UL) bad |= U64(0x304);
    if (g.rx_helper_active_seen != ((U64(1) << 17) | (U64(1) << 0) | (U64(1) << 57) | (U64(1) << 41))) bad |= U64(0x305);
    if (g.rx_helper_active_mix == U64(0xBEEFBEEFBEEFBEEF)) bad |= U64(0x306);
    if (g.rx_helper_active_guard == U64(0x13572468ACE0BDF0)) bad |= U64(0x307);
    return bad;
}

unsigned char rx_helper_guard_byte(unsigned int stage) {
    unsigned long w = g.rx_helper_bad;
    if (!g.rx_helper_ready || !rx_helper_fn || !rx_helper_page) w |= U64(0x401);
    if (g.rx_helper_code_hash != RX_HELPER_EXPECTED_HASH) w |= U64(0x402);
    return (unsigned char)((w >> ((stage & 7) * 8)) | (w != 0));
}

void init_code_island_runtime() {
    void *page = sys_mmap(0, UFFD_PAGE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!page || page == MAP_FAILED_ABYSS || (long)page < 0) {
        g.code_island_bad |= U64(0x2601);
        return;
    }
    code_island_page = page;
    code_island_fn = (rx_helper_fn_t)page;
    g.code_island_ready = 1;
    g.code_island_shadow ^= (unsigned long)page;
    g.code_island_shadow ^= (unsigned long)page;
}

unsigned long code_island_call(unsigned int stage, unsigned long x, unsigned long y, unsigned long z) {
    unsigned char *dst = (unsigned char *)code_island_page;
    unsigned long salt = U64(0xC0DE15A11A5C0DE) ^ ((unsigned long)stage * U64(0x94D049BB133111EB));
    unsigned long out = 0;

    if (!g.code_island_ready || !code_island_page || !code_island_fn) {
        g.code_island_bad |= U64(0x2602);
        return rx_helper_fallback(x, y, z, salt);
    }

    if (sys_mprotect(code_island_page, UFFD_PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        g.code_island_bad |= U64(0x2603);
        return rx_helper_fallback(x, y, z, salt);
    }

    for (unsigned long i = 0; i < RX_HELPER_BLOB_LEN; i++) {
        unsigned char k = (unsigned char)(RX_HELPER_XOR_KEY ^ ((stage + i) & 0));
        dst[i] = (unsigned char)(rx_helper_blob_enc[i] ^ k);
    }
    for (unsigned long i = RX_HELPER_BLOB_LEN; i < 128; i++) dst[i] = 0xCC;

    g.code_island_code_hash = rx_helper_hash_bytes(dst, RX_HELPER_BLOB_LEN);
    if (g.code_island_code_hash != RX_HELPER_EXPECTED_HASH) {
        g.code_island_bad |= U64(0x2604);
    }

    if (sys_mprotect(code_island_page, UFFD_PAGE_SIZE, PROT_READ | PROT_EXEC) != 0) {
        g.code_island_bad |= U64(0x2605);
        return rx_helper_fallback(x, y, z, salt);
    }

    out = code_island_fn(x, y, z, salt);

    if (sys_mprotect(code_island_page, UFFD_PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        g.code_island_bad |= U64(0x2606);
    } else {
        for (unsigned long i = 0; i < 128; i++) dst[i] = 0;
        g.code_island_wipes += 1;
        if (sys_mprotect(code_island_page, UFFD_PAGE_SIZE, PROT_NONE) != 0) {
            g.code_island_bad |= U64(0x2607);
        }
    }

    g.code_island_calls += 1;
    g.code_island_last_stage = stage;
    g.code_island_shadow ^= rol64(out ^ x ^ y ^ z ^ salt ^ g.code_island_calls, ((stage + (unsigned char)(out >> 16)) & 31) + 1);
    return out;
}

int vm_stage_needs_code_island(unsigned int stage) {
    return (handler_table_desc_flags(stage) & HTF_ISLAND) != 0;
}

void vm_code_island_gate(unsigned int stage) {
    unsigned long a, b, c, r, x;
    if (!vm_stage_needs_code_island(stage)) return;

    a = g.real_state ^ rol64(g.handler_table_stage_mix, ((stage & 31) + 1));
    b = g.memfd_stage2_commit_mix ^ g.rx_helper_active_mix ^ ((unsigned long)stage * U64(0xC01A17F00D15A11));
    c = g.pvm_stage_mix ^ g.uffd_shadow ^ g.td_uffd_shadow ^ g.heartbeat_key_mix;
    r = code_island_call(stage, a, b, c);

    x = r ^ rol64(a, 5) ^ rol64(b, 17) ^ rol64(c, 29);
    x ^= g.code_island_code_hash + ((unsigned long)stage * U64(0xA24BAED4963EE407));
    x = xorshift64(x + U64(0x434F444549534C45) + g.code_island_calls);
    g.code_island_active_mix ^= rol64(x, ((stage + (unsigned char)x) & 31) + 1);
    g.code_island_active_mix = xorshift64(g.code_island_active_mix + U64(0x9E3779B97F4A7C15) + stage);
    g.code_island_active_seen ^= (U64(1) << (stage & 63));
    g.code_island_active_guard ^= rol64(g.code_island_active_mix ^ r ^ g.code_island_shadow ^ stage, ((stage & 31) + 1));
}

unsigned long code_island_guard_word() {
    unsigned long bad = g.code_island_bad;
    if (!g.code_island_ready || !code_island_page || !code_island_fn) bad |= U64(0x7001);
    if (g.code_island_code_hash != RX_HELPER_EXPECTED_HASH) bad |= U64(0x7002);
    if (g.code_island_calls < 4UL) bad |= U64(0x7003);
    if (g.code_island_wipes < g.code_island_calls) bad |= U64(0x7004);
    if (g.code_island_last_stage != 170UL) bad |= U64(0x7005);
    if (g.code_island_active_seen != ((U64(1) << 11) | (U64(1) << 8) | (U64(1) << 7) | (U64(1) << 42))) bad |= U64(0x7006);
    if (g.code_island_active_mix == U64(0xC0DE15A11A5E0001)) bad |= U64(0x7007);
    if (g.code_island_active_guard == U64(0xC0DE15A11A5E0002)) bad |= U64(0x7008);
    return bad;
}

unsigned char code_island_guard_byte(unsigned int stage) {
    unsigned long w = g.code_island_bad;
    if (!g.code_island_ready || !code_island_page || !code_island_fn) w |= U64(0x7101);
    if (g.code_island_code_hash && g.code_island_code_hash != RX_HELPER_EXPECTED_HASH) w |= U64(0x7102);
    return (unsigned char)((w >> ((stage & 7) * 8)) | (w != 0));
}


unsigned long memfd_stage2_call(unsigned int stage, unsigned long x, unsigned long y, unsigned long z) {
    unsigned long salt = U64(0x5EED5EED12345678) ^ ((unsigned long)stage * U64(0xD1B54A32D192ED03));
    unsigned long out;
    if (memfd_stage2_fn && g.memfd_stage2_ready) {
        out = memfd_stage2_fn(x, y, z, salt);
    } else {
        out = rx_helper_fallback(x, y, z, salt);
        g.memfd_stage2_bad |= U64(0x1001);
    }
    g.memfd_stage2_calls += 1;
    g.memfd_stage2_last_stage = stage;
    g.memfd_stage2_shadow ^= rol64(out ^ x ^ y ^ z ^ salt ^ g.memfd_stage2_calls, ((stage + (unsigned char)(out >> 8)) & 31) + 1);
    return out;
}

void init_memfd_stage2_runtime() {
    int fd;
    unsigned char tmp[128];
    unsigned char memfd_name[32];
    void *page;
    long wr;
    unsigned long init_out;

    decode_blob(memfd_name, enc_memfd_stage2_name_v4, sizeof(enc_memfd_stage2_name_v4), U64(0x1021324354657687));
    fd = (int)sys_memfd_create((const char *)memfd_name, MFD_CLOEXEC);
    burn_stack_bytes(memfd_name, sizeof(memfd_name));
    if (fd < 0) {
        g.memfd_stage2_bad |= U64(0x2001);
        memfd_stage2_fn = 0;
        return;
    }

    for (unsigned long i = 0; i < RX_HELPER_BLOB_LEN; i++) {

        tmp[i] = (unsigned char)(rx_helper_blob_enc[i] ^ RX_HELPER_XOR_KEY);
    }
    for (unsigned long i = RX_HELPER_BLOB_LEN; i < sizeof(tmp); i++) tmp[i] = 0x90;

    g.memfd_stage2_code_hash = rx_helper_hash_bytes(tmp, RX_HELPER_BLOB_LEN);
    if (g.memfd_stage2_code_hash != RX_HELPER_EXPECTED_HASH) {
        g.memfd_stage2_bad |= U64(0x2002);
    }

    wr = sys_write_ret(fd, (const char *)tmp, RX_HELPER_BLOB_LEN);
    if (wr != (long)RX_HELPER_BLOB_LEN) {
        g.memfd_stage2_bad |= U64(0x2003);
        sys_close(fd);
        return;
    }

    sys_lseek(fd, 0, SEEK_SET_ABYSS);
    page = sys_mmap(0, UFFD_PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (!page || page == MAP_FAILED_ABYSS || (long)page < 0) {
        g.memfd_stage2_bad |= U64(0x2004);
        sys_close(fd);
        return;
    }

    memfd_stage2_page = page;
    memfd_stage2_fn = (rx_helper_fn_t)page;
    g.memfd_stage2_ready = 1;
    g.memfd_stage2_fd_tag = ((unsigned long)(unsigned int)fd << 32) ^ g.memfd_stage2_code_hash ^ U64(0xF1D0F1D0F1D0F1D0);
    init_out = memfd_stage2_call(0xE2U, U64(0xCAFEBABE11223344), g.real_state, g.target_key);
    g.memfd_stage2_shadow ^= init_out;

    g.memfd_stage2_target_root = xorshift64(init_out ^ g.memfd_stage2_code_hash ^
                                            rol64(g.memfd_stage2_fd_tag, 17) ^
                                            U64(0x4D454D4644544754));
    g.memfd_stage2_target_root ^= rol64(g.memfd_stage2_shadow + U64(0x5441524745544D46), 11);
    g.memfd_stage2_target_shadow = memfd_stage2_target_expected_shadow();
    g.memfd_stage2_output_key_mix ^= rol64(g.memfd_stage2_target_root ^ init_out ^ g.memfd_stage2_fd_tag, 29);
    g.helper_output_key_mix ^= rol64(g.memfd_stage2_output_key_mix ^ g.memfd_stage2_target_root, 7);
    sys_close(fd);
}

int vm_stage_needs_memfd_stage2(unsigned int stage) {
    return (handler_table_desc_flags(stage) & HTF_MEMFD) != 0;
}

void vm_memfd_stage2_gate(unsigned int stage) {
    unsigned long a, b, c, r, x;
    if (!vm_stage_needs_memfd_stage2(stage)) return;

    a = g.real_state ^ target_delta_guard_word() ^ ((unsigned long)stage * U64(0x9E3779B97F4A7C15));
    b = g.split_shadow[(stage / PHASE_COUNT) % FLAG_LEN] ^ g.heartbeat_target_shadow ^ g.rx_helper_active_mix;
    c = g.uffd_shadow ^ g.td_uffd_shadow ^ g.rx_helper_active_guard ^ g.memfd_stage2_fd_tag;
    r = memfd_stage2_call(stage, a, b, c);

    x = r ^ rol64(a, 5) ^ rol64(b, 17) ^ rol64(c, 43);
    x ^= g.memfd_stage2_code_hash + ((unsigned long)stage * U64(0xA24BAED4963EE407)) + g.memfd_stage2_calls;
    x = xorshift64(x + U64(0x4D454D4644535432) + g.rx_helper_active_mix);
    g.memfd_stage2_active_mix ^= rol64(x, ((stage + (unsigned char)x) & 31) + 1);
    g.memfd_stage2_active_mix = xorshift64(g.memfd_stage2_active_mix + U64(0xD1B54A32D192ED03) + stage);
    g.memfd_stage2_active_seen ^= (U64(1) << (stage & 63));
    g.memfd_stage2_active_guard ^= rol64(g.memfd_stage2_active_mix ^ r ^ g.memfd_stage2_shadow ^ stage, ((stage & 31) + 1));
}

unsigned long memfd_stage2_active_expected_mix() {
    return U64(0xC2638D32FAF5DDDB);
}

unsigned long memfd_stage2_active_expected_guard() {
    return U64(0xFDF12367AEEC97C7);
}

unsigned long memfd_stage2_target_mask(int n) {
    unsigned long root = g.memfd_stage2_target_root;
    unsigned long x;
    if (!root) root = U64(0x4D465F5441524745) ^ g.memfd_stage2_code_hash;
    x = root ^ ((unsigned long)(n + 1) * U64(0xD1B54A32D192ED03));
    x ^= rol64(g.memfd_stage2_code_hash + U64(0x9E3779B97F4A7C15), ((n & 31) + 1));
    x ^= rol64(g.memfd_stage2_fd_tag ^ U64(0x5444474D454D4644), (((n * 7) & 31) + 1));
    for (int r = 0; r < 4; r++) {
        x = xorshift64(x + U64(0xA24BAED4963EE407) +
                       ((unsigned long)(n + 0x100 + r) << (((n + r) & 7) * 8)));
        x ^= rol64(root + (unsigned long)r * U64(0x100000001B3), (((n + r * 9) & 31) + 1));
    }
    return x;
}

unsigned long memfd_stage2_target_expected_shadow() {
    unsigned long x = g.memfd_stage2_target_root ^ U64(0x544152474554524F);
    x ^= rol64(g.memfd_stage2_code_hash ^ g.memfd_stage2_fd_tag, 23);
    x = xorshift64(x + U64(0x4D454D4644544754));
    return x;
}

unsigned long memfd_stage2_target_guard_word() {
    unsigned long bad = 0;
    if (!g.memfd_stage2_target_root) bad |= U64(0x5101);
    if (g.memfd_stage2_target_shadow != memfd_stage2_target_expected_shadow()) bad |= U64(0x5102);
    if (g.memfd_stage2_target_uses != (unsigned long)STAGE_COUNT) bad |= U64(0x5103);
    return bad;
}

unsigned long memfd_stage2_guard_word() {
    unsigned long bad = g.memfd_stage2_bad;
    if (!g.memfd_stage2_ready || !memfd_stage2_fn || !memfd_stage2_page) bad |= U64(0x3001);
    if (g.memfd_stage2_code_hash != RX_HELPER_EXPECTED_HASH) bad |= U64(0x3002);
    if (g.memfd_stage2_calls < 5UL) bad |= U64(0x3003);
    if (g.memfd_stage2_last_stage != (unsigned long)(PHYSICAL_STAGE_COUNT - 1U)) bad |= U64(0x3004);
    if (g.memfd_stage2_active_seen != ((U64(1) << 29) | (U64(1) << 13) | (U64(1) << 10) | (U64(1) << 43))) bad |= U64(0x3005);
    if (g.memfd_stage2_active_mix == U64(0x5A5A5A5AC3C3C3C3)) bad |= U64(0x3006);
    if (g.memfd_stage2_active_guard == U64(0x2468ACE013579BDF)) bad |= U64(0x3007);
    if (g.memfd_stage2_commit_mix == U64(0xC01A17F00DFACE00)) bad |= U64(0x3008);
    if (g.memfd_stage2_commit_mirror !=
        (g.memfd_stage2_commit_mix ^ rol64(g.memfd_stage2_active_seen + U64(0x4D454D464D495252),
                                        ((((FLAG_LEN - 1) + logical_order[FLAG_LEN - 1]) & 31) + 1)))) bad |= U64(0x3009);
    if (memfd_stage2_target_guard_word() != 0) bad |= U64(0x3010);
    return bad;
}

unsigned char memfd_stage2_guard_byte(unsigned int stage) {
    unsigned long w = g.memfd_stage2_bad;
    if (!g.memfd_stage2_ready || !memfd_stage2_fn || !memfd_stage2_page) w |= U64(0x4001);
    if (g.memfd_stage2_code_hash != RX_HELPER_EXPECTED_HASH) w |= U64(0x4002);
    return (unsigned char)((w >> ((stage & 7) * 8)) | (w != 0));
}

void memfd_stage2_commit_sample(unsigned char logical_stage, unsigned char idx, unsigned char c, unsigned long state, unsigned long micro) {
    unsigned long x;
    unsigned long lane;

    lane  = g.memfd_stage2_active_mix;
    lane ^= rol64(g.memfd_stage2_active_guard, ((idx + 5U) & 31) + 1);
    lane ^= rol64(g.memfd_stage2_shadow, ((c + logical_stage + 7U) & 31) + 1);
    lane ^= g.memfd_stage2_fd_tag ^ g.memfd_stage2_code_hash;

    x  = lane ^ micro ^ rol64(state, ((logical_stage + idx) & 31) + 1);
    x ^= ((unsigned long)(c + 0x100U + logical_stage) << (((idx ^ logical_stage) & 7) * 8));
    x ^= rol64(g.memfd_stage2_active_seen ^ (g.memfd_stage2_calls + 0x100UL), ((logical_stage + 3U) & 31) + 1);

    for (unsigned char r = 0; r < 5; r++) {
        x = xorshift64(x + U64(0x4D454D46444D4958) +
                       ((unsigned long)(logical_stage + 1U) * U64(0x100000001B3)) +
                       ((unsigned long)(idx + r + 0x100U) << (((r + c) & 7) * 8)));
        x ^= rol64(lane + r + c, ((r * 7U + logical_stage) & 31) + 1);
    }

    g.memfd_stage2_commit_mix ^= rol64(x, ((logical_stage + idx + 9U) & 31) + 1);
    g.memfd_stage2_commit_mix = xorshift64(g.memfd_stage2_commit_mix + U64(0xC01A17F00DFACE00) + logical_stage);
    g.memfd_stage2_commit_mirror = g.memfd_stage2_commit_mix ^
                                rol64(g.memfd_stage2_active_seen + U64(0x4D454D464D495252),
                                        ((logical_stage + idx) & 31) + 1);
}

unsigned long memfd_stage2_commit_expected_mix() {
    // step16 no longer relies on a build-layout-sensitive absolute constant.
    // The commit lane is checked through mirror/call/seen/hash invariants.
    return g.memfd_stage2_commit_mix;
}


unsigned long process_vm_expected_mailbox(unsigned long epoch, unsigned long mix) {
    unsigned long x = U64(0x50564D5752495445) ^ (epoch * U64(0x9E3779B97F4A7C15));
    x ^= rol64(g.pvm_code_hash ^ g.memfd_stage2_target_root, (int)((epoch & 31UL) + 1UL));
    x ^= rol64(g.heartbeat_cookie ^ U64(0x4348494C44505243), (int)(((mix >> 3) & 31UL) + 1UL));
    x = xorshift64(x + mix + U64(0xD1B54A32D192ED03));
    return x;
}

unsigned long process_vm_expected_mirror(unsigned long mailbox, unsigned long epoch, unsigned long mix) {
    unsigned long x = mailbox ^ rol64(mix ^ g.heartbeat_cookie ^ U64(0x50564D4D49525252), (int)((epoch & 31UL) + 1UL));
    x ^= rol64(g.pvm_code_hash + epoch + U64(0x100000001B3), (int)(((mailbox >> 11) & 31UL) + 1UL));
    return xorshift64(x + U64(0x4153594E43505243));
}

int process_vm_snapshot_valid() {
    unsigned long epoch = g.pvm_epoch;
    unsigned long mix = g.pvm_mix;
    unsigned long mailbox = g.pvm_mailbox;
    if (!epoch || !g.pvm_writes) return 0;
    if (mailbox != process_vm_expected_mailbox(epoch, mix)) return 0;
    if (g.pvm_mirror != process_vm_expected_mirror(mailbox, epoch, mix)) return 0;
    return 1;
}

void process_vm_publish_fallback() {
    unsigned long epoch = 1;
    unsigned long mix = xorshift64(U64(0xFA11BACCE55D00D) ^ g.pvm_code_hash ^ g.memfd_stage2_target_root);
    g.pvm_mailbox = process_vm_expected_mailbox(epoch, mix);
    g.pvm_mirror = process_vm_expected_mirror(g.pvm_mailbox, epoch, mix);
    g.pvm_epoch = epoch;
    g.pvm_mix = mix;
    g.pvm_writes = epoch;
    g.pvm_fallback = 1;
}

void process_vm_child_worker(unsigned long parent_pid) {
    unsigned long packet[5];
    struct iovec_abyss local_iov;
    struct iovec_abyss remote_iov;
    struct timespec_abyss ts;
    unsigned long mix;

    ts.tv_sec = 0;
    ts.tv_nsec = 8000000L;
    sys_nanosleep(&ts);

    mix = xorshift64(U64(0xC001D00D50564D57) ^ g.pvm_code_hash ^ g.memfd_stage2_target_root);
    local_iov.iov_base = packet;
    local_iov.iov_len = sizeof(packet);
    remote_iov.iov_base = (void *)&g.pvm_mailbox;
    remote_iov.iov_len = sizeof(packet);

    for (unsigned long epoch = 1; epoch <= 1; epoch++) {
        mix = xorshift64(mix + epoch * U64(0x9E3779B97F4A7C15) + g.heartbeat_cookie);
        packet[0] = process_vm_expected_mailbox(epoch, mix);
        packet[1] = process_vm_expected_mirror(packet[0], epoch, mix);
        packet[2] = epoch;
        packet[3] = mix;
        packet[4] = epoch;
        for (int tries = 0; tries < 24; tries++) {
            long n = sys_process_vm_writev((long)parent_pid, &local_iov, 1, &remote_iov, 1, 0);
            if (n == (long)sizeof(packet)) break;
            sys_nanosleep(&ts);
        }
        sys_nanosleep(&ts);
    }
    sys_exit(0);
}

unsigned long process_vm_guard_word() {
    unsigned long bad = g.pvm_bad;
    if (g.pvm_code_hash != small_hash_bytes((const unsigned char *)process_vm_child_worker, 320)) bad |= U64(0x6001);
    if (!g.pvm_fallback && !g.pvm_child_pid) bad |= U64(0x6002);
    if (!process_vm_snapshot_valid()) bad |= U64(0x6003);
    if (g.pvm_stage_mix == U64(0x50564D5354414745)) bad |= U64(0x6004);
    return bad;
}

unsigned char process_vm_guard_byte(unsigned int stage) {
    unsigned long w = g.pvm_bad;
    if (g.pvm_code_hash != small_hash_bytes((const unsigned char *)process_vm_child_worker, 320)) w |= U64(0x6401);
    if (!g.pvm_fallback && !g.pvm_child_pid) w |= U64(0x6402);
    if (!process_vm_snapshot_valid()) w |= U64(0x6403);
    return (unsigned char)((w >> ((stage & 7) * 8)) | (w != 0));
}

int vm_stage_needs_process_vm(unsigned int stage) {
    return (handler_table_desc_flags(stage) & HTF_PVM) != 0;
}

void vm_process_vm_gate(unsigned int stage) {
    unsigned long x;
    if (!vm_stage_needs_process_vm(stage)) return;
    if (!process_vm_snapshot_valid()) {
        g.pvm_bad |= U64(0x6101) + stage;
        poison_debug_state(U64(0x61000000) + stage);
        return;
    }
    x  = g.pvm_mailbox ^ rol64(g.pvm_mix, ((stage & 31) + 1));
    x ^= rol64(g.pvm_epoch + g.pvm_writes + U64(0x50564D4741544500), ((stage * 3U) & 31) + 1);
    x ^= g.memfd_stage2_target_root ^ g.heartbeat_cookie;
    g.pvm_stage_mix ^= rol64(xorshift64(x + g.real_state + stage), ((stage + 7U) & 31) + 1);
    g.pvm_stage_mix = xorshift64(g.pvm_stage_mix + U64(0x50564D5354414745) + stage);
}

void watchdog_process_vm_guard() {
    for (;;) {
        if (g.pvm_writes && !process_vm_snapshot_valid()) {
            g.pvm_bad |= U64(0x6201);
            poison_debug_state(U64(0x6201));
        }
        if (g.pvm_code_hash != small_hash_bytes((const unsigned char *)process_vm_child_worker, 320)) {
            g.pvm_bad |= U64(0x6202);
            poison_debug_state(U64(0x6202));
        }
        watchdog_sleep_ms(43);
    }
}

void init_process_vm_child_runtime() {
    long parent_pid;
    long pid;
    struct timespec_abyss ts;

    g.pvm_code_hash = small_hash_bytes((const unsigned char *)process_vm_child_worker, 320);
    g.pvm_stage_mix = U64(0x50564D5354414745);
    parent_pid = sys_getpid();
    pid = sys_clone_process();

    if (pid == 0) {
        process_vm_child_worker((unsigned long)parent_pid);
        sys_exit(0);
    }

    if (pid > 0) {
        g.pvm_child_pid = (unsigned long)pid;
        sys_prctl(PR_SET_PTRACER_ABYSS, (unsigned long)pid, 0, 0, 0);
        ts.tv_sec = 0;
        ts.tv_nsec = 1000000L;
        for (int i = 0; i < 260; i++) {
            if (process_vm_snapshot_valid()) break;
            sys_nanosleep(&ts);
        }
        if (!process_vm_snapshot_valid()) process_vm_publish_fallback();
        spawn_watchdog(watchdog_process_vm_guard, watchdog_stack_8, WATCHDOG_STACK_SIZE);
    } else {
        g.pvm_bad |= U64(0x6301);
        process_vm_publish_fallback();
    }
}

void eventfd_signal_u64(int fd, unsigned long value) {
    if (fd < 0) return;
    if (!value) value = 1;
    sys_write(fd, (const char *)&value, 8);
}

void vm_register_event_node(struct VMEventNode *node) {
    struct epoll_event_abyss ev;
    if (evrt.epfd < 0 || !node || node->fd < 0) return;
    ev.events = EPOLLIN;
    ev.data = (unsigned long)node;
    sys_epoll_ctl(evrt.epfd, EPOLL_CTL_ADD, node->fd, &ev);
}
//tick_fd 由时间触发可读,key_fd / anti_fd 由主动写入触发。epoll 检测到可读后，程序读取并消耗该事件，然后根据事件类型更新 VM 的内部状态，从而驱动后续执行
void init_event_runtime() {
    struct itimerspec_abyss ts;

    evrt.epfd = -1;
    evrt.key_fd = -1;
    evrt.anti_fd = -1;
    evrt.tick_fd = -1;

    evrt.epfd = (int)sys_epoll_create1(0); //事件汇聚点
    evrt.key_fd = (int)sys_eventfd2(0, EFD_NONBLOCK); //KEY 事件通道
    evrt.anti_fd = (int)sys_eventfd2(0, EFD_NONBLOCK); //ANTI 事件通道
    evrt.tick_fd = (int)sys_timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK); //TICK 定时器通道

    evrt.key_node.fd = evrt.key_fd;
    evrt.key_node.kind = VM_EVENT_KEY;
    evrt.key_node.salt = U64(0xA1E7F00D11112222);

    evrt.anti_node.fd = evrt.anti_fd;
    evrt.anti_node.kind = VM_EVENT_ANTI;
    evrt.anti_node.salt = U64(0xBADC0DE22223333);

    evrt.tick_node.fd = evrt.tick_fd;
    evrt.tick_node.kind = VM_EVENT_TICK;
    evrt.tick_node.salt = U64(0x71C7AC1D33334444);

    vm_register_event_node(&evrt.key_node);
    vm_register_event_node(&evrt.anti_node);
    vm_register_event_node(&evrt.tick_node);

    if (evrt.tick_fd >= 0) {
        ts.it_interval.tv_sec = 0;
        ts.it_interval.tv_nsec = 37000000L; //后续每 37ms 触发
        ts.it_value.tv_sec = 0;
        ts.it_value.tv_nsec = 1000000L;//首次 1ms 
        sys_timerfd_settime(evrt.tick_fd, 0, &ts);
    }
    //注入第一拍 KEY 事件（启动脉冲）
    eventfd_signal_u64(evrt.key_fd, 1);
}

__attribute__((noinline)) unsigned long event_algo_expected_mirror(void) {
    unsigned long x;
    x = g.event_algo_key ^ U64(0x4556474154474D52);
    x ^= rol64(g.event_algo_rounds + U64(0xD1B54A32D192ED03),
               (int)(((g.event_algo_key >> 3) & 31UL) + 1UL));
    x ^= rol64(g.event_shadow ^ g.gate_shadow ^ g.event_mask,
               (int)(((g.event_algo_rounds + 7UL) & 31UL) + 1UL));
    return xorshift64(x + U64(0xA24BAED4963EE407));
}

__attribute__((noinline)) void init_eventfd_algorithm_gate(void) {
    static const unsigned long pulses[5] = {
        U64(0x1A2B3C4D5E6F7788),
        U64(0x9E3779B97F4A7C15),
        U64(0xD1B54A32D192ED03),
        U64(0xA24BAED4963EE407),
        U64(0xF1357AEA2E62A9C5),
    };
    int fd;
    unsigned long key;
    unsigned long acc;
    unsigned long v;

    fd = (int)sys_eventfd2(0, 0);
    key = U64(0x4556474154474154);
    acc = U64(0xA11CE5EED5A17E00);
    g.event_algo_ready = 0;
    g.event_algo_rounds = 0;

    if (fd >= 0) {
        for (unsigned int i = 0; i < 5U; i++) {
            unsigned long pulse = pulses[i] ^ rol64(acc + (unsigned long)i * U64(0x100000001B3),
                                                    (int)(((i * 7U + 3U) & 31U) + 1U));
            v = 0;
            eventfd_signal_u64(fd, pulse);
            if (sys_read(fd, (char *)&v, 8) != 8) {
                v = pulse ^ U64(0xBAD0EFD0BAD0EFD0);
            }
            acc = xorshift64(acc ^ v ^ rol64(key, (int)(((i + 11U) & 31U) + 1U)));
            key ^= rol64(v + pulses[(i + 2U) % 5U], (int)(((v >> 3) & 31UL) + 1UL));
            key = xorshift64(key + acc + U64(0x94D049BB133111EB));
            g.event_algo_rounds += 1;
        }
        sys_close(fd);
        g.event_algo_ready = U64(0x4556474154474F4B);
    } else {
        for (unsigned int i = 0; i < 5U; i++) {
            acc = xorshift64(acc ^ pulses[i] ^ key);
            key = xorshift64(key + acc + U64(0x94D049BB133111EB));
            g.event_algo_rounds += 1;
        }
        g.event_algo_ready = U64(0x4556474154474642);
    }

    g.event_algo_key = key ^ rol64(acc, 17) ^ U64(0xC3A5C85C97CB3127);
    g.event_algo_mirror = event_algo_expected_mirror();
    eventfd_signal_u64(evrt.key_fd, (g.event_algo_key & 7UL) + 1UL);
    vm_event_barrier(0xE7U);
    g.event_algo_mirror = event_algo_expected_mirror();
}

unsigned long event_algo_guard_word(void) {
    unsigned long bad = 0;
    if (g.event_algo_rounds != 5UL) bad |= U64(0x6701);
    if (g.event_algo_ready != U64(0x4556474154474F4B)) bad |= U64(0x6702);
    if (!g.event_algo_key) bad |= U64(0x6704);
    if (g.event_algo_mirror != event_algo_expected_mirror()) bad |= U64(0x6708);
    return bad;
}

__attribute__((noinline)) unsigned char eventfd_algorithm_stage_mask(struct StageLocalCtx *ctx,
                                                                     unsigned long micro) {
    unsigned long x;
    x = g.event_algo_key;
    x ^= rol64(g.event_algo_mirror, (int)(((ctx->logical_stage + 3U) & 31U) + 1U));
    x ^= rol64(micro ^ g.event_shadow ^ g.event_mask,
               (int)(((ctx->idx ^ ctx->phase) & 31U) + 1U));
    x ^= ((unsigned long)(ctx->c + 0x100U) << (((ctx->idx + ctx->phase) & 7U) * 8U));
    x = xorshift64(x + U64(0x455647414D534B31) +
                   (unsigned long)ctx->logical_stage * U64(0x9E3779B97F4A7C15));
    return (unsigned char)((x >> ((ctx->idx & 7U) * 8U)) ^ (x >> 37) ^ (ctx->phase * 0x5bU));
}

void vm_signal_anti_event(unsigned long reason) {
    unsigned long v = reason ^ U64(0xA1171A1171A1171);
    eventfd_signal_u64(evrt.anti_fd, v);
}

void vm_event_barrier(unsigned int stage) {
    struct epoll_event_abyss events[4];
    long n;

    if (evrt.epfd < 0) return;

    n = sys_epoll_wait(evrt.epfd, events, 4, 0);
    if (n <= 0) return;

    for (long i = 0; i < n; i++) {
        struct VMEventNode *node = (struct VMEventNode *)events[i].data;
        unsigned long counter = 0;
        unsigned long mix;
        long r;

        if (!node || node->fd < 0) continue;

        r = sys_read(node->fd, (char *)&counter, 8);
        if (r != 8 || counter == 0) counter = 1;

        mix = node->salt ^ counter ^ ((unsigned long)stage * U64(0x9E3779B97F4A7C15));
        mix = xorshift64(mix + g.event_counter + node->kind);

        g.event_counter += counter + node->kind + stage;
        g.event_mask ^= node->kind ^ rol64(counter + stage, (int)((node->kind + stage) & 31) + 1);
        g.event_shadow ^= mix;

        if (node->kind == VM_EVENT_KEY) {
            g.key_epoch += counter;
        } else if (node->kind == VM_EVENT_TICK) {
            g.timer_epoch += counter;
        } else if (node->kind == VM_EVENT_ANTI) {
            g.anti_epoch += counter;
            g.event_mask |= U64(0x8000000000000000);
        }

        g.event_shadow ^= mix;
    }
}

static inline __attribute__((always_inline)) int vm_stage_needs_futex_gate(unsigned int stage) {
    return (handler_table_desc_flags(stage) & HTF_FUTEX) != 0;
}

void vm_gate_publish(unsigned int delta, unsigned long salt) {
    unsigned int next;
    unsigned long mix;

    if (!delta) delta = 1;
    g.gate_epoch += delta;

    mix = xorshift64(g.gate_shadow ^ salt ^ g.gate_epoch ^ g.event_counter);
    g.gate_shadow ^= mix;
    g.gate_shadow ^= mix;

    next = g.futex_word + 1U;
    if (!next) next = 1U;
    g.futex_word = next;
    sys_futex_wake(&g.futex_word, 16);
}

void vm_futex_gate(unsigned int stage) {
    struct timespec_abyss ts;
    unsigned int seen;
    unsigned int start_epoch;
    unsigned long mix;

    if (!vm_stage_needs_futex_gate(stage)) return;

    start_epoch = g.gate_epoch;
    seen = g.futex_word;
    ts.tv_sec = 0;
    ts.tv_nsec = 3000000L;

    for (int i = 0; i < 3 && g.gate_epoch == start_epoch; i++) {
        sys_futex_wait(&g.futex_word, seen, &ts);
        seen = g.futex_word;
    }

    g.gate_waits += 1;
    mix = xorshift64(g.gate_shadow ^ ((unsigned long)stage * U64(0xD1B54A32D192ED03)) ^ g.gate_epoch);

    // Keep step 2 neutral: this proves a synchronization edge exists without
    // changing the final acceptance state yet.
    g.gate_shadow ^= mix;
    g.gate_shadow ^= mix;
}

//根据 signal frame 恢复原来的寄存器状态，继续执行后续的代码
__attribute__((naked)) void abyss_signal_restorer() {
    __asm__ volatile (
        "mov $15, %rax\n\t"
        "syscall\n\t"
    );
}

static inline __attribute__((always_inline)) int vm_stage_needs_sigill_gate(unsigned int stage) {
    return (handler_table_desc_flags(stage) & HTF_SIGILL) != 0;
}

void sigill_opcode_handler(int sig, void *info, void *uctx_void) {
    struct ucontext *ctx = (struct ucontext *)uctx_void;
    unsigned long rip = ctx->uc_mcontext.rip;
    unsigned long stage = g.sigill_stage_hint & 0xffUL;
    unsigned long mix;

    (void)sig;
    (void)info;

    if (!g.sigill_armed) {
        g.fail_acc |= 1UL;
        sys_exit(132);
    }

    g.sigill_count += 1;
    g.sigill_last_rip = rip;

    mix = rip ^ (stage * U64(0x9E3779B97F4A7C15)) ^ g.event_shadow ^ g.gate_shadow;
    mix = xorshift64(mix + g.sigill_count + U64(0x5116110DEC0DE001));

    g.sigill_shadow ^= mix;
    g.sigill_shadow ^= mix;

    ctx->uc_mcontext.rip = rip + 2;
}


static inline __attribute__((always_inline)) int vm_stage_needs_segv_gate(unsigned int stage) {
    return (handler_table_desc_flags(stage) & HTF_SEGV) != 0;
}

void sigsegv_stack_handler(int sig, void *info, void *uctx_void) {
    struct ucontext *ctx = (struct ucontext *)uctx_void;
    unsigned long rip = ctx->uc_mcontext.rip;
    unsigned long rsp = ctx->uc_mcontext.rsp;
    unsigned long fault = ctx->uc_mcontext.cr2;
    unsigned long stage = g.segv_stage_hint & 0xffUL;
    unsigned long mix;

    (void)sig;
    (void)info;

    if (handler_table_try_resolve_fault(fault)) { //懒加载解密
        return;
    }

    if (!g.segv_armed || !g.segv_saved_rsp || !g.segv_recover_rip) {
        g.fail_acc |= 1UL;
        sys_exit(139);
    }

    g.segv_count += 1;
    g.segv_last_rip = rip;
    g.segv_last_rsp = rsp;
    g.segv_fault_addr = fault;

    mix = rip ^ rol64(rsp, 7) ^ rol64(fault, 17);
    mix ^= (stage + 1UL) * U64(0xA24BAED4963EE407);
    mix ^= g.event_shadow ^ g.gate_shadow ^ g.sigill_shadow;
    mix = xorshift64(mix + g.segv_count + U64(0x5E6D5E6D5E6D5E6D));

    g.segv_shadow ^= mix;
    g.segv_shadow ^= mix;

    ctx->uc_mcontext.rsp = g.segv_saved_rsp;
    ctx->uc_mcontext.rip = g.segv_recover_rip;
}
//初始化两种信号
void init_signal_runtime() {
    struct stack_abyss ss;
    struct kernel_sigaction_abyss sa;
    //备用信号栈的内存缓冲区
    ss.ss_sp = sigalt_stack_main;
    ss.ss_flags = 0;
    ss.ss_size = SIGALT_STACK_SIZE;
    sys_sigaltstack(&ss, 0);

    sa.handler = sigill_opcode_handler;
    sa.flags = SA_SIGINFO | SA_ONSTACK | SA_RESTORER; //handler 执行完以后，跳到 sa.restorer 指向的代码
    sa.restorer = abyss_signal_restorer;
    sa.mask = 0;
    sys_rt_sigaction(SIGILL, &sa, 0, 8);

    sa.handler = sigsegv_stack_handler;
    sa.flags = SA_SIGINFO | SA_ONSTACK | SA_RESTORER; 
    sa.restorer = abyss_signal_restorer;
    sa.mask = 0;
    sys_rt_sigaction(SIGSEGV, &sa, 0, 8);
}

void vm_sigill_gate(unsigned int stage) {
    unsigned long mix;

    if (!vm_stage_needs_sigill_gate(stage)) return;

    g.sigill_stage_hint = stage;
    g.sigill_armed = 1;
    __asm__ volatile (".byte 0x0f, 0x0b\n\t" : : : "memory");
    g.sigill_armed = 0;

    mix = xorshift64(g.sigill_last_rip ^ g.sigill_count ^ ((unsigned long)stage * U64(0xD6E8FEB86659FD93)));
    g.sigill_shadow ^= mix;
    g.sigill_shadow ^= mix;
}

void vm_segv_gate(unsigned int stage) {
    unsigned long saved_rsp;
    unsigned long mix;

    if (!vm_stage_needs_segv_gate(stage)) return;

    __asm__ volatile ("mov %%rsp, %0" : "=r"(saved_rsp));
    g.segv_saved_rsp = saved_rsp;
    g.segv_recover_rip = (unsigned long)&&after_fake_stack_fault;
    g.segv_stage_hint = stage;
    g.segv_armed = 1;

    __asm__ volatile (
        "mov $0x40, %%rsp\n\t"
        "mov (%%rsp), %%rax\n\t"
        : : : "rax", "memory"
    );

after_fake_stack_fault:
    g.segv_armed = 0;
    g.segv_saved_rsp = 0;
    g.segv_recover_rip = 0;

    mix = xorshift64(g.segv_last_rip ^ rol64(g.segv_last_rsp, 11) ^
                    rol64(g.segv_fault_addr, 23) ^
                     ((unsigned long)stage * U64(0x94D049BB133111EB)));
    g.segv_shadow ^= mix;
    g.segv_shadow ^= mix;
}


static const unsigned long handler_table_sealed_words[16] = {
    U64(0x6E1A2B3C4D5E6071), U64(0x8A7C6D5E4F302112),
    U64(0x13C0FFEE5A11CE09), U64(0xA55A96965EED1234),
    U64(0xD1CEB00C7711AA55), U64(0xBADC0FFEE0DDF00D),
    U64(0xFACEFEED12345678), U64(0xC001D00D90ABCDEF),
    U64(0x3141592653589793), U64(0x2718281828459045),
    U64(0x9E3779B97F4A7C15), U64(0xBF58476D1CE4E5B9),
    U64(0x94D049BB133111EB), U64(0xD6E8FEB86659FD93),
    U64(0xA24BAED4963EE407), U64(0x1F123BB5A17C0D3D)
};

unsigned long handler_table_mask(unsigned int i) {
    unsigned long x = U64(0x48414E444C455254) ^ g.target_key;
    x ^= (unsigned long)(i + 1U) * U64(0x9E3779B97F4A7C15);
    x ^= rol64(g.memfd_stage2_target_root ^ U64(0x4D454D4644485442), (int)((i & 31U) + 1U));
    x ^= rol64(g.heartbeat_key_mix ^ U64(0x4845415254485442), (int)(((i * 7U) & 31U) + 1U));
    x = xorshift64(x + g.memfd_stage2_code_hash + U64(0xD1B54A32D192ED03));
    x = xorshift64(x ^ rol64(x, (int)(((i * 11U) & 31U) + 1U)));
    return x;
}

unsigned long handler_table_plain_word(unsigned int i) {
    unsigned long e = handler_table_sealed_words[i & 15U];
    unsigned long x = e ^ handler_table_mask(i);
    x ^= (unsigned long)(i + 0x100U) * U64(0x100000001B3);
    x ^= rol64(g.target_key + U64(0xC6BC279692B5CC83), (int)(((i * 5U) & 31U) + 1U));
    x = xorshift64(x + U64(0xA5A5A5A55A5A5A5A));
    return x ^ rol64(e, (int)(((i * 3U) & 31U) + 1U));
}

unsigned long handler_table_expected_shadow() {
    unsigned long x = U64(0x48444C525441424C) ^ g.target_key;
    for (unsigned int i = 0; i < 64U; i += 5U) {
        x ^= handler_table_plain_word(i) + ((unsigned long)i * U64(0x1F123BB5A17C0D3D));
        x = xorshift64(x ^ rol64(x, (int)(((i * 9U) & 31U) + 1U)));
    }
    return xorshift64(x ^ U64(0x7A17EADBEEF0C0DE));
}


unsigned long generated_layout_guard_word() {
    unsigned long x = GHOST_STEP30_LAYOUT_SEED ^ U64(0x47454E4C41594F55);
    for (unsigned int i = 0; i < 4U; i++) {
        x ^= generated_layout_manifest_words[i] + ((unsigned long)(i + 1U) * U64(0x9E3779B97F4A7C15));
        x = xorshift64(x ^ rol64(x, (int)(((i * 7U) & 31U) + 1U)));
    }
    return x ^ xorshift64(GHOST_STEP30_LAYOUT_SEED + U64(0x535445503238));
}

unsigned long handler_table_stage_plain_desc(unsigned int stage) {
    unsigned long f = generated_handler_base_flags[semantic_stage_of(stage)];

    // Step37: stage policy is now keyed by physical stage descriptor.
    // The semantic logical/phase is decoded separately; gate flags follow physical wrappers.
    f |= HTF_PHASE;
    f |= (((unsigned long)(stage + 1U) * U64(0x100000001B3)) & U64(0xff00ff00ff00fc00));
    f |= (rol64(handler_table_plain_word((stage * 5U + 3U) & 63U), (int)(((stage * 7U) & 31U) + 1U)) & U64(0x00ff00ff00ff0000));
    f ^= generated_layout_guard_word() & 0UL;
    return f;
}

unsigned long handler_table_stage_desc_mask(unsigned int stage) {
    unsigned long x = U64(0x48444C5244455343) ^ g.target_key;
    x ^= (unsigned long)(stage + 0x55U) * U64(0xD6E8FEB86659FD93);
    x ^= rol64(g.memfd_stage2_target_root ^ g.heartbeat_target_shadow, (int)(((stage * 3U) & 31U) + 1U));
    x ^= rol64(g.td_uffd_shadow ^ g.uffd_shadow, (int)(((stage * 11U) & 31U) + 1U));
    return xorshift64(x + handler_table_plain_word((stage * 13U + 9U) & 63U));
}

unsigned long handler_table_pack_stage_desc(unsigned int stage) {
    return handler_table_stage_plain_desc(stage) ^ handler_table_stage_desc_mask(stage);
}

unsigned long handler_table_desc_flags(unsigned int stage) {
    unsigned long packed;
    unsigned long plain;
    unsigned int st = (unsigned int)stage;
    if (!handler_table_lazy_words) return 0;
    packed = handler_table_lazy_words[HT_DESC_BASE + st];
    plain = packed ^ handler_table_stage_desc_mask(st);
    return plain & (HTF_META | HTF_FUTEX | HTF_SIGILL | HTF_SEGV | HTF_HEARTBEAT | HTF_RX | HTF_MEMFD | HTF_PVM | HTF_PHASE | HTF_ISLAND);
}

void build_handler_table_page_image(unsigned char *page) {
    clear_page_bytes(page, HANDLER_TABLE_BYTES);
    unsigned long *w = (unsigned long *)page;
    for (unsigned int i = 0; i < 64U; i++) {
        w[i] = handler_table_plain_word(i);
    }
    w[64] = handler_table_expected_shadow();
    w[65] = U64(0x48444C525F475541) ^ g.memfd_stage2_target_root ^ g.heartbeat_key_mix;
    for (unsigned int st = 0; st < PHYSICAL_STAGE_COUNT; st++) {
        w[HT_DESC_BASE + st] = handler_table_pack_stage_desc(st);
    }
}

void handler_table_mark_ready(unsigned long source_tag) {
    g.handler_table_ready = 1;
    g.handler_table_shadow = handler_table_expected_shadow() ^ (source_tag & 0UL);
    if (handler_table_page) {
        g.handler_table_page_hash = small_hash_bytes((const unsigned char *)handler_table_page, (HT_DESC_BASE + PHYSICAL_STAGE_COUNT) * 8UL);
    }
}

int handler_table_try_resolve_fault(unsigned long fault_addr) {
    if (!handler_table_page) return 0;
    unsigned long base = (unsigned long)handler_table_page;
    if (fault_addr < base || fault_addr >= base + HANDLER_TABLE_BYTES) return 0;

    g.handler_table_faults += 1;
    g.handler_table_last_addr = fault_addr;

    if (sys_mprotect(handler_table_page, HANDLER_TABLE_BYTES, PROT_READ | PROT_WRITE) < 0) {
        g.handler_table_bad |= 1UL;
        return 0;
    }
    build_handler_table_page_image(handler_table_page);
    handler_table_mark_ready(U64(0x48444C52504F4E45));
    if (sys_mprotect(handler_table_page, HANDLER_TABLE_BYTES, PROT_READ) < 0) {
        g.handler_table_bad |= 2UL;
        return 0;
    }
    return 1;
}

void materialize_handler_table_direct(void *page) {
    handler_table_page = (unsigned char *)page;
    handler_table_lazy_words = (volatile unsigned long *)page;
    if (sys_mprotect(page, HANDLER_TABLE_BYTES, PROT_READ | PROT_WRITE) >= 0) {
        build_handler_table_page_image((unsigned char *)page);
        handler_table_mark_ready(U64(0x48444C5246414C4C));
        sys_mprotect(page, HANDLER_TABLE_BYTES, PROT_READ);
    } else {
        g.handler_table_bad |= 4UL;
    }
}

void init_handler_table_runtime() {
    void *page = sys_mmap(0, HANDLER_TABLE_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g.handler_table_ready = 0;
    g.handler_table_faults = 0;
    g.handler_table_shadow = U64(0x48444C5253484457);
    g.handler_table_bad = 0;
    g.handler_table_last_addr = 0;
    g.handler_table_reads = 0;
    g.handler_table_stage_mix = U64(0x48444C5253544147);
    g.handler_table_stage_mirror = U64(0x48444C524D495252);
    g.handler_table_page_hash = 0;

    if (!page || page == MAP_FAILED_ABYSS || (long)page < 0) {
        g.handler_table_bad |= 8UL;
        handler_table_page = 0;
        handler_table_lazy_words = 0;
        return;
    }

    materialize_handler_table_direct(page);
}

static inline __attribute__((always_inline)) int vm_stage_needs_handler_table(unsigned int stage) {
    return (handler_table_desc_flags(stage) & HTF_META) != 0;
}

unsigned long handler_table_guard_word() {
    unsigned long x = 0;
    if (!handler_table_lazy_words) x |= 1UL;
    if (!g.handler_table_ready) x |= 2UL;
    if (g.handler_table_faults == 0) x |= 4UL;
    if ((g.handler_table_shadow ^ handler_table_expected_shadow()) != 0) x |= 8UL;
    if (g.handler_table_bad) x |= 16UL;
    if (g.handler_table_stage_mix == U64(0x48444C5253544147)) x |= 64UL;
    if (g.handler_table_stage_mirror != (g.handler_table_stage_mix ^ rol64(g.handler_table_reads + U64(0x48444C524D495252), (int)(((g.handler_table_reads & 31UL) + 1UL))))) x |= 128UL;
    x |= x >> 32;
    x |= x >> 16;
    x |= x >> 8;
    return x & 0xffUL;
}

unsigned char handler_table_guard_byte(unsigned int stage) {
    unsigned long x = handler_table_guard_word();
    x ^= ((unsigned long)stage * U64(0x100000001B3)) & 0UL;
    return (unsigned char)(x & 0xffUL);
}

void vm_handler_table_gate(unsigned int stage, unsigned char logical_stage, unsigned char phase, unsigned char idx, unsigned char c) {
    unsigned int slot;
    unsigned long word;
    unsigned long mix;

    if (!vm_stage_needs_handler_table(stage)) return;
    if (!handler_table_lazy_words) return;

    slot = ((unsigned int)logical_stage * 7U + (unsigned int)phase * 13U + (unsigned int)idx + (unsigned int)c) & 63U;
    word = handler_table_lazy_words[slot];
    g.handler_table_reads += 1;
    mix = word ^ handler_table_desc_flags(stage) ^ ((unsigned long)stage * U64(0x9E3779B97F4A7C15));
    mix ^= rol64((unsigned long)c + ((unsigned long)idx << 8) + ((unsigned long)phase << 16), (int)(((slot + logical_stage) & 31U) + 1U));
    mix ^= g.memfd_stage2_target_root ^ g.pvm_stage_mix ^ g.heartbeat_stage_mix;
    mix = xorshift64(mix + g.handler_table_reads + U64(0x48444C5257414C4B));
    g.handler_table_stage_mix = xorshift64(g.handler_table_stage_mix ^ mix ^ rol64(g.handler_table_stage_mix, (int)(((slot * 3U) & 31U) + 1U)));
    g.handler_table_stage_mirror = g.handler_table_stage_mix ^ rol64(g.handler_table_reads + U64(0x48444C524D495252), (int)(((g.handler_table_reads & 31UL) + 1UL)));
}

unsigned char input_route_mask(unsigned char i) {
    unsigned long x = U64(0xC0FFEE123456789A) ^ ((unsigned long)i * U64(0x9E3779B97F4A7C15));
    x = xorshift64(x + rol64(U64(0xA5A5A5A55A5A5A5A), (i & 31) + 1));
    return (unsigned char)((x >> ((i & 7) * 8)) ^ (unsigned char)(i * 0x6d + 0x3b));
}

unsigned char input_stage_slot_a(unsigned char i) {
    return (unsigned char)((i * 13 + 5) & 63);
}

unsigned char input_stage_slot_b(unsigned char i) {
    return (unsigned char)((i * 7 + 11) & 63);
}

void clear_input_vault() {
    for (int i = 0; i < 128; i++) {
        input_vault.lane_a[i] = 0;
        input_vault.lane_b[i] = 0;
    }
    for (int i = 0; i < 64; i++) {
        input_vault.decoy[i] = 0;
        input_buf[i] = 0;
    }
    input_vault.input_len = 0; 
    input_vault.transit_hash = U64(0xD00DFEED1337C0DE);
}

void prepare_input_nodes() { 
    for (int k = 0; k < FLAG_LEN; k++) {
        unsigned char idx = (unsigned char)((k * 7 + 4) % FLAG_LEN);
        struct InputNode *node = &input_vault.nodes[k];
        node->raw_index = idx;
        node->sink_index = idx;
        node->mask = input_route_mask(idx);
        node->sink = (volatile unsigned char *)(input_buf + idx);
        node->mirror = &input_vault.decoy[(idx * 9 + 1) & 31];
        node->tag = xorshift64(U64(0xBAD0BEEFDEADC0DE) ^ ((unsigned long)idx * U64(0x1F123BB5A17C0D3D)));
        node->next = &input_vault.nodes[(k + 1) % FLAG_LEN];
    }
}

void scatter_raw_input(long nread) {
    unsigned long len = 0;
    int stopped = 0;
    if (nread < 0) nread = 0;

    for (int i = 0; i < 64; i++) {
        unsigned char c = 0;
        if (!stopped && (long)i < nread) {
            c = input_vault.raw[i];
            if (c == 0 || c == '\n' || c == '\r') {
                c = 0;
                stopped = 1;
            } else {
                len++;
            }
        }

        unsigned char m = input_route_mask((unsigned char)i);
        unsigned char a = input_stage_slot_a((unsigned char)i);
        unsigned char b = input_stage_slot_b((unsigned char)i);
        input_vault.lane_a[a] = (unsigned char)(c ^ m);
        input_vault.lane_b[b] = rol8((unsigned char)(c + m + i), ((i ^ m) & 7) + 1);
        input_vault.decoy[(i * 3 + 7) & 31] ^= (unsigned char)(c + 0x5a + i);
        input_vault.transit_hash ^= ((unsigned long)(c + 0x100 + i) << ((i & 7) * 8));
        input_vault.transit_hash = rol64(input_vault.transit_hash + U64(0x9E3779B97F4A7C15), ((c ^ i) & 15) + 3);
    }
    input_vault.input_len = len;
}


unsigned long route_roll_expected_mirror() {
    unsigned long x = g.route_roll_mix ^ U64(0x524F555445524F4C);
    x ^= rol64(g.route_roll_count + U64(0x9E3779B97F4A7C15), 17);
    x ^= rol64(g.route_roll_last ^ g.input_digest, 29);
    x ^= rol64(g.target_key ^ generated_layout_guard_word(), 11);
    return xorshift64(x + U64(0xD1B54A32D192ED03));
}

static inline __attribute__((always_inline)) void route_roll_update(unsigned char idx, unsigned char c, unsigned char diff) {
    unsigned char j0 = (unsigned char)((idx * 7U + 19U + (unsigned char)g.route_roll_count) % FLAG_LEN);
    unsigned char j1 = (unsigned char)((idx + 13U + c + (unsigned char)(g.route_roll_mix >> 8)) % FLAG_LEN);
    unsigned char a0 = input_vault.lane_a[input_stage_slot_a(j0)];
    unsigned char b0 = input_vault.lane_b[input_stage_slot_b(j1)];
    unsigned long x = g.route_roll_mix;
    x ^= ((unsigned long)(idx + 1U) * U64(0xA24BAED4963EE407));
    x ^= ((unsigned long)c << ((idx & 7U) * 8U));
    x ^= ((unsigned long)a0 << (((idx + 3U) & 7U) * 8U));
    x ^= ((unsigned long)b0 << (((idx + 5U) & 7U) * 8U));
    x ^= rol64(g.input_digest ^ g.target_key, ((idx ^ c) & 31U) + 1U);
    x ^= rol64(g.phase_dispatch_shadow ^ g.handler_table_stage_mix, ((idx + diff) & 31U) + 1U);
    x = xorshift64(x + U64(0xC3A5C85C97CB3127) + g.route_roll_count);
    g.route_roll_mix = x;
    g.route_roll_count += 1;
    g.route_roll_last = ((unsigned long)idx << 56) ^ ((unsigned long)c << 48) ^
                        ((unsigned long)j0 << 40) ^ ((unsigned long)j1 << 32) ^
                        ((unsigned long)diff << 24) ^ (x & U64(0xFFFFFF));
    g.route_roll_mirror = route_roll_expected_mirror();
}

unsigned long route_roll_guard_word() {
    unsigned long bad = g.route_roll_bad;
    if (g.route_roll_count < (unsigned long)(FLAG_LEN * PHASE_COUNT)) bad |= U64(0x4001);
    if (g.route_roll_mirror != route_roll_expected_mirror()) bad |= U64(0x4002);
    if (g.route_roll_mix == U64(0x524F5554455F494E)) bad |= U64(0x4004);
    return bad;
}

unsigned char route_roll_guard_byte(unsigned int stage) {
    unsigned long w = route_roll_guard_word();
    return (unsigned char)((w >> ((stage & 7U) * 8U)) | (w != 0));
}

unsigned char recover_routed_char(unsigned char idx) {
    unsigned char m = input_route_mask(idx);
    unsigned char a = input_stage_slot_a(idx);
    unsigned char b = input_stage_slot_b(idx);
    unsigned char c = (unsigned char)(input_vault.lane_a[a] ^ m);
    unsigned char chk = rol8((unsigned char)(c + m + idx), ((idx ^ m) & 7) + 1);
    unsigned char diff = (unsigned char)(chk ^ input_vault.lane_b[b]);

    g.fail_acc |= (unsigned long)diff;
    input_vault.transit_hash ^= ((unsigned long)(diff + 0x100U + idx) << ((idx & 7) * 8));
    route_roll_update(idx, c, diff);
    return c;
}

static inline __attribute__((always_inline)) unsigned char peek_routed_char(unsigned char idx) {
    unsigned char m = input_route_mask(idx);
    unsigned char a = input_stage_slot_a(idx);
    return (unsigned char)(input_vault.lane_a[a] ^ m);
}

static inline __attribute__((always_inline)) unsigned long virtual_lane_expected_mirror(unsigned char lane) {
    unsigned long x = g.virtual_lane_mix[lane];
    x ^= U64(0x564C414E454D4952) + (unsigned long)(lane + 1U) * U64(0xD1B54A32D192ED03);
    x ^= rol64(g.virtual_dispatch_shadow ^ g.virtual_lane_last, (int)(((lane * 7U + 5U) & 31U) + 1U));
    x = xorshift64(x + g.input_digest + ((unsigned long)lane << 40));
    return x ^ rol64(x, (int)(((lane * 11U + 3U) & 31U) + 1U));
}

__attribute__((noinline)) unsigned long virtual_stage_op_mix(unsigned long x,
                                                            unsigned char op,
                                                            unsigned char tap0,
                                                            unsigned char tap1,
                                                            unsigned char tap2,
                                                            unsigned int stage,
                                                            unsigned char logical,
                                                            unsigned char phase,
                                                            unsigned char lane,
                                                            unsigned char sub,
                                                            unsigned long erax,
                                                            unsigned long erbx,
                                                            unsigned long er12,
                                                            unsigned long er13) {
    switch (op & 15U) {
        case 0:
            x ^= rol64(erax + ((unsigned long)tap0 << ((sub & 7U) * 8U)), ((lane + stage) & 31U) + 1U);
            x = x * U64(0xD6E8FEB86659FD93) + U64(0x94D049BB133111EB);
            break;
        case 1:
            x += rol64(erbx ^ ((unsigned long)(tap1 + lane) * U64(0x100000001B3)), ((logical + sub) & 31U) + 1U);
            x ^= x >> 23;
            break;
        case 2:
            x = rol64(x ^ er12 ^ ((unsigned long)(tap2 ^ phase) << (((lane + sub) & 7U) * 8U)), ((tap0 + sub) & 31U) + 1U);
            x += U64(0x9E3779B97F4A7C15) ^ (unsigned long)stage * U64(0x51);
            break;
        case 3:
            x ^= xorshift64(er13 + x + ((unsigned long)tap0 << 17) + lane);
            x = rol64(x, 11) * U64(0xBF58476D1CE4E5B9);
            break;
        case 4:
            x += (erax ^ er13) + ((unsigned long)(tap1 + 0x100U + sub) << ((logical & 7U) * 8U));
            x = xorshift64(x);
            break;
        case 5:
            x ^= rol64(erbx + er12 + (unsigned long)(tap2 * 37U + lane), ((stage ^ lane ^ sub) & 31U) + 1U);
            x += U64(0xA5A5A5A55A5A5A5A);
            break;
        case 6:
            x = (x ^ (x >> 29)) * U64(0x5851F42D4C957F2D) + (unsigned long)(tap0 ^ sub ^ stage);
            break;
        case 7:
            x = rol64(x + erax + erbx + er12 + er13 + tap1 + sub, ((tap2 ^ lane) & 31U) + 1U);
            x ^= U64(0xD1B54A32D192ED03);
            break;
        case 8:
            x ^= rol64(g.rx_helper_target_root ^ g.memfd_stage2_target_root ^ tap2, ((sub * 3U + phase) & 31U) + 1U);
            x = xorshift64(x + U64(0x564D30384C414E45) + lane);
            break;
        case 9:
            x += rol64(g.pvm_mailbox ^ g.pvm_mirror ^ ((unsigned long)tap0 << 32), ((logical * 5U + sub) & 31U) + 1U);
            x ^= U64(0x50564D564C414E45);
            break;
        case 10:
            x ^= handler_table_plain_word((unsigned int)((stage + lane + sub) & 63U));
            x = rol64(x + g.handler_table_shadow + tap1, ((lane * 9U + 7U) & 31U) + 1U);
            break;
        case 11:
            x += heartbeat_target_mask((int)((logical + sub) % STAGE_COUNT));
            x ^= rol64(g.heartbeat_target_shadow ^ tap2, ((stage + sub) & 31U) + 1U);
            break;
        case 12:
            x ^= memfd_stage2_target_mask((int)((stage + lane) % STAGE_COUNT));
            x = xorshift64(x + rol64(g.memfd_stage2_fd_tag ^ tap0, ((phase + 13U) & 31U) + 1U));
            break;
        case 13:
            x = rol64(x ^ g.code_island_shadow ^ RX_HELPER_EXPECTED_HASH, ((tap1 + sub) & 31U) + 1U);
            x += U64(0xC0DE15A11A5ECAFE) ^ ((unsigned long)lane * U64(0x1F123BB5A17C0D3D));
            break;
        case 14:
            x ^= route_projection_runtime_latch ^ route_projection_epoch_gate.mix;
            x = xorshift64(x + ((unsigned long)(tap0 + tap1 + tap2 + 0x100U) << (((lane ^ sub) & 7U) * 8U)));
            break;
        default:
            x += rol64(g.helper_output_key_mix ^ g.memfd_stage2_output_key_mix ^ er13, ((stage + lane + sub) & 31U) + 1U);
            x ^= xorshift64(x ^ U64(0x564C414E45464F47) ^ tap0 ^ ((unsigned long)tap2 << 16));
            break;
    }
    return x;
}

__attribute__((noinline)) unsigned char virtual_stage_sub_count(unsigned int physical_stage) {
    unsigned char x;
    x = (unsigned char)(physical_stage * 7U + (physical_stage >> 2) * 3U + 5U);
    x ^= (unsigned char)((physical_stage * 13U) >> 1);
    return (unsigned char)(60U + (x % 81U));
}

__attribute__((noinline)) unsigned long virtual_stage_expected_count(void) {
    unsigned long n = 0;
    for (unsigned int st = 0; st < PHYSICAL_STAGE_COUNT; st++) {
        n += virtual_stage_sub_count((unsigned char)st);
    }
    return n;
}

__attribute__((noinline)) void virtual_stage_lane_update(unsigned int physical_stage,
                                                        struct StageLocalCtx *ctx,
                                                        unsigned char sub,
                                                        unsigned long erax,
                                                        unsigned long erbx,
                                                        unsigned long er12,
                                                        unsigned long er13) {
    unsigned char lane;
    unsigned char idx;
    unsigned char tap0;
    unsigned char tap1;
    unsigned char tap2;
    unsigned char op;
    unsigned long x;
    unsigned long virt_id;

    lane = (unsigned char)(ctx->phase * VIRTUAL_PHASE_WIDTH + sub);
    idx = ctx->idx;
    tap0 = peek_routed_char((unsigned char)((idx + ctx->logical_stage * 3U + sub * 5U + 7U) % FLAG_LEN));
    tap1 = peek_routed_char((unsigned char)((idx * 5U + ctx->phase * 11U + sub * 13U + 17U) % FLAG_LEN));
    tap2 = peek_routed_char((unsigned char)((ctx->logical_stage * 7U + tap0 + tap1 + sub + 23U) % FLAG_LEN));

    virt_id = (unsigned long)physical_stage * (unsigned long)VIRTUAL_PHASE_WIDTH + (unsigned long)sub;
    x = g.virtual_lane_mix[lane];
    x ^= U64(0x5649525453544147) ^ virt_id * U64(0x9E3779B97F4A7C15);
    x ^= ((unsigned long)(ctx->c + 0x100U + tap0) << (((ctx->phase + sub) & 7U) * 8U));
    x ^= rol64(erax ^ rol64(erbx, 7) ^ rol64(er12, 17) ^ rol64(er13, 29), ((lane + physical_stage) & 31U) + 1U);
    x ^= rol64(g.virtual_dispatch_shadow ^ g.phase_dispatch_shadow, ((ctx->logical_stage + sub) & 31U) + 1U);

    for (unsigned char r = 0; r < 4U; r++) {
        op = (unsigned char)((x >> (((r + sub) & 7U) * 8U)) ^ tap0 ^ tap1 ^ tap2 ^ lane ^ r);
        x = virtual_stage_op_mix(x, op, tap0, tap1, tap2, physical_stage, ctx->logical_stage,
                                 ctx->phase, lane, (unsigned char)(sub + r), erax, erbx, er12, er13);
        x ^= rol64((unsigned long)(peek_routed_char((unsigned char)((idx + sub + r * 9U) % FLAG_LEN)) + 0x100U + r)
                   << (((lane + r) & 7U) * 8U), ((op + r) & 31U) + 1U);
    }

    g.virtual_lane_mix[lane] = xorshift64(x ^ rol64(x, ((sub & 31U) + 1U)));
    g.virtual_dispatch_count += 1;
    g.virtual_lane_last = (virt_id << 40) ^ ((unsigned long)lane << 32) ^
                          ((unsigned long)ctx->logical_stage << 24) ^
                          ((unsigned long)idx << 16) ^ ((unsigned long)tap2 << 8) ^
                          (g.virtual_lane_mix[lane] & 0xffUL);
    g.virtual_dispatch_shadow ^= rol64(g.virtual_lane_mix[lane] ^ g.virtual_lane_last,
                                       (int)(((lane + sub + ctx->logical_stage) & 31U) + 1U));
    g.virtual_lane_mirror[lane] = virtual_lane_expected_mirror(lane);
}

__attribute__((noinline)) void virtual_phase_bundle(unsigned int physical_stage,
                                                    struct StageLocalCtx *ctx,
                                                    unsigned long erax,
                                                    unsigned long erbx,
                                                    unsigned long er12,
                                                    unsigned long er13) {
    unsigned char count = virtual_stage_sub_count(physical_stage);
    for (unsigned char sub = 0; sub < count; sub++) {
        virtual_stage_lane_update(physical_stage, ctx, sub, erax, erbx, er12, er13);
    }
}

unsigned long virtual_lane_guard_word() {
    unsigned long bad = g.virtual_lane_bad;
    if (g.virtual_dispatch_count != virtual_stage_expected_count()) bad |= U64(0x5601);
    if (g.virtual_dispatch_shadow == U64(0x5649525444535048)) bad |= U64(0x5602);
    if (!g.virtual_lane_last) bad |= U64(0x5604);
    for (unsigned char i = 0; i < VIRTUAL_LANE_COUNT; i++) {
        if (!g.virtual_lane_mix[i]) bad |= (U64(0x5700) + i);
        if (g.virtual_lane_mirror[i] != virtual_lane_expected_mirror(i)) bad |= (U64(0x5800) + i);
    }
    return bad;
}

unsigned char virtual_lane_guard_byte(unsigned int stage) {
    unsigned long w = virtual_lane_guard_word();
    return (unsigned char)((w >> ((stage & 7U) * 8U)) | (w != 0));
}

__attribute__((noinline)) unsigned long virtual_lane_runtime_digest(unsigned char logical_stage) {
    unsigned long x;
    unsigned char base;

    base = (unsigned char)((logical_stage * 7U + (unsigned char)g.virtual_dispatch_count) % VIRTUAL_LANE_COUNT);
    x  = U64(0x564C444947455354);
    x ^= ((unsigned long)(logical_stage + 1U) * U64(0xBF58476D1CE4E5B9));
    x ^= rol64(g.virtual_dispatch_shadow ^ g.virtual_lane_last,
               (int)(((logical_stage * 5U + 3U) & 31U) + 1U));

    for (unsigned char r = 0; r < 8U; r++) {
        unsigned char lane = (unsigned char)((base + r * 5U + logical_stage) % VIRTUAL_LANE_COUNT);
        x ^= rol64(g.virtual_lane_mix[lane] + ((unsigned long)lane << 32),
                   (int)(((logical_stage + r * 7U) & 31U) + 1U));
        x += g.virtual_lane_mirror[(unsigned char)((lane + r * 3U + 1U) % VIRTUAL_LANE_COUNT)] ^
             ((unsigned long)(r + 0x100U) * U64(0x100000001B3));
        x = xorshift64(x + U64(0xD1B54A32D192ED03) + g.virtual_dispatch_count);
    }
    return x ^ rol64(x, (int)(((logical_stage ^ (unsigned char)x) & 31U) + 1U));
}

__attribute__((noinline)) unsigned long stage_diff_cookie_memfd_part(struct StageLocalCtx *ctx,
                                                                    unsigned char v,
                                                                    unsigned long micro) {
    unsigned char lane0;
    unsigned char lane1;
    unsigned long x;

    lane0 = (unsigned char)((ctx->phase * VIRTUAL_PHASE_WIDTH + (ctx->idx % VIRTUAL_PHASE_WIDTH)) % VIRTUAL_LANE_COUNT);
    lane1 = (unsigned char)((ctx->logical_stage + ctx->idx + ctx->phase * 7U) % VIRTUAL_LANE_COUNT);

    x  = U64(0x44494646434F4F4B);
    x ^= ((unsigned long)(ctx->logical_stage + 1U) * U64(0x9E3779B97F4A7C15));
    x ^= ((unsigned long)(ctx->idx + 0x100U) << ((ctx->phase & 7U) * 8U));
    x ^= ((unsigned long)(ctx->c + 0x200U + v) << (((ctx->logical_stage ^ ctx->idx) & 7U) * 8U));
    x ^= rol64(micro ^ g.real_state ^ g.final_guard, (int)(((ctx->idx + 5U) & 31U) + 1U));
    x ^= rol64(g.virtual_lane_mix[lane0] ^ g.virtual_lane_mirror[lane1],
               (int)(((ctx->logical_stage + ctx->phase * 3U) & 31U) + 1U));
    x ^= rol64(g.virtual_dispatch_shadow ^ g.virtual_lane_last,
               (int)(((ctx->idx * 7U + ctx->phase) & 31U) + 1U));
    x ^= rol64(g.phase_lane_mix[ctx->phase & (PHASE_COUNT - 1)] ^ g.phase_dispatch_shadow,
               (int)(((ctx->logical_stage * 11U + 9U) & 31U) + 1U));
    x ^= rol64(g.memfd_stage2_target_root ^ g.memfd_stage2_output_key_mix ^ g.memfd_stage2_fd_tag,
               (int)(((ctx->idx * 3U + ctx->phase) & 31U) + 1U));
    x ^= virtual_lane_runtime_digest(ctx->logical_stage);
    return xorshift64(x + U64(0x4D4644434F4F4B31) + micro);
}

__attribute__((noinline)) unsigned long stage_diff_cookie_handler_part(struct StageLocalCtx *ctx,
                                                                      unsigned char v,
                                                                      unsigned long micro,
                                                                      unsigned long seed) {
    unsigned char lane0;
    unsigned char lane1;
    unsigned long x;

    lane0 = (unsigned char)((ctx->phase * VIRTUAL_PHASE_WIDTH + (ctx->idx % VIRTUAL_PHASE_WIDTH)) % VIRTUAL_LANE_COUNT);
    lane1 = (unsigned char)((ctx->logical_stage + ctx->idx + ctx->phase * 7U) % VIRTUAL_LANE_COUNT);
    x = seed ^ U64(0x48444C434F4F4B32);

    for (unsigned char r = 0; r < 5U; r++) {
        unsigned char lane = (unsigned char)((lane0 + r * 7U + ctx->phase) % VIRTUAL_LANE_COUNT);
        x = xorshift64(x + g.virtual_lane_mix[lane] +
                       ((unsigned long)(ctx->c + r + 0x100U) << (((ctx->idx + r) & 7U) * 8U)) +
                       U64(0xD1B54A32D192ED03));
        x ^= rol64(g.virtual_lane_mirror[(unsigned char)((lane1 + r * 5U) % VIRTUAL_LANE_COUNT)] ^ micro,
                   (int)(((ctx->logical_stage + r * 13U) & 31U) + 1U));
        x ^= handler_table_plain_word((unsigned int)((ctx->logical_stage + ctx->idx + r * 11U) & 63U));
    }
    x ^= rol64(stage_ctx_integrity_word(ctx) ^ ctx->ctx_mirror ^ v,
               (int)(((ctx->phase * 5U + ctx->idx) & 31U) + 1U));
    x ^= rol64(g.handler_table_shadow ^ g.handler_table_page_hash ^ g.handler_table_reads,
               (int)(((ctx->logical_stage + 17U) & 31U) + 1U));
    return xorshift64(x + U64(0x48444C46494E414C));
}

__attribute__((noinline)) unsigned long stage_diff_cookie_code_part(struct StageLocalCtx *ctx,
                                                                   unsigned char v,
                                                                   unsigned long micro,
                                                                   unsigned long seed) {
    unsigned long x;
    x = seed ^ U64(0x434F4445434F4F4B);
    x ^= rol64(g.code_island_shadow ^ g.code_island_code_hash ^ g.code_island_wipes,
               (int)(((ctx->idx + 23U) & 31U) + 1U));
    x ^= rol64(g.rx_helper_target_root ^ g.helper_output_key_mix ^ g.rx_helper_shadow,
               (int)(((ctx->logical_stage * 9U + 1U) & 31U) + 1U));
    x ^= rol64(g.pvm_mailbox ^ g.pvm_mirror ^ g.pvm_mix,
               (int)(((ctx->phase + ctx->c) & 31U) + 1U));
    x ^= rol64(runtime_core_stage_mask(ctx->logical_stage), ((ctx->idx & 31U) + 1U));
    x ^= ((unsigned long)(v + 0x100U) << (((ctx->idx ^ ctx->phase) & 7U) * 8U));
    x = xorshift64(x + micro + U64(0xC0DE15A11A5E1234));
    return x | U64(0x0101010101010101);
}

__attribute__((noinline)) unsigned long stage_diff_runtime_cookie(struct StageLocalCtx *ctx,
                                                                 unsigned char v,
                                                                 unsigned long micro) {
    unsigned long a;
    unsigned long b;

    a = stage_diff_cookie_memfd_part(ctx, v, micro);
    b = stage_diff_cookie_handler_part(ctx, v, micro, a);
    return stage_diff_cookie_code_part(ctx, v, micro, b);
}

__attribute__((noinline)) unsigned long stage_diff_scratch_key(struct StageLocalCtx *ctx,
                                                             unsigned char v,
                                                             unsigned long micro) {
    unsigned long x;
    x  = U64(0x5343524154434831);
    x ^= ctx->ctx_key ^ ctx->ctx_mirror;
    x ^= ((unsigned long)(ctx->logical_stage + 1U) * U64(0x9E3779B97F4A7C15));
    x ^= rol64(micro ^ g.virtual_dispatch_shadow ^ g.virtual_lane_last,
               (int)(((ctx->idx + 11U) & 31U) + 1U));
    x ^= rol64(g.phase_dispatch_shadow ^ g.real_state ^ v,
               (int)(((ctx->phase * 7U + ctx->c) & 31U) + 1U));
    return xorshift64(x + U64(0xD1B54A32D192ED03));
}

__attribute__((noinline)) void stage_diff_scratch_store(struct StageLocalCtx *ctx,
                                                       unsigned char v,
                                                       unsigned long micro,
                                                       unsigned long sealed_diff) {
    unsigned char slot;
    unsigned long key;
    unsigned long a;
    unsigned long b;

    slot = (unsigned char)((ctx->logical_stage * 3U + ctx->phase * 5U + ctx->idx) & 7U);
    key = stage_diff_scratch_key(ctx, v, micro);
    a = sealed_diff ^ key ^ rol64(ctx->shard_a, (int)(((slot + ctx->phase) & 31U) + 1U));
    b = rol64(sealed_diff + key + ctx->shard_b, (int)(((ctx->idx + slot) & 31U) + 1U));
    g.diff_scratch_a[slot] = a;
    g.diff_scratch_b[slot ^ 3U] = b;
    g.diff_scratch_seq += 1;
    g.diff_scratch_mirror = xorshift64(g.diff_scratch_mirror ^ a ^ rol64(b, (int)(((slot * 5U) & 31U) + 1U)) ^
                                       ((unsigned long)ctx->logical_stage << 48));
}

__attribute__((noinline)) unsigned long stage_diff_scratch_load(struct StageLocalCtx *ctx,
                                                              unsigned char v,
                                                              unsigned long micro) {
    unsigned char slot;
    unsigned long key;
    unsigned long a;
    unsigned long b;
    unsigned long sealed_a;
    unsigned long sealed_b;

    slot = (unsigned char)((ctx->logical_stage * 3U + ctx->phase * 5U + ctx->idx) & 7U);
    key = stage_diff_scratch_key(ctx, v, micro);
    a = g.diff_scratch_a[slot];
    b = g.diff_scratch_b[slot ^ 3U];
    sealed_a = a ^ key ^ rol64(ctx->shard_a, (int)(((slot + ctx->phase) & 31U) + 1U));
    sealed_b = rol64(b, (int)((64 - (((ctx->idx + slot) & 31U) + 1U)) & 63U)) - key - ctx->shard_b;
    if (sealed_a != sealed_b) {
        g.diff_scratch_mirror ^= U64(0xBADDF00D5EA1ED00) ^ sealed_a ^ sealed_b;
        return sealed_a ^ U64(1);
    }
    return sealed_a;
}


unsigned char recover_projected_char(unsigned char idx, unsigned char logical_stage,
                                    unsigned char phase, unsigned char nonce) {
    unsigned char a = recover_routed_char(idx);
    unsigned char j0 = (unsigned char)((idx + logical_stage * 3U + phase * 5U + nonce + 7U) % FLAG_LEN);
    unsigned char j1 = (unsigned char)((idx * 5U + logical_stage * 11U + nonce * 3U + 13U) % FLAG_LEN);
    unsigned char b = recover_routed_char(j0);
    unsigned char c = recover_routed_char(j1);
    unsigned char j2 = (unsigned char)((idx + b + c + logical_stage + nonce + 19U) % FLAG_LEN);
    unsigned char d = recover_routed_char(j2);

    unsigned long k = U64(0xA17E1234C0DEBEEF);
    k ^= ((unsigned long)(idx + 1U) * U64(0x9E3779B97F4A7C15));
    k ^= rol64(g.input_digest ^ g.target_key, ((idx ^ logical_stage ^ phase) & 31U) + 1U);
    k ^= rol64(g.split_shadow[logical_stage] ^ g.phase_lane_mix[phase & 3U],
            ((nonce + logical_stage) & 31U) + 1U);
    k ^= rol64(g.phase_dispatch_shadow ^ g.phase_lane_mirror[phase & 3U],
               ((idx + nonce * 7U) & 31U) + 1U);
    k ^= rol64(g.route_roll_mix ^ g.route_roll_mirror ^ g.route_roll_last,
            ((idx + logical_stage + nonce) & 31U) + 1U);
    k = xorshift64(k + ((unsigned long)a << 8) + ((unsigned long)b << 16) +
                ((unsigned long)c << 24) + ((unsigned long)d << 32));

    unsigned char r = (unsigned char)(((idx ^ logical_stage ^ phase ^ nonce) & 7U) + 1U);
    unsigned char v = (unsigned char)(a ^ rol8((unsigned char)(b + nonce + logical_stage), r));
    v = (unsigned char)(v + rol8((unsigned char)(c ^ (unsigned char)(k >> 8)), ((phase + nonce) & 7U) + 1U));
    v ^= (unsigned char)(d + (unsigned char)(k >> ((idx & 7U) * 8U)) + (unsigned char)(logical_stage * 0x31U));
    v = rol8(v, ((v ^ nonce ^ idx) & 7U) + 1U);
    return v;
}

void materialize_input_view(long nread) {
    clear_input_vault();
    prepare_input_nodes();
    scatter_raw_input(nread);

    struct InputNode *node = &input_vault.nodes[0];
    for (int k = 0; k < FLAG_LEN; k++) {
        unsigned char idx = node->raw_index;
        unsigned char c = recover_routed_char(idx);

        *(node->sink) = (unsigned char)(c ^ node->mask ^ (unsigned char)node->tag);
        *(node->mirror) ^= (unsigned char)(c ^ node->mask ^ (unsigned char)node->tag);
        input_vault.transit_hash ^= rol64(node->tag ^ c ^ idx, ((idx + k) & 31) + 1);
        node = node->next;
    }

    for (int i = FLAG_LEN; i < 64; i++) {
        input_buf[i] = 0;
    }

    g.dummy_hash ^= (input_vault.transit_hash & 0xffUL);
    g.dummy_hash ^= (input_vault.transit_hash & 0xffUL);
}

void decode_blob(unsigned char *out, const unsigned char *enc, unsigned long len, unsigned long seed) {
    unsigned long k = seed;
    for (unsigned long i = 0; i < len; i++) {
        k = xorshift64(k + U64(0x9E3779B97F4A7C15) + i * 0x51UL);
        out[i] = enc[i] ^ (unsigned char)((k >> ((i & 7) * 8)) ^ (unsigned char)(i * 29 + 0x31));
    }
    out[len] = 0;
}

static inline __attribute__((always_inline)) void burn_stack_bytes(volatile unsigned char *p, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) p[i] = 0;
}

void write_encrypted_blob(int fd, const unsigned char *enc, unsigned long len, unsigned long seed) {
    unsigned char tmp[80];
    if (len >= sizeof(tmp)) return;
    decode_blob(tmp, enc, len, seed);
    sys_write(fd, (const char *)tmp, len);
    burn_stack_bytes(tmp, len + 1);
}

unsigned long uffd_expected_shadow() {
    unsigned long x = U64(0x0FFDF00D1234ABCD) ^ U64(0x7A6B5C4D3E2F1908) ^ g.target_key;
    x ^= sealed_packs_a[0] + rol64(sealed_packs_a[5] ^ U64(0x13579BDF2468ACE0), 11);
    x ^= rol64(sealed_packs_b[1] + U64(0xC6BC279692B5CC83), 19);
    x = xorshift64(x + U64(0x9E3779B97F4A7C15));
    x = xorshift64(x ^ rol64(x, 23) ^ U64(0xD1B54A32D192ED03));
    return x ^ rol64(g.target_key + U64(0xA5A5A5A55A5A5A5A), 7);
}

void uffd_mark_sealed_page_ready(unsigned long source_tag) {
    g.uffd_shadow = uffd_expected_shadow() ^ (source_tag & 0UL);
}

unsigned long uffd_guard_word() {
    unsigned long x = g.uffd_shadow ^ uffd_expected_shadow();
    if (!sealed_lazy_words) x |= 1UL;
    if (!(g.uffd_faults != 0 || g.uffd_fallback == 1)) x |= 2UL;
    x |= x >> 32;
    x |= x >> 16;
    x |= x >> 8;
    return x & 0xffUL;
}

unsigned char uffd_guard_byte(unsigned int stage) {
    unsigned long x = uffd_guard_word();
    x ^= (unsigned long)(stage + 0x100U) & 0UL; 
    return (unsigned char)(x & 0xffUL);
}
void clear_page_bytes(unsigned char *p, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) p[i] = 0;
}

void build_uffd_sealed_page_image(unsigned char *page) {
    clear_page_bytes(page, UFFD_PAGE_SIZE);
    unsigned long *w = (unsigned long *)page;
    for (int i = 0; i < 6; i++) {
        // The UFFD page contains the already-sealed rails, not plaintext targets.
        // Keeping the same rail values preserves the calibrated accepted path.
        w[i] = sealed_packs_a[i];
        w[8 + i] = sealed_packs_b[i];
    }
    w[15] = U64(0x55FFDDAA77112300) ^ g.target_key ^ g.real_state;
}

unsigned long sealed_lazy_pack_a(unsigned char block) {
    if (sealed_lazy_words) return sealed_lazy_words[block];
    return sealed_packs_a[block];
}

unsigned long sealed_lazy_pack_b(unsigned char block) {
    if (sealed_lazy_words) return sealed_lazy_words[8 + block];
    return sealed_packs_b[block];
}

void uffd_sealed_page_worker() {
    struct uffd_msg_abyss msg;
    build_uffd_sealed_page_image(uffd_fill_page);
    build_target_delta_page_image(target_delta_fill_page);

    for (;;) {
        long n = sys_read(sealed_uffd_fd, (char *)&msg, sizeof(msg));
        if (n != (long)sizeof(msg)) {
            struct timespec_abyss ts;
            ts.tv_sec = 0;
            ts.tv_nsec = 1000000L;
            sys_nanosleep(&ts);
            continue;
        }

        if (msg.event == UFFD_EVENT_PAGEFAULT) {
            unsigned long fault_page = msg.arg.pagefault.address & ~(UFFD_PAGE_SIZE - 1UL);
            struct uffdio_copy_abyss copy;

            copy.dst = fault_page;
            copy.len = UFFD_PAGE_SIZE;
            copy.mode = 0;
            copy.copy = 0;

            if (target_delta_lazy_words && fault_page == (unsigned long)target_delta_lazy_words) {
                g.td_uffd_faults += 1;
                g.td_uffd_last_addr = msg.arg.pagefault.address;
                target_delta_mark_page_ready(U64(0xD317ADEC0FFEE00) ^ (g.td_uffd_faults & 0UL));
                copy.src = (unsigned long)target_delta_fill_page;
            } else {
                g.uffd_faults += 1;
                g.uffd_last_addr = msg.arg.pagefault.address;
                uffd_mark_sealed_page_ready(U64(0xC0FFEE00C0FFEE00) ^ (g.uffd_faults & 0UL));
                copy.src = (unsigned long)uffd_fill_page;
            }

            sys_ioctl(sealed_uffd_fd, UFFDIO_COPY_ABYSS, &copy);
        }
    }
}

void materialize_sealed_page_direct(void *page) {
    build_uffd_sealed_page_image((unsigned char *)page);
    sealed_lazy_words = (volatile unsigned long *)page;
    g.uffd_fallback = 1;
    g.uffd_enabled = 0;
    g.uffd_faults = 1;
    g.uffd_last_addr = (unsigned long)page;
    uffd_mark_sealed_page_ready(U64(0xF411BACCF411BACC));
}

unsigned long target_delta_expected_shadow() {
    unsigned long x = U64(0x7D9A7E5A1A2B3C4D) ^ g.target_key;
    x ^= (unsigned long)STAGE_COUNT * U64(0x100000001B3);
    x ^= rol64(raw_stage_delta(0) + U64(0x9E3779B97F4A7C15), 7);
    x ^= rol64(raw_stage_delta(STAGE_COUNT - 1) ^ U64(0xD1B54A32D192ED03), 19);
    x ^= rol64(raw_stage_delta((STAGE_COUNT / 2)) + U64(0xBF58476D1CE4E5B9), 31);
    for (int i = 0; i < STAGE_COUNT; i += 17) {
        x = xorshift64(x ^ raw_stage_delta(i) ^ ((unsigned long)i * U64(0x1F123BB5A17C0D3D)));
    }
    return xorshift64(x ^ rol64(g.target_key + U64(0xA5A5A5A55A5A5A5A), 13));
}

void target_delta_mark_page_ready(unsigned long source_tag) {
    g.td_uffd_shadow = target_delta_expected_shadow() ^ (source_tag & 0UL);
}

unsigned long target_delta_guard_word() {
    unsigned long x = g.td_uffd_shadow ^ target_delta_expected_shadow();
    if (!target_delta_lazy_words) x |= 1UL;
    if (!(g.td_uffd_faults != 0 || g.td_uffd_fallback == 1)) x |= 2UL;
    x |= x >> 32;
    x |= x >> 16;
    x |= x >> 8;
    return x & 0xffUL;
}

unsigned char target_delta_guard_byte(unsigned int stage) {
    unsigned long x = target_delta_guard_word();
    x ^= ((unsigned long)stage << 1) & 0UL;
    return (unsigned char)(x & 0xffUL);
}

void build_target_delta_page_image(unsigned char *page) {
    clear_page_bytes(page, TARGET_DELTA_BYTES);
    unsigned long *w = (unsigned long *)page;
    for (int i = 0; i < STAGE_COUNT; i++) {
        unsigned long d = raw_stage_delta(i);
        unsigned long enc = d ^ g.target_key ^ ((unsigned long)i * U64(0x1F123BB5A17C0D3D));
        w[i] = enc ^ heartbeat_target_mask(i) ^ memfd_stage2_target_mask(i);
    }
    w[STAGE_COUNT + 0] = U64(0xD317ADEC0DEFACE1) ^ g.target_key;
    w[STAGE_COUNT + 1] = target_delta_expected_shadow();
}

void materialize_target_delta_page_direct(void *page) {
    build_target_delta_page_image((unsigned char *)page);
    target_delta_lazy_words = (volatile unsigned long *)page;
    g.td_uffd_fallback = 1;
    g.td_uffd_enabled = 0;
    g.td_uffd_faults = 1;
    g.td_uffd_last_addr = (unsigned long)page;
    target_delta_mark_page_ready(U64(0x7A97DEFACED17A00));
}

void init_userfaultfd_runtime() {
    void *page = sys_mmap(0, UFFD_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *td_page = sys_mmap(0, TARGET_DELTA_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED_ABYSS || (long)page < 0) {
        sealed_lazy_words = 0;
        g.uffd_fallback = 2;
    }
    if (td_page == MAP_FAILED_ABYSS || (long)td_page < 0) {
        target_delta_lazy_words = 0;
        g.td_uffd_fallback = 2;
    }
    if (!page || page == MAP_FAILED_ABYSS || (long)page < 0 || !td_page || td_page == MAP_FAILED_ABYSS || (long)td_page < 0) {
        return;
    }

    long fd = sys_userfaultfd(0);
    if (fd < 0) {
        materialize_sealed_page_direct(page);
        materialize_target_delta_page_direct(td_page);
        return;
    }

    struct uffdio_api_abyss api;
    api.api = UFFD_API_ABYSS;
    api.features = 0;
    api.ioctls = 0;
    if (sys_ioctl((int)fd, UFFDIO_API_ABYSS, &api) < 0) {
        materialize_sealed_page_direct(page);
        materialize_target_delta_page_direct(td_page);
        return;
    }
    //page与userfaulted绑定
    struct uffdio_register_abyss reg;
    reg.range.start = (unsigned long)page;
    reg.range.len = UFFD_PAGE_SIZE;
    reg.mode = UFFDIO_REGISTER_MODE_MISSING;
    reg.ioctls = 0;
    if (sys_ioctl((int)fd, UFFDIO_REGISTER_ABYSS, &reg) < 0) {
        materialize_sealed_page_direct(page);
        materialize_target_delta_page_direct(td_page);
        return;
    }

    materialize_target_delta_page_direct(td_page);

    sealed_uffd_fd = (int)fd;
    sealed_lazy_words = (volatile unsigned long *)page;
    g.uffd_enabled = 1;
    g.uffd_fallback = 0;
    g.uffd_shadow ^= ((unsigned long)page & 0UL) ^ U64(0xAABBCCDD11335577);

    spawn_watchdog(uffd_sealed_page_worker, watchdog_stack_5, WATCHDOG_STACK_SIZE);
}

__attribute__((noinline)) static unsigned long runtime_core_gate_word(unsigned char logical_stage) {
    unsigned long x;
    unsigned long a;
    unsigned long b;
    unsigned long p;
    unsigned long h;
    unsigned long fake_lane;
    unsigned long virt;
    unsigned int st;

    st = (unsigned int)logical_stage;
    a  = heartbeat_target_mask(st);
    a ^= rol64(g.heartbeat_key_mix ^ g.heartbeat_target_shadow,
               (int)(((st * 5U) & 31U) + 1U));

    b  = memfd_stage2_target_mask(st);
    b ^= rol64(g.memfd_stage2_target_root ^ g.memfd_stage2_output_key_mix,
               (int)(((st * 7U + 3U) & 31U) + 1U));

    p  = process_vm_snapshot_valid() ? g.pvm_mailbox : process_vm_expected_mailbox(1, g.pvm_mix);
    p ^= process_vm_snapshot_valid() ? g.pvm_mirror : process_vm_expected_mirror(p, 1, g.pvm_mix);
    p ^= rol64(g.pvm_code_hash ^ g.pvm_mix, (int)(((st * 11U + 5U) & 31U) + 1U));

    h  = handler_table_expected_shadow();
    h ^= handler_table_plain_word((st * 9U + 7U) & 63U);
    h ^= rol64(handler_table_stage_desc_mask(st), (int)(((st * 13U + 9U) & 31U) + 1U));
    virt = virtual_lane_runtime_digest(logical_stage);

    fake_lane  = g.code_island_shadow ^ RX_HELPER_EXPECTED_HASH;
    fake_lane ^= rol64(g.rx_helper_target_root ^ g.helper_output_key_mix,
                       (int)(((st * 3U + 1U) & 31U) + 1U));
    fake_lane ^= rol64(g.code_island_ready ? U64(0xC0DE15A11A5ECAFE) : U64(0x5EEDFACEDEADC0DE),
                       (int)(((st * 17U + 2U) & 31U) + 1U));

    x  = U64(0x47415445434F5245) ^ ((unsigned long)(st + 1U) * U64(0x9E3779B97F4A7C15));
    x ^= rol64(a, (int)(((st + 3U) & 31U) + 1U));
    x ^= rol64(b, (int)(((st + 11U) & 31U) + 1U));
    x ^= rol64(p, (int)(((st + 19U) & 31U) + 1U));
    x ^= rol64(h, (int)(((st + 27U) & 31U) + 1U));
    x ^= rol64(virt, (int)(((st * 29U + 15U) & 31U) + 1U));
    x ^= fake_lane;

    for (unsigned char r = 0; r < 5U; r++) {
        unsigned long lane;
        lane = (r & 1U) ? a : b;
        lane ^= (r & 2U) ? p : h;
        lane ^= rol64(virt, (int)(((r * 11U + logical_stage) & 31U) + 1U));
        lane ^= fake_lane + ((unsigned long)(logical_stage + r + 0x100U) << (((logical_stage + r) & 7U) * 8));
        x = xorshift64(x + lane + U64(0xD1B54A32D192ED03) + (unsigned long)r * U64(0x100000001B3));
        x ^= rol64(lane ^ x, (int)(((logical_stage + r * 7U) & 31U) + 1U));
    }

    return xorshift64(x ^ rol64(a ^ b ^ p ^ h ^ virt, (int)(((st * 23U + 4U) & 31U) + 1U)));
}

unsigned char runtime_core_stage_mask(unsigned char logical_stage) {
    unsigned long x;
    unsigned char m;

    x = runtime_core_gate_word(logical_stage);
    m = (unsigned char)(x >> ((logical_stage & 7U) * 8U));
    m ^= (unsigned char)(x >> 37);
    m ^= (unsigned char)(x >> (((logical_stage * 3U + 5U) & 7U) * 8U));
    m = rol8((unsigned char)(m + logical_stage * 0x3dU + 0x71U),
             (int)(((logical_stage ^ (unsigned char)x) & 7U) + 1U));
    return m;
}

unsigned long sealed_stream_key64(unsigned char i, unsigned char lane) {
    unsigned long s = U64(0x6A09E667F3BCC909);
    s ^= (unsigned long)(i + 1) * U64(0x9E3779B97F4A7C15);
    s ^= (unsigned long)(lane + 0x41) * U64(0xD1B54A32D192ED03);
    s ^= rol64(g.target_key ^ U64(0xA5A5A5A55A5A5A5A), ((i + lane) & 31) + 1);
    s = xorshift64(s + U64(0xBF58476D1CE4E5B9));
    s = xorshift64(s ^ rol64(s, ((i ^ lane) & 31) + 1));
    return s;
}

unsigned char sealed_mix_round(unsigned char v, unsigned char side, unsigned char i, unsigned char r, unsigned long *state) {
    unsigned long x = *state;
    x ^= (unsigned long)(side + 0x100U + r * 17U + i) << ((r & 7) * 8);
    x = xorshift64(x + U64(0x9E3779B97F4A7C15) + (unsigned long)r * U64(0x100000001B3));
    v = rol8((unsigned char)(v + (unsigned char)(x >> (((i + r) & 7) * 8)) + (unsigned char)(side * 13U + r * 29U)),
            ((i + r + side) % 7) + 1);
    v ^= (unsigned char)((x >> (((r ^ i) & 7) * 8)) + (unsigned char)(i * 0x3dU + r * 0x55U));
    *state = x ^ ((unsigned long)v << (((i + r + 3) & 7) * 8));
    return v;
}

__attribute__((noinline)) unsigned long target_vm_expected_mirror(void) {
    unsigned long x;
    x = g.target_vm_shadow ^ U64(0x544752564D495252);
    x ^= rol64(g.target_vm_counter + U64(0xA24BAED4963EE407),
               (int)(((g.target_vm_gate & 31UL) + 1UL)));
    x ^= rol64(g.target_vm_gate ^ g.helper_output_key_mix ^ g.memfd_stage2_target_root,
               (int)((((g.target_vm_counter >> 2) & 31UL) + 1UL)));
    return xorshift64(x + U64(0x9E3779B97F4A7C15));
}

__attribute__((noinline)) void target_vm_noise_round(unsigned char i,
                                                    unsigned char side,
                                                    unsigned char pc,
                                                    unsigned char v,
                                                    unsigned long s) {
    unsigned long z;
    unsigned char tap;
    tap = peek_routed_char((unsigned char)((i * 9U + side * 5U + pc * 3U + (unsigned char)s) % FLAG_LEN));
    z  = g.target_vm_shadow ^ s ^ rol64(g.target_vm_gate, (int)(((pc + i) & 31U) + 1U));
    z ^= ((unsigned long)(tap + 0x100U + v + pc) << (((i ^ pc) & 7U) * 8U));
    z ^= rol64(g.virtual_dispatch_shadow ^ g.forty_round_shadow,
               (int)(((side + pc * 7U) & 31U) + 1U));
    z = xorshift64(z + U64(0x544752564D524E44) + ((unsigned long)pc << 40));
    g.target_vm_shadow = xorshift64(g.target_vm_shadow ^ z ^
                                    rol64(g.target_key ^ g.route_roll_mix,
                                          (int)(((tap + pc) & 31U) + 1U)));
    g.target_vm_counter += 1;
    g.target_vm_gate = xorshift64(g.target_vm_gate + z +
                                  ((unsigned long)(i + 1U) * U64(0x100000001B3)) +
                                  g.target_vm_counter);
    g.target_vm_mirror = target_vm_expected_mirror();
}

__attribute__((noinline)) unsigned long target_vm_guard_word(void) {
    unsigned long bad = 0;
    if (g.target_vm_counter != TARGET_VM_NOISE_COUNT) bad |= U64(0x7101);
    if (g.target_vm_shadow == U64(0x5447525653484457)) bad |= U64(0x7102);
    if (g.target_vm_mirror != target_vm_expected_mirror()) bad |= U64(0x7104);
    if (!g.target_vm_gate) bad |= U64(0x7108);
    return bad;
}

__attribute__((noinline)) unsigned char decode_sealed_target_worker(unsigned char i) {
    unsigned char a = (unsigned char)(sealed_lazy_pack_a((unsigned char)(i >> 3)) >> ((i & 7) * 8));
    unsigned char b = (unsigned char)(sealed_lazy_pack_b((unsigned char)(i >> 3)) >> ((i & 7) * 8));
    unsigned long s = sealed_stream_key64(i, b ^ 0x5a);
    unsigned char v = (unsigned char)(a ^ (unsigned char)s ^ rol8((unsigned char)(b + i * 11U), ((i & 7) + 1)));

    for (unsigned char r = 0; r < TARGET_VM_TOTAL_ROUNDS; r++) {
        if (r < TARGET_VM_REAL_ROUNDS) {
            v = sealed_mix_round(v, b, i, r, &s);
        } else {
            target_vm_noise_round(i, b, r, v, s);
        }
    }
    v ^= (unsigned char)(sealed_stream_key64(i ^ 0xA7U, v ^ b) >> (((i + 3) & 7) * 8));
    v ^= helper_sealed_target_byte(i);
    v ^= runtime_core_stage_mask(i);
    return v;
}

__attribute__((noinline)) unsigned long target_decode_dispatch_expected_mirror(void) {
    unsigned long x;
    x = g.target_decode_dispatch_shadow ^ U64(0x5444444D49525252);
    x ^= rol64(g.target_decode_dispatch_counter + U64(0xD1B54A32D192ED03),
               (int)(((g.target_decode_dispatch_gate & 31UL) + 1UL)));
    x ^= rol64(g.target_decode_dispatch_gate ^ g.target_vm_gate ^ g.diff_dispatch_gate,
               (int)((((g.target_decode_dispatch_counter >> 3) & 31UL) + 1UL)));
    return xorshift64(x + U64(0xA24BAED4963EE407));
}

__attribute__((noinline)) unsigned char decode_sealed_target_decoy_worker(unsigned char i) {
    unsigned char a;
    unsigned char b;
    unsigned char v;
    unsigned char slot;
    unsigned long x;

    a = (unsigned char)(sealed_lazy_pack_b((unsigned char)(i >> 3)) >> ((i & 7) * 8));
    b = (unsigned char)(sealed_lazy_pack_a((unsigned char)((i ^ 0x15U) >> 3)) >> ((i & 7) * 8));
    x = sealed_stream_key64((unsigned char)(i ^ 0x5dU), (unsigned char)(a + b + 0x33U));
    x ^= rol64(g.target_decode_dispatch_gate ^ g.target_key ^ g.route_roll_mirror,
               (int)(((i + a) & 31U) + 1U));
    v = (unsigned char)(a ^ b ^ (unsigned char)x ^ runtime_core_stage_mask((unsigned char)(i ^ 0x31U)));
    v = rol8((unsigned char)(v + i * 0x29U + (unsigned char)(x >> 17)),
             (int)(((i ^ b) & 7U) + 1U));

    slot = (unsigned char)(i & 7U);
    g.target_decode_decoy_scratch[slot] = xorshift64(g.target_decode_decoy_scratch[slot] ^ x ^
                                                     ((unsigned long)v << (((i ^ slot) & 7U) * 8U)));
    return v;
}

__attribute__((noinline)) unsigned long target_decode_dispatch_guard_word(void) {
    unsigned long bad = 0;
    if (g.target_decode_dispatch_counter != TARGET_DECODE_DISPATCH_COUNT) bad |= U64(0x7501);
    if (g.target_decode_dispatch_shadow == U64(0x5444445353484457)) bad |= U64(0x7502);
    if (g.target_decode_dispatch_mirror != target_decode_dispatch_expected_mirror()) bad |= U64(0x7504);
    if (!g.target_decode_dispatch_gate) bad |= U64(0x7508);
    return bad;
}

unsigned char decode_sealed_target(unsigned char i) {
    unsigned char decoy;
    unsigned char real;
    unsigned long salt;

    decoy = decode_sealed_target_decoy_worker(i);
    salt = ((unsigned long)(decoy + 0x100U) << ((i & 7U) * 8U)) ^
           rol64(g.target_decode_dispatch_gate ^ g.target_vm_shadow,
                 (int)(((i * 5U) & 31U) + 1U));
    g.target_decode_dispatch_shadow = xorshift64(g.target_decode_dispatch_shadow ^ salt ^
                                                 g.target_decode_decoy_scratch[i & 7U]);
    g.target_decode_dispatch_counter += 1;
    g.target_decode_dispatch_gate = xorshift64(g.target_decode_dispatch_gate +
                                               g.target_decode_dispatch_shadow +
                                               ((unsigned long)(i + 1U) * U64(0x9E3779B97F4A7C15)) +
                                               g.target_decode_dispatch_counter);
    g.target_decode_dispatch_mirror = target_decode_dispatch_expected_mirror();

    real = decode_sealed_target_worker(i);
    return (unsigned char)(real ^ ((decoy ^ decoy) & 0xffU));
}

void expand_sealed_stream() {
    for (int i = 0; i < FLAG_LEN; i++) {
        unsigned char t = decode_sealed_target((unsigned char)i);
        unsigned char a = (unsigned char)(sealed_lazy_pack_a((unsigned char)(i >> 3)) >> ((i & 7) * 8));
        unsigned char b = (unsigned char)(sealed_lazy_pack_b((unsigned char)(i >> 3)) >> ((i & 7) * 8));
        sealed_cache[i] = (unsigned char)(t ^ a ^ rol8(b, ((i & 7) + 1)) ^ 0xA5);
        g.entropy[(i * 5) & 63] ^= ((unsigned long)t << ((i & 7) * 8));
    }
}

void build_dynamic_ptr_pool() {
    unsigned char perm[FLAG_LEN];
    unsigned long seed = U64(0x51F15EED1234ABCD);

    for (int i = 0; i < FLAG_LEN; i++) perm[i] = (unsigned char)i;

    seed ^= (g.entropy[0] & 0);
    seed ^= (g.step_counter & 0);

    for (int i = FLAG_LEN - 1; i > 0; i--) {
        seed = xorshift64(seed ^ ((unsigned long)i * U64(0x9E3779B97F4A7C15)));
        unsigned long j = seed % (unsigned long)(i + 1);
        unsigned char t = perm[i];
        perm[i] = perm[j];
        perm[j] = t;
        OPAQUE_PREDICATE_NOISE(seed + i + j);
    }

    for (int i = 0; i < FLAG_LEN; i++) {
        logical_order[i] = perm[i];
        ptr_pool[i] = (volatile unsigned char *)(input_buf + ((perm[i] ^ (input_vault.decoy[(i * 5 + 1) & 31] & 0))));
        g.entropy[(i * 3) & 63] ^= ((unsigned long)perm[i] << ((i & 7) * 8));
    }
}

unsigned long make_frame_reg(unsigned int stage, unsigned char lane) {
    unsigned long x = g.real_state ^ g.target_key;
    x ^= (unsigned long)(stage + 1) * U64(0xD1B54A32D192ED03);
    x ^= (unsigned long)(lane + 3) * U64(0x94D049BB133111EB);
    x = rol64(x, ((stage + lane * 11) & 31) + 1);
    x = x * U64(0xBF58476D1CE4E5B9) + U64(0x9E3779B97F4A7C15) + (unsigned long)lane * U64(0x0123456789ABCDEF);
    x ^= x >> 27;
    return x;
}

unsigned long micro_mix_op(unsigned long x, unsigned char op, unsigned char tap, unsigned int stage, unsigned char idx, unsigned char r,
                        unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    switch (op & 7U) {
        case 0:
            x ^= rol64(erax + ((unsigned long)tap << ((r & 7) * 8)), ((stage + r) & 31) + 1);
            x = x * U64(0xD6E8FEB86659FD93) + U64(0x94D049BB133111EB);
            break;
        case 1:
            x += rol64(erbx ^ ((unsigned long)(tap + idx) * U64(0x100000001B3)), ((idx + r) & 31) + 1);
            x ^= x >> 23;
            break;
        case 2:
            x = rol64(x ^ er12 ^ ((unsigned long)(tap ^ stage) << (((idx + r) & 7) * 8)), ((tap + r) & 31) + 1);
            x += U64(0x9E3779B97F4A7C15) ^ (unsigned long)stage * U64(0x51);
            break;
        case 3:
            x ^= xorshift64(er13 + x + ((unsigned long)tap << 17) + r);
            x = rol64(x, 11) * U64(0xBF58476D1CE4E5B9);
            break;
        case 4:
            x += (erax ^ er13) + ((unsigned long)(tap + 0x100U + r) << ((stage & 7) * 8));
            x = xorshift64(x);
            break;
        case 5:
            x ^= rol64(erbx + er12 + (unsigned long)(idx * 37U + tap), ((stage ^ idx ^ r) & 31) + 1);
            x += U64(0xA5A5A5A55A5A5A5A);
            break;
        case 6:
            x = (x ^ (x >> 29)) * U64(0x5851F42D4C957F2D) + (unsigned long)(tap ^ r ^ stage);
            break;
        default:
            x = rol64(x + erax + erbx + er12 + er13 + tap + r, ((tap ^ idx) & 31) + 1);
            x ^= U64(0xD1B54A32D192ED03);
            break;
    }
    return x;
}

unsigned long run_stage_micro_ops(unsigned int stage, unsigned char idx, unsigned char c, unsigned long state,
                                unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    unsigned long x = state ^ rol64(erax, 5) ^ rol64(erbx, 17) ^ rol64(er12, 29) ^ rol64(er13, 41);
    x ^= ((unsigned long)c << ((stage & 7) * 8));
    x += (unsigned long)(idx + 1U) * U64(0x9E3779B97F4A7C15);

    for (unsigned char r = 0; r < 11; r++) {
        unsigned char tap_idx = (unsigned char)((idx + stage * 3U + r * 5U + (unsigned char)x) % FLAG_LEN);
        unsigned char tap = recover_routed_char(tap_idx);
        unsigned char op = (unsigned char)((x >> (((r + stage) & 7) * 8)) ^ tap ^ r ^ stage);
        x = micro_mix_op(x, op, tap, stage, idx, r, erax, erbx, er12, er13);
        x ^= rol64(g.event_shadow ^ g.gate_shadow ^ g.sigill_shadow, ((r + idx) & 31) + 1) & 0UL;
        if (((stage + r) & 7U) == 3U) {
            vm_event_barrier((unsigned char)(stage ^ r ^ 0x40U));
        }
    }
    return x ^ rol64(x, 27) ^ (x >> 19);
}

struct StatefulVMFrame {
    unsigned long x;
    unsigned long regmix;
    unsigned long micro;
    unsigned char c;
    unsigned char idx;
    unsigned int stage;
    unsigned char v;
};

__attribute__((noinline)) unsigned char stateful_vm_decode_op(struct StatefulVMFrame *f,
                                                             unsigned char pc) {
    unsigned char op;
    op = (unsigned char)((f->x >> (((pc + f->stage) & 7U) * 8U)) ^ f->v ^ f->idx);
    op ^= (unsigned char)(g.virtual_lane_last >> (((pc ^ f->idx) & 7U) * 8U));
    op += (unsigned char)(pc * 0x31U + f->stage * 0x17U);
    return (unsigned char)(op & 0x0fU);
}

__attribute__((noinline)) unsigned long forty_round_expected_mirror(void) {
    unsigned long x;
    x = g.forty_round_shadow ^ U64(0x3430524F554E4453);
    x ^= rol64(g.forty_round_counter + U64(0x9E3779B97F4A7C15),
               (int)(((g.forty_round_gate & 31UL) + 1UL)));
    x ^= rol64(g.forty_round_gate ^ U64(0x465254594D495252),
               (int)((((g.forty_round_counter >> 3) & 31UL) + 1UL)));
    return xorshift64(x + U64(0xD1B54A32D192ED03));
}

__attribute__((noinline)) void stateful_vm_noise_round(struct StatefulVMFrame *f,
                                                      unsigned char op,
                                                      unsigned char pc) {
    unsigned long z;
    unsigned char tap_idx;
    unsigned char tap;

    tap_idx = (unsigned char)((f->idx * 11U + f->stage * 7U + pc * 5U +
                              (unsigned char)(f->micro >> ((pc & 7U) * 8U))) % FLAG_LEN);
    tap = peek_routed_char(tap_idx);
    z  = g.forty_round_shadow ^ f->regmix ^ rol64(f->micro, (int)(((pc + op) & 31U) + 1U));
    z ^= ((unsigned long)(tap + 0x100U + pc) << (((pc ^ f->idx) & 7U) * 8U));
    z ^= rol64(g.virtual_dispatch_shadow ^ g.virtual_lane_last,
               (int)(((f->stage + pc * 3U) & 31U) + 1U));
    z = xorshift64(z + U64(0xA24BAED4963EE407) + ((unsigned long)op << 40));
    g.forty_round_shadow = xorshift64(g.forty_round_shadow ^ z ^
                                      rol64(g.forty_round_gate, (int)(((pc + tap) & 31U) + 1U)));
    g.forty_round_counter += 1;
    g.forty_round_gate = xorshift64(g.forty_round_gate + z +
                                    ((unsigned long)(f->stage + 1U) * U64(0x100000001B3)) +
                                    g.forty_round_counter);
    g.forty_round_mirror = forty_round_expected_mirror();

    f->x ^= (z ^ z);
    f->v ^= (unsigned char)((z ^ z) & 0xffU);
}

__attribute__((noinline)) unsigned long forty_round_guard_word(void) {
    unsigned long bad = 0;
    if (g.forty_round_counter != FORTY_ROUND_NOISE_COUNT) bad |= U64(0x4001);
    if (g.forty_round_shadow == U64(0x4652545953484457)) bad |= U64(0x4002);
    if (g.forty_round_mirror != forty_round_expected_mirror()) bad |= U64(0x4004);
    if (!g.forty_round_gate) bad |= U64(0x4008);
    return bad;
}

__attribute__((noinline)) void stateful_vm_semantic_round(struct StatefulVMFrame *f,
                                                         unsigned char r) {
    unsigned char tap_idx = (unsigned char)((f->idx + r * 7U + f->stage * 5U +
                                            (unsigned char)(f->x >> 11)) % FLAG_LEN);
    unsigned char tap = recover_routed_char(tap_idx);
    f->x = xorshift64(f->x + ((unsigned long)(tap + 0x100U + r) << (((r + f->idx) & 7U) * 8U)) +
                      U64(0x9E3779B97F4A7C15) + (unsigned long)f->stage * U64(0x1337));
    f->v = rol8((unsigned char)(f->v + tap + (unsigned char)(f->x >> (((f->stage + r) & 7U) * 8U))),
                ((f->idx + f->stage + r + (unsigned char)f->x) % 7) + 1);
    f->v ^= (unsigned char)((f->x >> (((f->idx ^ r) & 7U) * 8U)) +
                            (unsigned char)(r * 0x2dU + f->stage * 0x31U));
}

__attribute__((noinline)) void stateful_vm_exec_op(struct StatefulVMFrame *f,
                                                  unsigned char op,
                                                  unsigned char pc) {
    unsigned long noise;
    if (pc >= STATEFUL_VM_REAL_ROUNDS) {
        stateful_vm_noise_round(f, op, pc);
        return;
    }

    noise = rol64(f->regmix ^ f->micro ^ ((unsigned long)op << 32),
                  (int)(((pc + op) & 31U) + 1U));
    switch (op & 7U) {
        case 0:
            f->x ^= noise & 0UL;
            stateful_vm_semantic_round(f, pc);
            break;
        case 1:
            f->v ^= (unsigned char)(noise & 0U);
            stateful_vm_semantic_round(f, pc);
            f->x += (noise ^ noise);
            break;
        case 2:
            f->x = rol64(f->x, 1) ^ rol64(f->x, 1) ^ f->x;
            stateful_vm_semantic_round(f, pc);
            break;
        case 3:
            stateful_vm_semantic_round(f, pc);
            f->v = (unsigned char)(f->v + (unsigned char)((noise ^ noise) & 0xffU));
            break;
        case 4:
            f->x ^= (g.diff_scratch_mirror ^ g.diff_scratch_mirror);
            stateful_vm_semantic_round(f, pc);
            break;
        case 5:
            stateful_vm_semantic_round(f, pc);
            f->x ^= (g.dummy_hash ^ g.dummy_hash);
            break;
        case 6:
            f->v ^= (unsigned char)((g.virtual_dispatch_shadow ^ g.virtual_dispatch_shadow) & 0xffU);
            stateful_vm_semantic_round(f, pc);
            break;
        default:
            stateful_vm_semantic_round(f, pc);
            break;
    }
}

unsigned char stateful_transform(unsigned char c, unsigned char idx, unsigned int stage, unsigned long state,
                                unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13,
                                unsigned long micro) {
    struct StatefulVMFrame f;
    f.regmix = erax ^ rol64(erbx, 13) ^ rol64(er12, 29) ^ rol64(er13, 47) ^ micro;
    f.micro = micro;
    f.c = c;
    f.idx = idx;
    f.stage = stage;
    f.x = state ^ f.regmix ^ ((unsigned long)(c + 0x100U + idx) << ((stage & 7) * 8));
    f.v = (unsigned char)(c ^ (unsigned char)f.x ^ (unsigned char)(f.regmix >> 32));

    for (unsigned char pc = 0; pc < STATEFUL_VM_TOTAL_ROUNDS; pc++) {
        unsigned char op = stateful_vm_decode_op(&f, pc);
        stateful_vm_exec_op(&f, op, pc);
    }

    f.v = (unsigned char)(f.v + (unsigned char)(micro >> (((idx ^ stage) & 7) * 8)));
    f.v ^= (unsigned char)((f.regmix * U64(0x45D9F3B) + rol64(micro, 9)) >> 24);
    return f.v;
}

__attribute__((noinline)) unsigned long mix_vm_expected_mirror(void) {
    unsigned long x;
    x = g.mix_vm_shadow ^ U64(0x4D58564D49525252);
    x ^= rol64(g.mix_vm_counter + U64(0xD1B54A32D192ED03),
               (int)(((g.mix_vm_gate & 31UL) + 1UL)));
    x ^= rol64(g.mix_vm_gate ^ g.target_vm_gate ^ g.forty_round_gate,
               (int)((((g.mix_vm_counter >> 4) & 31UL) + 1UL)));
    return xorshift64(x + U64(0xBF58476D1CE4E5B9));
}

__attribute__((noinline)) void mix_vm_noise_round(unsigned char v,
                                                 unsigned char c,
                                                 unsigned char idx,
                                                 unsigned int stage,
                                                 unsigned char pc,
                                                 unsigned long state,
                                                 unsigned long regmix,
                                                 unsigned long micro) {
    unsigned long z;
    unsigned char tap;
    tap = peek_routed_char((unsigned char)((idx + stage * 5U + pc * 7U + (unsigned char)state) % FLAG_LEN));
    z  = g.mix_vm_shadow ^ state ^ rol64(regmix ^ micro, (int)(((pc + idx) & 31U) + 1U));
    z ^= ((unsigned long)(tap + 0x100U + v + c + pc) << (((stage ^ pc) & 7U) * 8U));
    z ^= rol64(g.target_vm_shadow ^ g.forty_round_shadow ^ g.virtual_lane_last,
               (int)(((idx + pc * 11U) & 31U) + 1U));
    z = xorshift64(z + U64(0x4D58564D524E4430) + ((unsigned long)stage << 48));
    g.mix_vm_shadow = xorshift64(g.mix_vm_shadow ^ z ^
                                 rol64(g.mix_vm_gate ^ g.target_vm_gate,
                                       (int)(((tap + pc) & 31U) + 1U)));
    g.mix_vm_counter += 1;
    g.mix_vm_gate = xorshift64(g.mix_vm_gate + z +
                               ((unsigned long)(stage + 1U) * U64(0x9E3779B97F4A7C15)) +
                               g.mix_vm_counter);
    g.mix_vm_mirror = mix_vm_expected_mirror();
}

__attribute__((noinline)) unsigned long mix_vm_guard_word(void) {
    unsigned long bad = 0;
    if (g.mix_vm_counter != MIX_VM_NOISE_COUNT) bad |= U64(0x7201);
    if (g.mix_vm_shadow == U64(0x4D58564D53484457)) bad |= U64(0x7202);
    if (g.mix_vm_mirror != mix_vm_expected_mirror()) bad |= U64(0x7204);
    if (!g.mix_vm_gate) bad |= U64(0x7208);
    return bad;
}

unsigned long mix_state(unsigned long state, unsigned char v, unsigned char c, unsigned char idx, unsigned int stage,
                        unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13, unsigned long micro) {
    unsigned long regmix = erax + rol64(erbx, 7) + (er12 ^ rol64(er13, 19)) + micro;
    state ^= ((unsigned long)(v + 0x100U + c + (regmix & 0xffUL)) << ((idx & 7) * 8));
    for (unsigned char r = 0; r < MIX_VM_TOTAL_ROUNDS; r++) {
        if (r < MIX_VM_REAL_ROUNDS) {
            unsigned char tap = recover_routed_char((unsigned char)((idx + stage + r * 3U) % FLAG_LEN));
            state ^= ((unsigned long)(tap + r + stage + 0x100U) << (((r + stage) & 7) * 8));
            state = rol64(state ^ regmix ^ rol64(micro, ((r + idx) & 31) + 1), ((9 + r * 5) & 31) + 1);
            state = state * U64(0xD6E8FEB86659FD93) + U64(0xA5A5A5A55A5A5A5A) +
                    (unsigned long)stage * U64(0x1337) + idx + ((regmix >> (17 + r)) & 0xffffUL);
            state ^= state >> (23 + (r & 7));
        } else {
            mix_vm_noise_round(v, c, idx, stage, r, state, regmix, micro);
        }
    }
    return state ^ rol64(micro, 31);
}

unsigned long compute_input_digest() {
    unsigned long h = U64(0xD1A5B33F00DFACE1);
    for (int i = 0; i < FLAG_LEN; i++) {
        unsigned char c = recover_routed_char((unsigned char)i);
        unsigned long x = (unsigned long)c + U64(0x100) + (unsigned long)i * U64(0x31);
        h ^= x << ((i & 7) * 8);
        h = rol64(h + U64(0x9E3779B97F4A7C15) + (unsigned long)i * U64(0x1337), ((c ^ i) & 15) + 3);
        h = h * U64(0xBF58476D1CE4E5B9) + U64(0x94D049BB133111EB) + c;
        h ^= h >> 29;
    }
    return h;
}

unsigned long generated_stage_order_guard_word();

unsigned long expected_input_digest_mask() {
    unsigned long m = U64(0x4D41534B494E5055);
    m ^= rol64(generated_layout_guard_word(), 5);
    m ^= rol64(generated_stage_order_guard_word(), 11);
    m ^= rol64(RX_HELPER_EXPECTED_HASH, 17);
    m ^= rol64(GHOST_STEP30_LAYOUT_SEED, 23);
    for (unsigned int i = 0; i < 4U; i++) {
        m ^= rol64(generated_layout_manifest_words[i], (int)(((i * 9U + 3U) & 31U) + 1U));
        m = xorshift64(m + U64(0xD6E8FEB86659FD93) + i);
    }
    return m;
}

unsigned long expected_input_digest() {
    return U64(0xE61D9378A13161C3) ^ expected_input_digest_mask();
}

int fake_check_a() {
    unsigned long s = U64(0xF00DBABE12345678);
    int ok = 1;
    for (int i = 0; i < FLAG_LEN; i++) {
        unsigned char c = recover_routed_char((unsigned char)((i * 5 + 3) % FLAG_LEN));
        unsigned char v = (unsigned char)(((c + i * 13) ^ (s >> ((i & 7) * 8))) + 0x21);
        if (v != fake_expected_a[i]) ok = 0;
        s = rol64(s ^ v ^ i, 5) + U64(0x100000001B3);
    }
    return ok;
}

int fake_check_b() {
    unsigned long s = U64(0x0BADF00DCC55AA99);
    int score = 0;
    for (int i = 0; i < FLAG_LEN; i++) {
        unsigned char c = recover_routed_char((unsigned char)((i * 7 + 1) % FLAG_LEN));
        unsigned char v = rol8((unsigned char)(c ^ i ^ (s >> 40)), (i % 7) + 1);
        score += (v == fake_expected_b[i]);
        s ^= ((unsigned long)v << ((i & 7) * 8));
        s = s * U64(0x5851F42D4C957F2D) + 1;
    }
    return score == FLAG_LEN;
}

#define FAKE_LANE_INIT U64(0xF4A3C0DEC0FFEE39)
#define FAKE_LANE_EXPECTED_COUNT 12UL

static inline __attribute__((always_inline)) unsigned long fake_lane_mirror_of(unsigned long mix, unsigned long count, unsigned long last) {
    unsigned long x = mix ^ rol64(count + U64(0xFA1ECAFE1234ABCD), 17) ^ rol64(last + U64(0xC0FFEEBADF00D123), 29);
    x = xorshift64(x + U64(0x9E3779B97F4A7C15));
    return x ^ rol64(x, 23);
}

static inline __attribute__((always_inline)) unsigned long fake_lane_step(unsigned long mix, unsigned long tag, int a, int b, unsigned long count) {
    unsigned long r = ((unsigned long)(a & 1) * U64(0xA24BAED4963EE407)) ^
                      ((unsigned long)(b & 1) * U64(0xD1B54A32D192ED03));
    r ^= tag * U64(0x9E3779B97F4A7C15);
    r ^= rol64(generated_layout_guard_word(), (int)((tag & 31UL) + 1UL));
    r ^= rol64(generated_stage_order_guard_word(), (int)(((tag >> 5) & 31UL) + 1UL));
    r ^= count * U64(0x100000001B3);
    mix ^= rol64(r + U64(0x46414B4543484B31), (int)(((tag ^ r) & 31UL) + 1UL));
    mix = xorshift64(mix + U64(0xBF58476D1CE4E5B9) + r);
    return mix;
}

void fake_check_lane_update(unsigned int physical_stage, unsigned char logical_stage, int a, int b) {
    unsigned long tag = ((unsigned long)physical_stage << 24) ^ ((unsigned long)logical_stage << 8) ^
                        ((unsigned long)(a & 1) << 1) ^ ((unsigned long)(b & 1) << 2) ^ U64(0x39);
    if (g.fake_lane_mix == 0) {
        g.fake_lane_mix = FAKE_LANE_INIT;
        g.fake_lane_mirror = fake_lane_mirror_of(g.fake_lane_mix, 0, 0);
    }
    if ((a | b) != 0) {
        g.fake_lane_bad |= (tag | U64(1));
    }
    g.fake_lane_count += 1;
    g.fake_lane_mix = fake_lane_step(g.fake_lane_mix, tag, a, b, g.fake_lane_count);
    g.fake_lane_last = tag ^ rol64(g.fake_lane_mix, (int)(((physical_stage + logical_stage) & 31U) + 1U));
    g.fake_lane_mirror = fake_lane_mirror_of(g.fake_lane_mix, g.fake_lane_count, g.fake_lane_last);
    g.dummy_hash ^= (g.fake_lane_mix & 0x7fUL);
}

unsigned long fake_check_guard_word() {
    unsigned long bad = g.fake_lane_bad;
    if (g.fake_lane_count != FAKE_LANE_EXPECTED_COUNT) bad |= U64(0xFA390001);
    if (g.fake_lane_mix == 0 || g.fake_lane_mix == FAKE_LANE_INIT) bad |= U64(0xFA390002);
    if (g.fake_lane_mirror != fake_lane_mirror_of(g.fake_lane_mix, g.fake_lane_count, g.fake_lane_last)) bad |= U64(0xFA390003);
    if (!g.fake_lane_last) bad |= U64(0xFA390004);
    return bad;
}

unsigned char fake_check_guard_byte(unsigned int stage) {
    unsigned long w = fake_check_guard_word();
    return (unsigned char)((w >> ((stage & 7) * 8)) | (w != 0));
}


unsigned long split_stage_probe(unsigned int physical_stage, unsigned char logical_stage, unsigned char phase,
                                unsigned char idx, unsigned char c,
                                unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    unsigned long x = g.split_shadow[logical_stage];
    x ^= ((unsigned long)(physical_stage + 0x100U) << (((phase + logical_stage) & 7) * 8));
    x ^= rol64(erax ^ erbx ^ er12 ^ er13, ((physical_stage + phase) & 31) + 1);
    x += ((unsigned long)c + 0x100UL + idx + phase) * U64(0x9E3779B97F4A7C15);

    for (unsigned char r = 0; r < 5; r++) {
        unsigned char tap_idx = (unsigned char)((idx + logical_stage * 7U + phase * 11U + r * 13U) % FLAG_LEN);
        unsigned char tap = recover_routed_char(tap_idx);
        x = micro_mix_op(x, (unsigned char)(tap ^ phase ^ r ^ physical_stage), tap,
                        logical_stage, idx, (unsigned char)(r + phase), erax, erbx, er12, er13);
        if (((physical_stage + r) & 3U) == 1U) {
            vm_event_barrier((unsigned char)(physical_stage ^ r ^ 0x20U));
        }
    }

    return x ^ rol64(x, 17) ^ (x >> 23);
}

void split_stage_shadow_only(unsigned int physical_stage, unsigned char logical_stage, unsigned char phase,
                            unsigned char idx, unsigned char c,
                            unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    unsigned long x;

    x = split_stage_probe(physical_stage, logical_stage, phase, idx, c, erax, erbx, er12, er13);
    g.split_shadow[logical_stage] ^= x;
    g.split_counter += 1;
    g.split_last = ((unsigned long)physical_stage << 32) ^ ((unsigned long)logical_stage << 16) ^ phase ^ x;

    // Preparation phases are intentionally not final-checking on their own.
    // Their shadow is folded into the commit phase by fold_split_shadow(),
    // which makes these physical stages part of the accepted path.
    g.dummy_hash ^= (x & 0xffUL);
    g.dummy_hash ^= (x & 0xffUL);
}


unsigned long fold_split_shadow(unsigned long shadow, unsigned char logical_stage, unsigned char idx, unsigned char c,
                                unsigned long state,
                                unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    unsigned long x = shadow ^ rol64(state, ((logical_stage + idx) & 31) + 1);
    x ^= ((unsigned long)uffd_guard_byte(logical_stage) << (((idx + logical_stage) & 7) * 8));
    x ^= ((unsigned long)target_delta_guard_byte(logical_stage) << (((idx + logical_stage + 3) & 7) * 8));
    x ^= ((unsigned long)heartbeat_guard_byte(logical_stage) << (((idx + logical_stage + 5) & 7) * 8));
    x ^= ((unsigned long)rx_helper_guard_byte(logical_stage) << (((idx + logical_stage + 6) & 7) * 8));
    x ^= ((unsigned long)handler_table_guard_byte(logical_stage) << (((idx + logical_stage + 7) & 7) * 8));
    x ^= ((unsigned long)(c + 0x100U + logical_stage) << (((idx ^ logical_stage) & 7) * 8));
    x += U64(0xC6BC279692B5CC83) ^ ((unsigned long)(logical_stage + 1U) * U64(0x9E3779B97F4A7C15));

    for (unsigned char r = 0; r < 9; r++) {
        unsigned char tap_idx = (unsigned char)((idx + logical_stage * 9U + r * 17U + (unsigned char)(x >> 5)) % FLAG_LEN);
        unsigned char tap = recover_routed_char(tap_idx);
        unsigned char op = (unsigned char)(tap ^ c ^ logical_stage ^ r ^ (unsigned char)(x >> (((r + idx) & 7) * 8)));
        x = micro_mix_op(x, op, tap, logical_stage, idx, (unsigned char)(r + 0x21U), erax, erbx, er12, er13);
        x ^= rol64(shadow + ((unsigned long)tap << (((r + logical_stage) & 7) * 8)), ((r * 5U + idx) & 31) + 1);
    }

    x ^= rol64(x ^ shadow, ((c + logical_stage) & 31) + 1);
    x = xorshift64(x + U64(0xD1B54A32D192ED03) + (unsigned long)idx * U64(0x100000001B3));
    return x ^ (x >> 29) ^ rol64(shadow, 13);
}



static inline __attribute__((always_inline)) unsigned int semantic_stage_of(unsigned int stage) {
    return stage / STAGE_EXPANSION;
}

static inline __attribute__((always_inline)) unsigned int stage_expansion_lane(unsigned int stage) {
    return stage % STAGE_EXPANSION;
}

static inline __attribute__((always_inline)) unsigned int stage_lane_seed(unsigned int sem) {
    return (unsigned int)((sem * 7U + (sem >> 1U) * 3U + 3U) % STAGE_EXPANSION);
}

static inline __attribute__((always_inline)) unsigned int stage_lane_step(unsigned int sem) {
    static const unsigned char steps[4] = { 1U, 3U, 7U, 9U };
    return (unsigned int)steps[((sem * 5U) ^ (sem >> 2U) ^ 1U) & 3U];
}

static inline __attribute__((always_inline)) unsigned int stage_lane_at_rank(unsigned int sem, unsigned int rank) {
    return (unsigned int)((stage_lane_seed(sem) + rank * stage_lane_step(sem)) % STAGE_EXPANSION);
}

static inline __attribute__((always_inline)) unsigned int stage_lane_rank(unsigned int sem, unsigned int lane) {
    for (unsigned int rank = 0; rank < STAGE_EXPANSION; rank++) {
        if (stage_lane_at_rank(sem, rank) == lane) return rank;
    }
    return STAGE_EXPANSION - 1U;
}

static inline __attribute__((always_inline)) unsigned int stage_group_entry(unsigned int sem) {
    return sem * STAGE_EXPANSION + stage_lane_at_rank(sem, 0U);
}

static inline __attribute__((always_inline)) unsigned int stage_real_lane(unsigned int sem) {
    return stage_lane_at_rank(sem, (unsigned int)((sem * 3U + (sem >> 2U) + 5U) % STAGE_EXPANSION));
}

static inline __attribute__((always_inline)) unsigned long stage_ctx_mask(unsigned int stage) {
    unsigned long st = (unsigned long)stage;
    unsigned long m = U64(0xD15A0000A5A55A5A) ^ ((st + 1UL) * U64(0x9E3779B97F4A7C15));
    m ^= (((st * st + U64(0x1234)) & U64(0xffffffffffffffff)) << 7);
    return m;
}

__attribute__((noinline)) unsigned long decode_stage_ctx_desc(unsigned int stage) {
    unsigned long w;
    unsigned int sem;
    if ((unsigned long)stage >= PHYSICAL_STAGE_COUNT) return U64(0xffffffffffffffff);
    sem = semantic_stage_of(stage);
    if (sem >= SEMANTIC_STAGE_COUNT) return U64(0xffffffffffffffff);
    w = generated_stage_ctx_desc[sem] ^ stage_ctx_mask(sem);

    g.phase_dispatch_shadow ^= rol64(w ^ ((unsigned long)stage * U64(0xA24BAED4963EE407)), ((stage & 31U) + 1U));
    g.phase_dispatch_shadow ^= rol64(w ^ ((unsigned long)stage * U64(0xA24BAED4963EE407)), ((stage & 31U) + 1U));
    return w;
}

static inline __attribute__((always_inline)) unsigned char stage_ctx_logical(unsigned long desc) {
    return (unsigned char)(desc & 0xffU);
}

static inline __attribute__((always_inline)) unsigned char stage_ctx_phase(unsigned long desc) {
    return (unsigned char)((desc >> 8) & 0xffU);
}

static inline __attribute__((always_inline)) unsigned int stage_ctx_tag(unsigned long desc) {
    return (unsigned int)((desc >> 16) & 0xffffU);
}

static inline __attribute__((always_inline)) unsigned int stage_ctx_expected_tag(unsigned int stage, unsigned char logical, unsigned char phase) {
    return (unsigned int)(((unsigned int)logical * 0x31U) ^ ((unsigned int)phase * 0x7dU) ^ ((unsigned int)stage * 0x9bU) ^ 0x5aU) & 0xffffU;
}

static inline __attribute__((always_inline)) unsigned long stage_next_mask(unsigned int stage) {
    unsigned long st = (unsigned long)stage;
    unsigned long m = U64(0x4E455854A5A5C3C3) ^ ((st + 1UL) * U64(0xD1B54A32D192ED03));
    m ^= (((st * 0x9BUL + U64(0x55AA)) & U64(0xffffffffffffffff)) << 9);
    return m;
}

static inline __attribute__((always_inline)) unsigned int stage_next_expected_tag(unsigned int stage, unsigned int next) {
    return (unsigned int)(((unsigned int)next * 0x71U) ^ ((unsigned int)stage * 0xC3U) ^ 0xBEEFU) & 0xffffU;
}

unsigned long generated_stage_order_guard_word() {
    unsigned long h = U64(0x5354474F52445236);
    for (unsigned long i = 0; i < PHYSICAL_STAGE_COUNT; i++) {
        unsigned long sem = i / STAGE_EXPANSION;
        unsigned long rank = i % STAGE_EXPANSION;
        unsigned long lane = stage_lane_at_rank((unsigned int)sem, (unsigned int)rank);
        unsigned long mapped_sem = (unsigned long)generated_stage_order_v2[sem];
        unsigned long mapped_lane = stage_lane_at_rank((unsigned int)mapped_sem, (unsigned int)rank);
        unsigned long actual = sem * STAGE_EXPANSION + lane;
        unsigned long p = mapped_sem * STAGE_EXPANSION + mapped_lane;
        h ^= rol64((p + 1UL) * U64(0x9E3779B97F4A7C15) ^ actual, (int)(((actual ^ p) & 31UL) + 1UL));
        h = xorshift64(h + U64(0xD1B54A32D192ED03) + p + lane);
    }
    return h;
}

__attribute__((noinline)) unsigned int decode_stage_next_index(unsigned int stage) {
    unsigned long w;
    unsigned int sem;
    unsigned int lane;
    unsigned int old_next;
    unsigned int next;
    unsigned int tag;
    if ((unsigned long)stage >= PHYSICAL_STAGE_COUNT) return (unsigned int)(STAGE_COUNT - 1);
    sem = semantic_stage_of(stage);
    lane = stage_expansion_lane(stage);
    if (sem >= SEMANTIC_STAGE_COUNT) return (unsigned int)(STAGE_COUNT - 1);
    if (stage_lane_rank(sem, lane) + 1U < STAGE_EXPANSION) {
        next = sem * STAGE_EXPANSION + stage_lane_at_rank(sem, stage_lane_rank(sem, lane) + 1U);
        tag = stage_next_expected_tag(stage, next);
    } else {
        w = generated_stage_next_desc[sem] ^ stage_next_mask(sem);
        old_next = (unsigned int)(w & 0xffffU);
        tag = (unsigned int)((w >> 16) & 0xffffU);
        if (old_next > SEMANTIC_STAGE_COUNT || tag != stage_next_expected_tag(sem, old_next)) {
            g.fail_acc |= 1UL;
            return (unsigned int)(STAGE_COUNT - 1);
        }
        next = (old_next == SEMANTIC_STAGE_COUNT) ? (unsigned int)(STAGE_COUNT - 1) : stage_group_entry(old_next);
    }
    g.phase_dispatch_shadow ^= rol64(((unsigned long)next << 32) ^ tag ^ ((unsigned long)stage * U64(0x4E45585453524F50)), ((stage & 31U) + 1U));
    g.phase_dispatch_shadow ^= rol64(((unsigned long)next << 32) ^ tag ^ ((unsigned long)stage * U64(0x4E45585453524F50)), ((stage & 31U) + 1U));
    return next;
}

__attribute__((noinline)) void srop_jump_from_stage(unsigned int stage) {
    unsigned int next = decode_stage_next_index(stage);
    unsigned long target = decode_target((int)next);
    srop_jump_seeded(target, next);
}

#define xchar_packs_v1 generated_xchar_packs_v1

// step31: 32-bit runtime-bound cross-character target lane.
// Two 32-bit encrypted targets are packed into each 64-bit word.
static const unsigned long xchar32_packs_v1[(FLAG_LEN + 1) / 2] = {
    U64(0xF282797EB1282B5E), U64(0x0B7F8F908C69FF8D), U64(0x57847D7AAB9C7D69), U64(0x5DA36265B57E25BA),
    U64(0x90E31FA951BD8B8F), U64(0xAC189792C6A3E2E7), U64(0x5A245210CB259053), U64(0x6C81CA06E2350E50),
    U64(0x5F44219A5BB8E510), U64(0xE79A04C86BC14786), U64(0x11C23C61D0027936), U64(0x2085A0629EA7A89F),
    U64(0x6D3AA7D5CCE2EC6C), U64(0x680A7D78DD82B4FF), U64(0x84D53EC52DDD1C87), U64(0x6265027DAE7CA061),
    U64(0x80696D12410572A1), U64(0xE5A65BA2671A96AA), U64(0x113374842C50291D), U64(0xBF84C1B90559A232),
    U64(0xB56A638D836B5065), U64(0x0000000087BDAA9B)
};

unsigned char xchar_target_key(unsigned int stage) {
    unsigned long s = U64(0xD00DCAFE5EEDFACE) ^ ((unsigned long)(stage + 1U) * U64(0xA24BAED4963EE407));
    s = xorshift64(s + rol64(U64(0x9E3779B97F4A7C15) ^ ((unsigned long)stage * U64(0x1F123BB5A17C0D3D)),
                        (int)((stage & 31U) + 1U)));
    return (unsigned char)((s >> ((stage & 7U) * 8U)) ^ (unsigned char)(stage * 0x6dU + 0x41U) ^ (unsigned char)(s >> 37));
}

unsigned char decode_xchar_target(unsigned int stage) {
    unsigned char enc = (unsigned char)(xchar_packs_v1[stage >> 3] >> ((stage & 7U) * 8U));
    return (unsigned char)(enc ^ xchar_target_key(stage));
}

unsigned int xchar32_target_key(unsigned int stage) {
    unsigned long s = U64(0x31F0C0DEC0FFEE31) ^ ((unsigned long)(stage + 3U) * U64(0xD6E8FEB86659FD93));
    s ^= rol64(U64(0xA24BAED4963EE407) ^ ((unsigned long)stage * U64(0x1F123BB5A17C0D3D)),
               (int)(((stage * 7U + 11U) & 31U) + 1U));
    s = xorshift64(s + U64(0x9E3779B97F4A7C15) + (unsigned long)stage * U64(0x100000001B3));
    s ^= rol64(s ^ U64(0x94D049BB133111EB), (int)(((stage ^ 0x1dU) & 31U) + 1U));
    return (unsigned int)(s ^ (s >> 32) ^ rol64(s, 17));
}

unsigned int decode_xchar_target32(unsigned int stage) {
    unsigned long pack = xchar32_packs_v1[stage >> 1];
    unsigned int enc = (unsigned int)(pack >> ((stage & 1U) * 32U));
    return enc ^ xchar32_target_key(stage);
}

unsigned int cross_char_actual32(struct StageLocalCtx *ctx, unsigned char v, unsigned long micro) {
    unsigned char logical_stage = ctx->logical_stage;
    unsigned char phase = ctx->phase;
    unsigned char idx = ctx->idx;
    unsigned char c = recover_projected_char(ctx->idx, logical_stage, phase, 0x41U);
    unsigned char t0 = recover_projected_char((unsigned char)((idx + logical_stage * 5U + 7U) % FLAG_LEN), logical_stage, phase, 0x52U);
    unsigned char t1 = recover_projected_char((unsigned char)((logical_stage * 11U + idx * 3U + 5U) % FLAG_LEN), logical_stage, phase, 0x63U);
    unsigned char t2 = recover_projected_char((unsigned char)((idx * 7U + logical_stage * 13U + 19U) % FLAG_LEN), logical_stage, phase, 0x74U);
    unsigned char t3 = recover_projected_char((unsigned char)((idx ^ (unsigned char)(logical_stage * 9U + 23U)) % FLAG_LEN), logical_stage, phase, 0x85U);
    unsigned char t4 = recover_projected_char((unsigned char)((idx + t0 + phase * 11U + 3U) % FLAG_LEN), logical_stage, phase, 0x96U);
    unsigned char t5 = recover_projected_char((unsigned char)((logical_stage + t2 + (unsigned char)(v * 3U) + 17U) % FLAG_LEN), logical_stage, phase, 0xA7U);

    unsigned long x = U64(0x58434841524C494E) ^ ((unsigned long)(logical_stage + 1U) * U64(0x9E3779B97F4A7C15));
    x ^= ((unsigned long)(c + 0x100U + idx) << ((logical_stage & 7U) * 8U));

    x ^= rol64(micro ^ g.split_shadow[logical_stage], ((logical_stage + idx) & 31U) + 1U);
    x ^= rol64(g.phase_lane_mix[phase & 3U] ^ ((unsigned long)v << (((idx ^ logical_stage) & 7U) * 8U)),
               ((phase * 7U + logical_stage) & 31U) + 1U);
    x ^= rol64(g.real_state ^ g.input_digest ^ g.target_key,
            ((idx + 13U) & 31U) + 1U);
    x ^= rol64(g.phase_dispatch_shadow ^ g.phase_lane_mirror[phase & 3U],
               ((idx * 5U + logical_stage) & 31U) + 1U);

    unsigned char taps[6];
    taps[0] = t0; taps[1] = t1; taps[2] = t2; taps[3] = t3; taps[4] = t4; taps[5] = t5;
    for (unsigned char r = 0; r < 6; r++) {
        unsigned char tap = taps[r];
        x ^= ((unsigned long)(tap + 0x100U + r * 0x31U + logical_stage) << (((idx + r) & 7U) * 8U));
        x = rol64(x + U64(0xD6E8FEB86659FD93) + (unsigned long)tap * (unsigned long)(r + 3U) + idx + micro,
                  ((tap ^ idx ^ logical_stage ^ (unsigned char)(r * 5U) ^ v) & 31U) + 1U);
        x ^= x >> (13U + (r & 7U));
        x = x * U64(0xBF58476D1CE4E5B9) + U64(0x94D049BB133111EB) + (unsigned long)(c ^ tap ^ r ^ v);
    }

    x ^= rol64(x ^ micro ^ g.real_state, 23);
    x = xorshift64(x + U64(0xC3A5C85C97CB3127) + ((unsigned long)logical_stage << 32) + idx);
    return (unsigned int)(x ^ (x >> 32) ^ rol64(x, 9) ^ rol64(x, 37));
}

unsigned char cross_char_actual(struct StageLocalCtx *ctx, unsigned char v, unsigned long micro) {
    unsigned int z = cross_char_actual32(ctx, v, micro);
    return (unsigned char)(z ^ (z >> 8) ^ (z >> 16) ^ (z >> 24));
}

static inline __attribute__((always_inline)) unsigned long xchar_expected_mirror() {
    unsigned long x = g.xchar_mix ^ U64(0x58434841524D4952) ^ (g.xchar_count * U64(0x9E3779B97F4A7C15));
    x = rol64(x ^ g.xchar_last ^ g.input_digest, (int)(((g.xchar_count + 11UL) & 31UL) + 1UL));
    return x ^ (x >> 27);
}

unsigned long xchar_guard_word() {
    unsigned long bad = 0;
    if (g.xchar_count != FLAG_LEN) bad |= 1;
    if (!g.xchar_mix) bad |= 2;
    if (g.xchar_mirror != xchar_expected_mirror()) bad |= 4;
    return bad;
}

unsigned char xchar_guard_byte(unsigned int stage) {
    unsigned long w = xchar_guard_word();
    return (unsigned char)((w >> ((stage & 7U) * 8U)) & 0xffU);
}

__attribute__((noinline)) unsigned long cross_char_diff_worker(struct StageLocalCtx *ctx,
                                                            unsigned char v,
                                                            unsigned long micro) {
    unsigned int actual32 = cross_char_actual32(ctx, v, micro);
    unsigned int target32 = decode_xchar_target32(ctx->logical_stage);
    unsigned int diff32 = actual32 ^ target32;
    unsigned char actual8 = (unsigned char)(actual32 ^ (actual32 >> 8) ^ (actual32 >> 16) ^ (actual32 >> 24));
    unsigned char target8 = decode_xchar_target(ctx->logical_stage);

    unsigned long x = g.xchar_mix;
    x ^= ((unsigned long)(actual32 + U64(0x100000000) + target32) << ((ctx->logical_stage & 1U) * 32U));
    x ^= ((unsigned long)(actual8 + 0x100U + target8) << ((ctx->logical_stage & 7U) * 8U));
    x ^= rol64(micro ^ g.split_shadow[ctx->logical_stage] ^ g.phase_lane_mix[ctx->phase & 3U],
            ((ctx->idx + ctx->logical_stage) & 31U) + 1U);
    x ^= rol64(g.handler_table_stage_mix ^ g.memfd_stage2_commit_mix ^ g.rx_helper_active_mix,
            ((ctx->idx ^ ctx->logical_stage ^ ctx->phase) & 31U) + 1U);
    x = xorshift64(x + U64(0xC3A5C85C97CB3127) + (unsigned long)ctx->idx * U64(0x100000001B3));
    g.xchar_mix = x;
    g.xchar_count += 1;
    g.xchar_last = ((unsigned long)ctx->logical_stage << 56) ^ ((unsigned long)ctx->idx << 48) ^
                ((unsigned long)actual32 << 16) ^ target32 ^ rol64(x, 7);
    g.xchar_mirror = xchar_expected_mirror();
    return 0;
}

__attribute__((noinline)) int stage_load_local_ctx(unsigned int stage, struct StageLocalCtx *ctx) {
    volatile unsigned char *p;
    unsigned long desc = decode_stage_ctx_desc(stage);
    unsigned int tag;

    ctx->logical_stage = stage_ctx_logical(desc);
    ctx->phase = stage_ctx_phase(desc);
    tag = stage_ctx_tag(desc);
    if (ctx->logical_stage >= FLAG_LEN) return 0;
    if (ctx->phase >= PHASE_COUNT) return 0;
    if (tag != stage_ctx_expected_tag(semantic_stage_of(stage), ctx->logical_stage, ctx->phase)) {
        g.fail_acc |= (unsigned long)((tag ^ stage_ctx_expected_tag(semantic_stage_of(stage), ctx->logical_stage, ctx->phase)) & 1U);
        return 0;
    }

    p = ptr_pool[ctx->logical_stage];
    ctx->idx = logical_order[ctx->logical_stage];
    ctx->c = recover_routed_char(ctx->idx);
    stage_ctx_seal(ctx, stage);

    g.dummy_hash ^= ((unsigned long)(*p) & 0UL);
    return 1;
}

__attribute__((noinline)) void stage_runtime_gates(unsigned int stage) {
    vm_event_barrier(stage);
    vm_futex_gate(stage);
    vm_sigill_gate(stage);
    vm_segv_gate(stage);
    vm_heartbeat_gate(stage);
    vm_rx_helper_gate(stage);
    vm_memfd_stage2_gate(stage);
    vm_code_island_gate(stage);
    vm_process_vm_gate(stage);
}

__attribute__((noinline)) void stage_metadata_gate(unsigned int stage, struct StageLocalCtx *ctx) {
    vm_handler_table_gate(stage, ctx->logical_stage, ctx->phase, ctx->idx, ctx->c);
}

static inline __attribute__((always_inline)) unsigned long phase_lane_expected_mirror(unsigned char phase) {
    unsigned long x = g.phase_lane_mix[phase];
    x ^= U64(0x50484153454C4E45) + (unsigned long)(phase + 1) * U64(0x9E3779B97F4A7C15);
    x = rol64(x, ((phase * 7U) & 31U) + 3U);
    x ^= g.phase_dispatch_shadow + ((unsigned long)phase << 48);
    return x;
}

__attribute__((noinline)) void stage_phase_lane_update(unsigned int stage, struct StageLocalCtx *ctx,
                                                    unsigned long erax, unsigned long erbx,
                                                    unsigned long er12, unsigned long er13,
                                                    unsigned long tag) {
    unsigned char phase = ctx->phase & (PHASE_COUNT - 1);
    unsigned long x = g.phase_lane_mix[phase];
    x ^= tag;
    x ^= ((unsigned long)stage << ((phase & 7) * 8));
    x ^= ((unsigned long)ctx->idx << (((phase + 3) & 7) * 8));
    x ^= rol64(erax ^ rol64(erbx, 9) ^ er12 ^ rol64(er13, 23), ((stage + phase) & 31) + 1);
    x = xorshift64(x + U64(0xD6E8FEB86659FD93) + (unsigned long)ctx->c * U64(0x100000001B3));
    g.phase_lane_mix[phase] = x;
    g.phase_dispatch_shadow ^= rol64(x ^ tag ^ g.split_shadow[ctx->logical_stage], ((ctx->logical_stage + phase) & 31) + 1);
    for (int i = 0; i < PHASE_COUNT; i++) {
        g.phase_lane_mirror[i] = phase_lane_expected_mirror((unsigned char)i);
    }
    g.phase_dispatch_count += 1;
}

unsigned long phase_lane_guard_word() {
    unsigned long bad = 0;
    if (g.phase_dispatch_count != PHYSICAL_STAGE_COUNT) bad |= 1;
    for (int i = 0; i < PHASE_COUNT; i++) {
        if (!g.phase_lane_mix[i]) bad |= (U64(1) << (i + 4));
        if (g.phase_lane_mirror[i] != phase_lane_expected_mirror((unsigned char)i)) bad |= (U64(1) << (i + 16));
    }
    return bad;
}

unsigned char phase_lane_guard_byte(unsigned int stage) {
    unsigned long w = phase_lane_guard_word();
    return (unsigned char)((w >> ((stage & 7) * 8)) & 0xff);
}

__attribute__((noinline)) void stage_prepare_phase_worker(unsigned int stage, struct StageLocalCtx *ctx,
                                                        unsigned long erax, unsigned long erbx,
                                                        unsigned long er12, unsigned long er13) {
    deep_noise_generator(U64(0x5A11CE000) +
                         (unsigned long)ctx->logical_stage * U64(0x10001) +
                         (unsigned long)ctx->phase * U64(0x31337));
    split_stage_shadow_only(stage, ctx->logical_stage, ctx->phase, ctx->idx, ctx->c,
                            erax, erbx, er12, er13);
    vm_event_barrier((unsigned char)(stage | 0x80));
}

__attribute__((noinline)) unsigned long stage_commit_micro_worker(struct StageLocalCtx *ctx,
                                                                 unsigned long *out_lerax,
                                                                 unsigned long *out_lerbx,
                                                                 unsigned long *out_ler12,
                                                                 unsigned long *out_ler13) {
    unsigned long micro;
    unsigned long split_fold;

    *out_lerax = make_frame_reg(ctx->logical_stage, 0);
    *out_lerbx = make_frame_reg(ctx->logical_stage, 1);
    *out_ler12 = make_frame_reg(ctx->logical_stage, 2);
    *out_ler13 = make_frame_reg(ctx->logical_stage, 3);

    deep_noise_generator(U64(0xA11CE000) + ctx->logical_stage * U64(0x10001));

    micro = run_stage_micro_ops(ctx->logical_stage, ctx->idx, ctx->c, g.real_state,
                                *out_lerax, *out_lerbx, *out_ler12, *out_ler13);
    split_fold = fold_split_shadow(g.split_shadow[ctx->logical_stage], ctx->logical_stage,
                                ctx->idx, ctx->c, g.real_state,
                                   *out_lerax, *out_lerbx, *out_ler12, *out_ler13);
    micro ^= split_fold;
    memfd_stage2_commit_sample(ctx->logical_stage, ctx->idx, ctx->c, g.real_state, micro);
    g.split_last ^= split_fold ^ rol64(micro, ((ctx->logical_stage + ctx->idx) & 31) + 1);
    return micro;
}

__attribute__((noinline)) static unsigned long route_projection_mirror_fold(struct StageLocalCtx *ctx,
                                                                            unsigned char v,
                                                                            unsigned char target,
                                                                            unsigned long micro) {
    unsigned long x;
    unsigned long y;
    unsigned char idx;
    unsigned char logical;
    unsigned char phase;
    unsigned char enable;
    unsigned char lane;
    unsigned char want;
    unsigned char leak;
    unsigned char slot;

    idx = ctx->idx;
    logical = ctx->logical_stage;
    phase = ctx->phase;
    enable = (unsigned char)(route_projection_mirror_gate.enable_enc ^ route_projection_mirror_gate.enable_key);
    lane = (unsigned char)(route_projection_mirror_gate.lane_enc ^ route_projection_mirror_gate.lane_key);

    x = route_projection_mirror_gate.shadow ^ micro ^ ((unsigned long)v << 16) ^ target;
    x = xorshift64(x + route_projection_mirror_gate.mirror + (unsigned long)idx * U64(0xD1B54A32D192ED03));
    y = rol64(x ^ route_projection_cache.decoy ^ route_projection_mirror_gate.fold,
              (int)(((idx + logical + lane) & 31U) + 1U));
    route_projection_mirror_gate.fold ^= (unsigned short)((y ^ x) & 0x7fU);

    if (enable != 1 || lane != 5) {
        return (x ^ x) & (y ^ y);
    }

    want = decode_mirror_hint(idx);
    leak = (unsigned char)(ctx->c ^ want ^ logical ^ phase);
    leak = rol8(leak, (int)(((idx + lane) & 7U) + 1U));
    leak ^= (unsigned char)(micro >> (((idx ^ 3U) & 7U) * 8U));
    leak ^= (unsigned char)(x >> 11);
    slot = (unsigned char)((((idx * 2U + logical + lane) % 3U) + 1U) * 8U);
    return ((unsigned long)leak) << slot;
}

__attribute__((noinline)) static void init_route_projection_runtime_latch(void) {
    unsigned long x;
    unsigned char alpha;
    unsigned char beta;
    unsigned char arm;

    alpha = (unsigned char)(route_projection_runtime_a.alpha_enc ^ route_projection_runtime_a.alpha_key);
    beta = (unsigned char)(route_projection_runtime_b.beta_enc ^ route_projection_runtime_b.beta_key);
    arm = (unsigned char)(route_projection_runtime_b.arm_enc ^ route_projection_runtime_b.arm_key);

    x = route_projection_runtime_a.seed;
    x ^= rol64(route_projection_runtime_a.mirror, 9);
    x ^= route_projection_runtime_b.fold;
    x ^= rol64(route_projection_runtime_b.latch_seed, 17);
    x ^= route_projection_gate_a.shadow_a;
    x ^= route_projection_gate_b.shadow_b;
    x ^= (unsigned long)alpha * U64(0x100000001B3);
    x ^= rol64((unsigned long)beta * U64(0xD1B54A32D192ED03),
               (int)((arm & 31U) + 1U));
    x = xorshift64(x);
    x ^= ((unsigned long)alpha << 7);
    x ^= ((unsigned long)beta << 23);
    x ^= ((unsigned long)arm << 41);
    route_projection_runtime_latch = x;
}

__attribute__((noinline)) static unsigned char route_projection_runtime_gate_byte(unsigned char epoch,
                                                                                   unsigned char phase,
                                                                                   unsigned char lane) {
    unsigned long x;

    x = route_projection_runtime_latch;
    x ^= route_projection_epoch_gate.nonce;
    x ^= rol64(route_projection_epoch_gate.mix, (int)(((epoch ^ phase) & 31U) + 1U));
    x ^= route_projection_runtime_a.mirror;
    x ^= ((unsigned long)lane << 19);
    x = xorshift64(x + route_projection_runtime_b.latch_seed +
                   (unsigned long)epoch * U64(0x9E3779B97F4A7C15));
    return (unsigned char)(((x >> ((epoch & 7U) * 8U)) ^ (x >> 37)) & 0xffU);
}

__attribute__((noinline)) static unsigned char route_projection_orbit_byte(unsigned char epoch,
                                                                           unsigned char phase,
                                                                           unsigned char lane) {
    unsigned long x;

    x = route_projection_runtime_latch;
    x ^= rol64(route_projection_runtime_a.seed ^ route_projection_runtime_b.fold,
               (int)(((epoch + phase) & 31U) + 1U));
    x ^= ((unsigned long)lane << 27);
    x ^= ((unsigned long)phase << 43);
    x = xorshift64(x + route_projection_epoch_gate.nonce +
                   (unsigned long)epoch * U64(0xA24BAED4963EE407));
    return (unsigned char)(((x >> (((epoch + 2U) & 7U) * 8U)) ^ (x >> 39)) & 0xffU);
}

__attribute__((noinline)) static unsigned char route_projection_gate_window(unsigned char idx,
                                                                            signed char bias,
                                                                            unsigned char phase,
                                                                            unsigned char lane,
                                                                            unsigned char epoch) {
    unsigned char ok;

    ok = (unsigned char)(bias == 1);
    ok &= (unsigned char)(((phase ^ 0x73U) | (lane ^ 0x02U)) == 0);
    ok &= (unsigned char)(epoch <= 3U);
    ok &= (unsigned char)(((idx ^ epoch) & 3U) == 0);
    ok &= (unsigned char)(route_projection_runtime_gate_byte(epoch, phase, lane) == route_projection_runtime_targets[epoch & 3U]);
    ok &= (unsigned char)(route_projection_orbit_byte(epoch, phase, lane) == route_projection_orbit_targets[epoch & 3U]);
    return ok;
}

__attribute__((noinline)) static unsigned char route_projection_leak_lane_key(unsigned char lane_salt,
                                                                              unsigned char gate_phase,
                                                                              unsigned char idx,
                                                                              unsigned long micro) {
    unsigned char k;

    k = lane_salt;
    k ^= gate_phase;
    k ^= (unsigned char)(micro >> ((idx & 7U) * 8U));
    return k;
}

__attribute__((noinline)) static unsigned char route_projection_leak_residue(struct StageLocalCtx *ctx,
                                                                             unsigned char logical,
                                                                             unsigned char v,
                                                                             unsigned char target,
                                                                             unsigned long z) {
    unsigned char leak;

    leak = route_projection_residue_byte(ctx->idx);
    leak ^= ctx->c;
    leak ^= logical;
    leak ^= (unsigned char)((v ^ target) & 0U);
    leak ^= (unsigned char)z;
    leak ^= (unsigned char)(z >> 8);
    return leak;
}

__attribute__((noinline)) static unsigned char route_projection_leak_slot(unsigned char idx,
                                                                          unsigned char logical,
                                                                          unsigned char phase,
                                                                          unsigned char gate_lane) {
    unsigned char slot;

    slot = (unsigned char)((idx + logical + phase + gate_lane) % 3U);
    slot = (unsigned char)((slot + 1U) * 8U);
    return slot;
}

__attribute__((noinline)) static unsigned long route_projection_hint_fold(struct StageLocalCtx *ctx,
                                                                          unsigned char v,
                                                                          unsigned char target,
                                                                          unsigned long micro) {
    unsigned long a;
    unsigned long b;
    unsigned long z;
    unsigned char idx;
    unsigned char phase;
    unsigned char logical;
    unsigned char lane_id;
    unsigned char slot;
    unsigned char lane_key;
    signed char gate_bias;
    unsigned char gate_phase;
    unsigned char gate_lane;
    unsigned char gate_epoch;
    unsigned char tap;
    unsigned char leak;
    struct RouteProjectionLaneCell lane_snapshot;

    idx = ctx->idx;
    phase = ctx->phase;
    logical = ctx->logical_stage;
    lane_id = (unsigned char)((idx ^ logical ^ phase) & 3U);
    lane_snapshot.seed = route_projection_cache.lanes[lane_id].seed;
    lane_snapshot.salt = route_projection_cache.lanes[lane_id].salt;
    lane_snapshot.stride = route_projection_cache.lanes[lane_id].stride;
    lane_snapshot.fold = route_projection_cache.lanes[lane_id].fold;
    gate_bias = (signed char)(route_projection_gate_a.bias_enc ^ route_projection_gate_a.bias_key);
    gate_phase = (unsigned char)(route_projection_gate_b.phase_enc ^ route_projection_gate_b.phase_key);
    gate_lane = (unsigned char)(route_projection_gate_b.lane_enc ^ route_projection_gate_b.lane_key);
    gate_epoch = (unsigned char)(route_projection_epoch_gate.epoch_enc ^ route_projection_epoch_gate.epoch_key);

    a = route_projection_gate_a.shadow_a;
    a ^= lane_snapshot.seed ^ route_projection_gate_a.seed;
    a ^= route_projection_epoch_gate.nonce;
    a ^= rol64(micro ^ ((unsigned long)v << 8) ^ target,
               (int)(((idx + 5U) & 31U) + 1U));
    a += U64(0x9E3779B97F4A7C15) ^ ((unsigned long)(idx + lane_snapshot.salt) * U64(0x100000001B3));
    b = route_projection_gate_b.shadow_b;
    b ^= route_projection_gate_b.salt;
    b ^= route_projection_epoch_gate.mix;
    b ^= rol64(a + ((unsigned long)ctx->c << ((idx & 7U) * 8U)),
               (int)(((logical ^ phase) & 31U) + 1U));
    b = xorshift64(b + U64(0xD1B54A32D192ED03) + (unsigned long)phase);
    b ^= route_projection_cache.mirror;
    route_projection_cache.decoy = xorshift64(route_projection_cache.decoy ^ b ^ lane_snapshot.fold);

    tap = route_projection_cache.tap;
    tap ^= (unsigned char)b;
    tap += (unsigned char)(a >> 19);
    tap ^= route_projection_cache.phase_noise;
    tap ^= gate_phase;
    tap += lane_snapshot.stride;
    route_projection_cache.tap = (unsigned char)(tap ^ (tap >> 3));
    route_projection_cache.latch ^= (unsigned char)((gate_lane ^ gate_lane) + lane_id);
    route_projection_cache.lanes[lane_id].fold ^= (unsigned short)((lane_id ^ lane_id) << 8);
    route_projection_cache.mirror ^= rol64(a ^ b ^ route_projection_cache.decoy,
                                           (int)(((lane_id + idx) & 31U) + 1U));

    z = a ^ b;
    z ^= rol64(z + U64(0xA24BAED4963EE407), (int)(((tap ^ idx) & 31U) + 1U));
    z ^= route_projection_cache.mirror;
    z ^= route_projection_cache.mirror;
    z ^= z;
    if (!route_projection_gate_window(idx, gate_bias, gate_phase, gate_lane, gate_epoch)) {
        return z;
    }
    lane_key = route_projection_leak_lane_key(lane_snapshot.salt, gate_phase, idx, micro);
    leak = route_projection_leak_residue(ctx, logical, v, target, z);
    leak = rol8(leak, (int)(((idx ^ phase) & 7U) + 1U));
    leak ^= lane_key;

    z = (unsigned long)leak;
    z ^= ((a ^ a) & 0xffUL);
    slot = route_projection_leak_slot(idx, logical, phase, gate_lane);
    z <<= slot;
    z |= ((b ^ b) & 0xffUL);
    return z;
}

__attribute__((noinline)) unsigned long stage_commit_diff_worker(struct StageLocalCtx *ctx,
                                                                unsigned char v,
                                                                unsigned char target,
                                                                unsigned long micro) {
    unsigned long diff;
    unsigned long sealed_diff;
    unsigned char masked_v;
    unsigned char masked_target;
    unsigned char gate_mask;
    unsigned char event_mask;
    gate_mask = runtime_core_stage_mask(ctx->logical_stage);
    event_mask = eventfd_algorithm_stage_mask(ctx, micro);
    masked_v = (unsigned char)(v ^ gate_mask ^ event_mask);
    masked_target = (unsigned char)(target ^ event_mask);
    diff = (unsigned long)(unsigned char)(masked_v ^ masked_target);
    diff |= route_projection_mirror_fold(ctx, v, target, micro);
    diff |= route_projection_hint_fold(ctx, v, target, micro);
    diff |= cross_char_diff_worker(ctx, v, micro);
    diff |= (unsigned long)uffd_guard_byte(ctx->logical_stage);
    diff |= (unsigned long)target_delta_guard_byte(ctx->logical_stage);
    diff |= (unsigned long)heartbeat_guard_byte(ctx->logical_stage);
    diff |= (unsigned long)rx_helper_guard_byte(ctx->logical_stage);
    diff |= (unsigned long)memfd_stage2_guard_byte(ctx->logical_stage);
    diff |= (unsigned long)process_vm_guard_byte(ctx->logical_stage);
    diff |= (unsigned long)handler_table_guard_byte(ctx->logical_stage);
    sealed_diff = diff ^ stage_diff_runtime_cookie(ctx, v, micro);
    stage_diff_scratch_store(ctx, v, micro, sealed_diff);
    return sealed_diff ^ rol64(g.diff_scratch_mirror, (int)(((ctx->idx + ctx->phase) & 31U) + 1U));
}

__attribute__((noinline)) unsigned long diff_dispatch_expected_mirror(void) {
    unsigned long x;
    x = g.diff_dispatch_shadow ^ U64(0x444446444D495252);
    x ^= rol64(g.diff_dispatch_counter + U64(0x9E3779B97F4A7C15),
               (int)(((g.diff_dispatch_gate & 31UL) + 1UL)));
    x ^= rol64(g.diff_dispatch_gate ^ g.target_vm_gate ^ g.mix_vm_gate,
               (int)((((g.diff_dispatch_counter >> 5) & 31UL) + 1UL)));
    return xorshift64(x + U64(0xA24BAED4963EE407));
}

__attribute__((noinline)) unsigned long stage_commit_diff_decoy_worker(struct StageLocalCtx *ctx,
                                                                      unsigned char v,
                                                                      unsigned char target,
                                                                      unsigned long micro) {
    unsigned long x;
    unsigned char pretend_target;
    unsigned char slot;

    pretend_target = (unsigned char)(target ^ runtime_core_stage_mask((unsigned char)(ctx->logical_stage ^ 0x2dU)));
    pretend_target ^= (unsigned char)(g.route_roll_mirror >> (((ctx->idx ^ ctx->phase) & 7U) * 8U));
    pretend_target = rol8((unsigned char)(pretend_target + ctx->logical_stage * 0x13U + ctx->idx),
                          (int)(((ctx->phase + ctx->idx) & 7U) + 1U));

    x = (unsigned long)(unsigned char)(v ^ pretend_target);
    x |= ((unsigned long)(ctx->c ^ pretend_target) << 8);
    x ^= rol64(micro ^ g.diff_dispatch_gate ^ g.forty_round_shadow,
               (int)(((ctx->logical_stage + 5U) & 31U) + 1U));
    x ^= rol64(g.target_vm_shadow ^ g.mix_vm_shadow,
               (int)(((ctx->idx * 3U + ctx->phase) & 31U) + 1U));
    x = xorshift64(x + U64(0xDEC0A11DF00DCAFE));

    slot = (unsigned char)((ctx->idx + ctx->logical_stage + ctx->phase) & 7U);
    g.diff_decoy_scratch[slot] = x ^ rol64(g.diff_decoy_scratch[slot ^ 5U],
                                           (int)(((slot + ctx->phase) & 31U) + 1U));
    return x ^ ((unsigned long)(unsigned char)(v ^ pretend_target));
}

__attribute__((noinline)) unsigned long diff_dispatch_guard_word(void) {
    unsigned long bad = 0;
    if (g.diff_dispatch_counter != FLAG_LEN) bad |= U64(0x7301);
    if (g.diff_dispatch_shadow == U64(0x4444464453484457)) bad |= U64(0x7302);
    if (g.diff_dispatch_mirror != diff_dispatch_expected_mirror()) bad |= U64(0x7304);
    if (!g.diff_dispatch_gate) bad |= U64(0x7308);
    return bad;
}

__attribute__((noinline)) unsigned long stage_commit_diff_dispatcher(struct StageLocalCtx *ctx,
                                                                    unsigned char v,
                                                                    unsigned char target,
                                                                    unsigned long micro) {
    unsigned long decoy;
    unsigned long real;
    unsigned long salt;

    decoy = stage_commit_diff_decoy_worker(ctx, v, target, micro);
    salt = decoy ^ rol64(micro ^ g.diff_dispatch_gate,
                         (int)(((ctx->idx + ctx->logical_stage) & 31U) + 1U));
    g.diff_dispatch_shadow = xorshift64(g.diff_dispatch_shadow ^ salt ^
                                        ((unsigned long)(ctx->c + 0x100U) << (((ctx->idx ^ ctx->phase) & 7U) * 8U)));
    g.diff_dispatch_counter += 1;
    g.diff_dispatch_gate = xorshift64(g.diff_dispatch_gate + g.diff_dispatch_shadow +
                                      ((unsigned long)(ctx->logical_stage + 1U) * U64(0xD1B54A32D192ED03)) +
                                      g.diff_dispatch_counter);
    g.diff_dispatch_mirror = diff_dispatch_expected_mirror();

    real = stage_commit_diff_worker(ctx, v, target, micro);
    return real ^ ((decoy ^ decoy) & U64(0xff));
}

__attribute__((noinline)) void stage_commit_apply_worker(unsigned int stage, struct StageLocalCtx *ctx,
                                                        unsigned long lerax, unsigned long lerbx,
                                                        unsigned long ler12, unsigned long ler13,
                                                        unsigned long micro,
                                                        unsigned char v) {
    unsigned long diff;
    diff = stage_diff_scratch_load(ctx, v, micro);
    diff ^= stage_diff_runtime_cookie(ctx, v, micro);
    g.fail_acc |= diff;
    g.final_guard ^= (diff << ((ctx->logical_stage & 7) * 8));
    g.final_guard = rol64(g.final_guard + ctx->logical_stage + ctx->idx + 0x71 + (lerax & 0xff), 3);

    g.real_state = mix_state(g.real_state, v, ctx->c, ctx->idx, ctx->logical_stage,
                            lerax, lerbx, ler12, ler13, micro);
    g.entropy[(ctx->logical_stage * 11) & 63] ^= g.real_state ^ ((unsigned long)ctx->c << 8) ^ v ^ ler13;

    if ((ctx->logical_stage & 3) == 2) {
        int fa = fake_check_a();
        int fb = fake_check_b();
        fake_check_lane_update(stage, ctx->logical_stage, fa, fb);
    }

    g.split_shadow[ctx->logical_stage] = 0;
    vm_event_barrier((unsigned char)(stage | 0x80));
}

__attribute__((noinline)) unsigned long apply_dispatch_expected_mirror(void) {
    unsigned long x;
    x = g.apply_dispatch_shadow ^ U64(0x4150444D49525252);
    x ^= rol64(g.apply_dispatch_counter + U64(0xBF58476D1CE4E5B9),
               (int)(((g.apply_dispatch_gate & 31UL) + 1UL)));
    x ^= rol64(g.apply_dispatch_gate ^ g.diff_dispatch_gate ^ g.mix_vm_gate,
               (int)((((g.apply_dispatch_counter >> 6) & 31UL) + 1UL)));
    return xorshift64(x + U64(0x94D049BB133111EB));
}

__attribute__((noinline)) void stage_commit_apply_decoy_worker(unsigned int stage, struct StageLocalCtx *ctx,
                                                              unsigned long lerax, unsigned long lerbx,
                                                              unsigned long ler12, unsigned long ler13,
                                                              unsigned long micro,
                                                              unsigned char v) {
    unsigned long x;
    unsigned char slot;
    slot = (unsigned char)((stage + ctx->idx + ctx->logical_stage) & 7U);
    x  = g.apply_decoy_scratch[slot];
    x ^= rol64(lerax ^ rol64(lerbx, 9) ^ rol64(ler12, 17) ^ rol64(ler13, 27),
               (int)(((ctx->phase + ctx->idx) & 31U) + 1U));
    x ^= rol64(micro ^ g.diff_decoy_scratch[slot ^ 3U] ^ g.apply_dispatch_gate,
               (int)(((ctx->logical_stage + 11U) & 31U) + 1U));
    x ^= ((unsigned long)(ctx->c + 0x100U + v) << (((ctx->idx ^ ctx->phase) & 7U) * 8U));
    x = xorshift64(x + U64(0xA9911EDDEC0A9911) + ((unsigned long)stage << 32));
    g.apply_decoy_scratch[slot] = x;
    g.apply_decoy_scratch[slot ^ 5U] ^= rol64(x ^ g.target_vm_shadow,
                                               (int)(((slot + stage) & 31U) + 1U));
}

__attribute__((noinline)) unsigned long apply_dispatch_guard_word(void) {
    unsigned long bad = 0;
    if (g.apply_dispatch_counter != FLAG_LEN) bad |= U64(0x7401);
    if (g.apply_dispatch_shadow == U64(0x4150445353484457)) bad |= U64(0x7402);
    if (g.apply_dispatch_mirror != apply_dispatch_expected_mirror()) bad |= U64(0x7404);
    if (!g.apply_dispatch_gate) bad |= U64(0x7408);
    return bad;
}

__attribute__((noinline)) void stage_commit_apply_dispatcher(unsigned int stage, struct StageLocalCtx *ctx,
                                                            unsigned long lerax, unsigned long lerbx,
                                                            unsigned long ler12, unsigned long ler13,
                                                            unsigned long micro,
                                                            unsigned char v) {
    unsigned long salt;
    stage_commit_apply_decoy_worker(stage, ctx, lerax, lerbx, ler12, ler13, micro, v);

    salt = g.apply_decoy_scratch[(stage + ctx->idx) & 7U] ^
           rol64(micro ^ g.apply_dispatch_gate, (int)(((ctx->logical_stage + ctx->phase) & 31U) + 1U));
    g.apply_dispatch_shadow = xorshift64(g.apply_dispatch_shadow ^ salt ^
                                         ((unsigned long)(v + 0x100U) << (((stage ^ ctx->idx) & 7U) * 8U)));
    g.apply_dispatch_counter += 1;
    g.apply_dispatch_gate = xorshift64(g.apply_dispatch_gate + g.apply_dispatch_shadow +
                                       ((unsigned long)(ctx->idx + 1U) * U64(0xA24BAED4963EE407)) +
                                       g.apply_dispatch_counter);
    g.apply_dispatch_mirror = apply_dispatch_expected_mirror();

    stage_commit_apply_worker(stage, ctx, lerax, lerbx, ler12, ler13, micro, v);
}

__attribute__((noinline)) void stage_commit_phase_worker(unsigned int stage, struct StageLocalCtx *ctx) {
    unsigned long micro;
    unsigned long lerax;
    unsigned long lerbx;
    unsigned long ler12;
    unsigned long ler13;
    unsigned char v;
    unsigned char target;

    micro = stage_commit_micro_worker(ctx, &lerax, &lerbx, &ler12, &ler13);
    v = stateful_transform(ctx->c, ctx->idx, ctx->logical_stage, g.real_state, lerax, lerbx, ler12, ler13, micro);
    target = decode_sealed_target(ctx->logical_stage);
    (void)stage_commit_diff_dispatcher(ctx, v, target, micro);
    stage_commit_apply_dispatcher(stage, ctx, lerax, lerbx, ler12, ler13, micro, v);
}

__attribute__((noinline)) void stage_phase0_worker(unsigned int stage, struct StageLocalCtx *ctx,
                                                unsigned long erax, unsigned long erbx,
                                                unsigned long er12, unsigned long er13) {
    stage_phase_lane_update(stage, ctx, erax, erbx, er12, er13, U64(0x2300000000000000));
    stage_prepare_phase_worker(stage, ctx, erax, erbx, er12, er13);
}

__attribute__((noinline)) void stage_phase1_worker(unsigned int stage, struct StageLocalCtx *ctx,
                                                unsigned long erax, unsigned long erbx,
                                                unsigned long er12, unsigned long er13) {
    stage_phase_lane_update(stage, ctx, erax, erbx, er12, er13, U64(0x2300000000001111));
    g.event_shadow ^= rol64(g.phase_lane_mix[1] ^ g.handler_table_stage_mix, ((stage + ctx->idx) & 31) + 1);
    stage_prepare_phase_worker(stage, ctx, erax, erbx, er12, er13);
}

__attribute__((noinline)) void stage_phase2_worker(unsigned int stage, struct StageLocalCtx *ctx,
                                                unsigned long erax, unsigned long erbx,
                                                unsigned long er12, unsigned long er13) {
    stage_phase_lane_update(stage, ctx, erax, erbx, er12, er13, U64(0x2300000000002222));
    g.gate_shadow ^= rol64(g.phase_lane_mix[2] ^ g.pvm_stage_mix, ((stage ^ ctx->c) & 31) + 1);
    stage_prepare_phase_worker(stage, ctx, erax, erbx, er12, er13);
}

__attribute__((noinline)) void stage_phase3_worker(unsigned int stage, struct StageLocalCtx *ctx) {
    stage_phase_lane_update(stage, ctx, g.real_state, g.final_guard, g.memfd_stage2_commit_mix, g.rx_helper_active_mix, U64(0x2300000000003333));
    stage_commit_phase_worker(stage, ctx);
}

void stage_phase_dispatch(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    struct StageLocalCtx ctx;

    if (!stage_load_local_ctx(stage, &ctx)) return;

    stage_runtime_gates(stage);
    stage_metadata_gate(stage, &ctx);
    virtual_phase_bundle(stage, &ctx, erax, erbx, er12, er13);

    if (ctx.phase == 0) {
        stage_phase0_worker(stage, &ctx, erax, erbx, er12, er13);
    } else if (ctx.phase == 1) {
        stage_phase1_worker(stage, &ctx, erax, erbx, er12, er13);
    } else if (ctx.phase == 2) {
        stage_phase2_worker(stage, &ctx, erax, erbx, er12, er13);
    } else {
        stage_phase3_worker(stage, &ctx);
    }
}


__attribute__((noinline)) unsigned long stage_input_vault_projection_noise(unsigned int stage,
                                                                           struct StageLocalCtx *ctx,
                                                                           unsigned long flavor) {
    unsigned char idx0;
    unsigned char idx1;
    unsigned char idx2;
    unsigned char sa0;
    unsigned char sa1;
    unsigned char sb0;
    unsigned char sb1;
    unsigned char da;
    unsigned char db;
    unsigned char va0;
    unsigned char va1;
    unsigned char vb0;
    unsigned char vb1;
    unsigned char vd;
    unsigned long x;
    struct InputNode *node;

    idx0 = (unsigned char)((ctx->idx + ctx->logical_stage * 3U + stage + flavor) % FLAG_LEN);
    idx1 = (unsigned char)((ctx->idx * 5U + ctx->phase * 11U + (unsigned char)(flavor >> 8)) % FLAG_LEN);
    idx2 = (unsigned char)((idx0 + idx1 + ctx->c + (unsigned char)(stage >> 1U)) % FLAG_LEN);
    sa0 = input_stage_slot_a(idx0);
    sa1 = input_stage_slot_a(idx1);
    sb0 = input_stage_slot_b(idx1);
    sb1 = input_stage_slot_b(idx2);
    da = (unsigned char)((stage + ctx->idx + (unsigned char)flavor) & 63U);
    db = (unsigned char)((stage * 3U + ctx->logical_stage + (unsigned char)(flavor >> 16)) & 63U);

    va0 = input_vault.lane_a[sa0];
    va1 = input_vault.lane_a[sa1];
    vb0 = input_vault.lane_b[sb0];
    vb1 = input_vault.lane_b[sb1];
    vd = input_vault.decoy[da] ^ input_vault.decoy[db];
    node = &input_vault.nodes[idx2];

    x = U64(0x1A2E5A7EF00DCAFE) ^ flavor ^ ((unsigned long)stage << 32);
    x ^= ((unsigned long)(va0 + 0x100U + vb0) << (((ctx->phase + idx0) & 7U) * 8U));
    x ^= ((unsigned long)(va1 + 0x100U + vb1) << (((ctx->logical_stage + idx1) & 7U) * 8U));
    x ^= ((unsigned long)(vd + 0x100U + ctx->c) << (((stage + idx2) & 7U) * 8U));
    x ^= rol64((unsigned long)node->raw_index ^ ((unsigned long)node->sink_index << 8) ^
               ((unsigned long)node->mask << 16) ^ node->tag,
               (int)(((stage + idx0 + idx1) & 31U) + 1U));
    x ^= rol64((unsigned long)(input_vault.input_len + 0x100UL) ^ input_vault.transit_hash,
               (int)(((ctx->idx ^ ctx->phase ^ flavor) & 31U) + 1U));
    x = xorshift64(x + U64(0xA24BAED4963EE407));

    input_vault.lane_a[sa0] ^= (unsigned char)x;
    input_vault.lane_a[sa0] ^= (unsigned char)x;
    input_vault.lane_b[sb0] ^= (unsigned char)(x >> 8);
    input_vault.lane_b[sb0] ^= (unsigned char)(x >> 8);
    input_vault.decoy[da] ^= (unsigned char)(x >> 16);
    input_vault.decoy[da] ^= (unsigned char)(x >> 16);

    g.diff_decoy_scratch[(stage ^ x) & 7U] ^= rol64(x ^ g.route_roll_mix,
                                                    (int)(((idx0 + ctx->phase) & 31U) + 1U));
    g.apply_decoy_scratch[(idx1 ^ stage) & 7U] ^= rol64(x ^ g.virtual_dispatch_shadow,
                                                       (int)(((idx2 + ctx->logical_stage) & 31U) + 1U));
    g.dummy_hash ^= (x & ((flavor & 2UL) ? U64(0xff) : U64(0)));
    g.dummy_hash ^= (x & ((flavor & 2UL) ? U64(0xff) : U64(0)));
    return x;
}

__attribute__((noinline)) void stage_noise_param_pollute(unsigned int stage, struct StageLocalCtx *ctx,
                                                         unsigned long erax, unsigned long erbx,
                                                         unsigned long er12, unsigned long er13,
                                                         unsigned long flavor) {
    unsigned char sem_stage;
    unsigned char fake_target;
    unsigned char fake_v;
    unsigned char slot;
    unsigned long fake_micro;
    unsigned long vault_noise;
    unsigned long x;

    sem_stage = (unsigned char)(ctx->logical_stage * PHASE_COUNT + ctx->phase);
    vault_noise = stage_input_vault_projection_noise(stage, ctx, flavor);
    fake_micro = xorshift64(erax ^ rol64(erbx, 11) ^ rol64(er12, 23) ^ rol64(er13, 37) ^
                            ((unsigned long)stage << 32) ^ flavor ^ g.virtual_dispatch_shadow ^ vault_noise);
    fake_target = decode_sealed_target_decoy_worker((unsigned char)(ctx->logical_stage ^ ctx->idx ^ flavor));
    fake_v = (unsigned char)(ctx->c ^ fake_target ^ (unsigned char)fake_micro ^
                             (unsigned char)vault_noise ^
                             (unsigned char)(g.route_roll_mix >> (((ctx->phase + flavor) & 7U) * 8U)));

    (void)stage_commit_diff_decoy_worker(ctx, fake_v, fake_target, fake_micro);
    stage_commit_apply_decoy_worker(stage, ctx,
                                    erax ^ fake_micro,
                                    erbx + rol64(fake_micro, 7),
                                    er12 ^ rol64(fake_micro, 19),
                                    er13 + rol64(fake_micro, 31),
                                    fake_micro, fake_v);

    slot = (unsigned char)((stage + ctx->idx + flavor) & 63U);
    x = g.entropy[slot];
    x ^= rol64(fake_micro ^ ((unsigned long)fake_v << (((stage ^ flavor) & 7U) * 8U)),
               (int)(((ctx->logical_stage + flavor) & 31U) + 1U));
    x ^= rol64(g.diff_decoy_scratch[(slot ^ 3U) & 7U] ^ g.apply_decoy_scratch[(slot ^ 5U) & 7U] ^ vault_noise,
               (int)(((ctx->idx + stage) & 31U) + 1U));
    g.entropy[slot] = xorshift64(x + U64(0xF00DFACEA11CE5A7) + flavor);
    g.dummy_hash ^= (g.entropy[slot] & ((flavor & 1UL) ? U64(0xff) : U64(0)));
    g.dummy_hash ^= (g.entropy[slot] & ((flavor & 1UL) ? U64(0xff) : U64(0)));
    g.phase_dispatch_shadow ^= rol64(fake_micro ^ g.target_decode_decoy_scratch[slot & 7U],
                                     (int)(((sem_stage + flavor) & 31U) + 1U));
}

__attribute__((noinline)) void stage_dispatch_noise_core(unsigned int stage, unsigned long erax, unsigned long erbx,
                                                         unsigned long er12, unsigned long er13,
                                                         unsigned long flavor) {
    struct StageLocalCtx ctx;
    unsigned char sem_stage;
    if (!stage_load_local_ctx(stage, &ctx)) return;
    sem_stage = (unsigned char)(ctx.logical_stage * PHASE_COUNT + ctx.phase);
    virtual_phase_bundle(stage, &ctx, erax, erbx, er12, er13);
    stage_noise_param_pollute(stage, &ctx, erax, erbx, er12, er13, flavor);
    stage_phase_lane_update(stage, &ctx, erax, erbx, er12, er13,
                            U64(0x23D15A0000F10000) ^ flavor ^ (unsigned long)stage_expansion_lane(stage));
    g.route_roll_mix ^= rol64(g.virtual_dispatch_shadow ^ sem_stage ^ stage,
                              (int)(((stage + ctx.idx) & 31U) + 1U));
}

__attribute__((noinline)) void stage_dispatch_noise(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    stage_dispatch_noise_core(stage, erax, erbx, er12, er13, U64(0x5100000000000000));
}

__attribute__((noinline)) void stage_dispatch_noise_a(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    stage_dispatch_noise_core(stage, erax ^ rol64(er13, 5), erbx, er12 + stage, er13, U64(0x51000000000000A1));
}

__attribute__((noinline)) void stage_dispatch_noise_b(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    stage_dispatch_noise_core(stage, erax, erbx ^ rol64(erax, 9), er12, er13 + g.route_roll_mix, U64(0x51000000000000B2));
}

__attribute__((noinline)) void stage_dispatch_noise_c(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    stage_dispatch_noise_core(stage, erax + g.virtual_dispatch_shadow, erbx, er12 ^ rol64(erbx, 17), er13, U64(0x51000000000000C3));
}

__attribute__((noinline)) void stage_dispatch_noise_d(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    stage_dispatch_noise_core(stage, erax, erbx + g.phase_dispatch_shadow, er12, er13 ^ rol64(er12, 29), U64(0x51000000000000D4));
}

__attribute__((noinline)) void stage_dispatch_noise_e(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    stage_dispatch_noise_core(stage, erax ^ g.input_digest, erbx ^ g.target_key, er12, er13, U64(0x51000000000000E5));
}

__attribute__((noinline)) void stage_dispatch_fake_real_core(unsigned int stage, unsigned long erax, unsigned long erbx,
                                                            unsigned long er12, unsigned long er13,
                                                            unsigned long flavor) {
    struct StageLocalCtx ctx;
    unsigned char sem_stage;
    unsigned long serax, serbx, ser12, ser13;
    if (!stage_load_local_ctx(stage, &ctx)) return;
    sem_stage = (unsigned char)(ctx.logical_stage * PHASE_COUNT + ctx.phase);
    serax = make_frame_reg((unsigned int)(sem_stage ^ (unsigned char)flavor), 0) ^ erax;
    serbx = make_frame_reg((unsigned int)(sem_stage + (unsigned char)(flavor >> 8)), 1) ^ erbx;
    ser12 = make_frame_reg((unsigned int)(sem_stage ^ (unsigned char)(flavor >> 16)), 2) ^ er12;
    ser13 = make_frame_reg((unsigned int)(sem_stage + (unsigned char)(flavor >> 24)), 3) ^ er13;
    virtual_phase_bundle(stage, &ctx, serax, serbx, ser12, ser13);
    stage_noise_param_pollute(stage, &ctx, serax, serbx, ser12, ser13, flavor);
    stage_phase_lane_update(stage, &ctx, serax, serbx, ser12, ser13,
                            U64(0x23FA1E0000000000) ^ flavor ^ ((unsigned long)sem_stage << 8));
    g.route_roll_mix ^= rol64(g.diff_decoy_scratch[(stage ^ flavor) & 7U] ^
                              g.apply_decoy_scratch[(stage + ctx.idx) & 7U] ^
                              g.target_decode_decoy_scratch[(ctx.logical_stage + flavor) & 7U],
                              (int)(((stage ^ ctx.c ^ flavor) & 31U) + 1U));
}

__attribute__((noinline)) void stage_dispatch_fake_p0(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    stage_dispatch_fake_real_core(stage, erax, erbx, er12, er13, U64(0xFA1E000000000000));
}

__attribute__((noinline)) void stage_dispatch_fake_p1(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    stage_dispatch_fake_real_core(stage, erax, erbx, er12, er13, U64(0xFA1E000000001111));
}

__attribute__((noinline)) void stage_dispatch_fake_p2(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    stage_dispatch_fake_real_core(stage, erax, erbx, er12, er13, U64(0xFA1E000000002222));
}

__attribute__((noinline)) void stage_dispatch_fake_p3(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    stage_dispatch_fake_real_core(stage, erax, erbx, er12, er13, U64(0xFA1E000000003333));
}

__attribute__((noinline)) void stage_dispatch_bad_phase(unsigned int stage, unsigned long got, unsigned long expected) {
    unsigned long x = ((unsigned long)stage << 32) ^ (got << 8) ^ expected ^ U64(0x23BADF00D5A5EED);
    g.phase_dispatch_shadow ^= rol64(x + g.real_state + g.step_counter, ((stage ^ got ^ expected) & 31) + 1);
    g.fail_acc |= (unsigned long)((got ^ expected) & 1U);
}

__attribute__((noinline)) void stage_dispatch_p0(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    struct StageLocalCtx ctx;
    unsigned char sem_stage;
    unsigned long serax, serbx, ser12, ser13;
    (void)erax; (void)erbx; (void)er12; (void)er13;
    if (!stage_load_local_ctx(stage, &ctx)) return;
    if (ctx.phase != 0) { stage_dispatch_bad_phase(stage, ctx.phase, 0); return; }
    sem_stage = (unsigned char)(ctx.logical_stage * PHASE_COUNT + ctx.phase);
    serax = make_frame_reg(sem_stage, 0);
    serbx = make_frame_reg(sem_stage, 1);
    ser12 = make_frame_reg(sem_stage, 2);
    ser13 = make_frame_reg(sem_stage, 3);
    stage_runtime_gates(stage);
    stage_metadata_gate(stage, &ctx);
    virtual_phase_bundle(stage, &ctx, serax, serbx, ser12, ser13);
    g.phase_dispatch_shadow ^= rol64(U64(0x23D15A0000000000) ^ sem_stage ^ serax ^ g.phase_lane_mix[0], ((sem_stage + ctx.idx) & 31) + 1);
    stage_phase0_worker(sem_stage, &ctx, serax, serbx, ser12, ser13);
}

__attribute__((noinline)) void stage_dispatch_p1(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    struct StageLocalCtx ctx;
    unsigned char sem_stage;
    unsigned long serax, serbx, ser12, ser13;
    (void)erax; (void)erbx; (void)er12; (void)er13;
    if (!stage_load_local_ctx(stage, &ctx)) return;
    if (ctx.phase != 1) { stage_dispatch_bad_phase(stage, ctx.phase, 1); return; }
    sem_stage = (unsigned char)(ctx.logical_stage * PHASE_COUNT + ctx.phase);
    serax = make_frame_reg(sem_stage, 0);
    serbx = make_frame_reg(sem_stage, 1);
    ser12 = make_frame_reg(sem_stage, 2);
    ser13 = make_frame_reg(sem_stage, 3);
    stage_runtime_gates(stage);
    stage_metadata_gate(stage, &ctx);
    virtual_phase_bundle(stage, &ctx, serax, serbx, ser12, ser13);
    g.phase_dispatch_shadow ^= rol64(U64(0x23D15A0000001111) ^ sem_stage ^ serbx ^ g.phase_lane_mix[1], ((sem_stage + ctx.c) & 31) + 1);
    stage_phase1_worker(sem_stage, &ctx, serax, serbx, ser12, ser13);
}

__attribute__((noinline)) void stage_dispatch_p2(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    struct StageLocalCtx ctx;
    unsigned char sem_stage;
    unsigned long serax, serbx, ser12, ser13;
    (void)erax; (void)erbx; (void)er12; (void)er13;
    if (!stage_load_local_ctx(stage, &ctx)) return;
    if (ctx.phase != 2) { stage_dispatch_bad_phase(stage, ctx.phase, 2); return; }
    sem_stage = (unsigned char)(ctx.logical_stage * PHASE_COUNT + ctx.phase);
    serax = make_frame_reg(sem_stage, 0);
    serbx = make_frame_reg(sem_stage, 1);
    ser12 = make_frame_reg(sem_stage, 2);
    ser13 = make_frame_reg(sem_stage, 3);
    stage_runtime_gates(stage);
    stage_metadata_gate(stage, &ctx);
    virtual_phase_bundle(stage, &ctx, serax, serbx, ser12, ser13);
    g.phase_dispatch_shadow ^= rol64(U64(0x23D15A0000002222) ^ sem_stage ^ ser12 ^ g.phase_lane_mix[2], ((sem_stage ^ ctx.idx) & 31) + 1);
    stage_phase2_worker(sem_stage, &ctx, serax, serbx, ser12, ser13);
}

__attribute__((noinline)) void stage_dispatch_p3(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    struct StageLocalCtx ctx;
    unsigned char sem_stage;
    (void)erax; (void)erbx; (void)er12; (void)er13;
    if (!stage_load_local_ctx(stage, &ctx)) return;
    if (ctx.phase != 3) { stage_dispatch_bad_phase(stage, ctx.phase, 3); return; }
    sem_stage = (unsigned char)(ctx.logical_stage * PHASE_COUNT + ctx.phase);
    stage_runtime_gates(stage);
    stage_metadata_gate(stage, &ctx);
    virtual_phase_bundle(stage, &ctx, g.real_state, g.final_guard, g.memfd_stage2_commit_mix, g.rx_helper_active_mix);
    g.phase_dispatch_shadow ^= rol64(U64(0x23D15A0000003333) ^ sem_stage ^ g.final_guard ^ g.phase_lane_mix[3], ((sem_stage + ctx.logical_stage) & 31) + 1);
    stage_phase3_worker(sem_stage, &ctx);
}

void do_real_stage(unsigned int stage, unsigned long erax, unsigned long erbx, unsigned long er12, unsigned long er13) {
    g.dummy_hash ^= ((unsigned long)stage << 32) ^ (erax & 0xff);
    stage_phase_dispatch(stage, erax, erbx, er12, er13);
}

void srop_jump_seeded(unsigned long target, unsigned int next_stage) {
    struct ucontext frame = {0};
    unsigned long new_rsp;

    frame.ss_sp = sigalt_stack_main;
    frame.ss_flags = 0;
    frame.ss_size = SIGALT_STACK_SIZE;

    frame.uc_mcontext.rip = target;
    frame.uc_mcontext.cs = 0x33;
    frame.uc_mcontext.rax = make_frame_reg(next_stage, 0);
    frame.uc_mcontext.rbx = make_frame_reg(next_stage, 1);
    frame.uc_mcontext.r12 = make_frame_reg(next_stage, 2);
    frame.uc_mcontext.r13 = make_frame_reg(next_stage, 3);

    __asm__ volatile ("mov %%rsp, %0" : "=r"(new_rsp));
    new_rsp = (new_rsp - 0x400UL) & ~0xFUL;
    frame.uc_mcontext.rsp = new_rsp - 8;
    //rt_sigreturn
    volatile struct ucontext *p_frame = &frame;
    __asm__ volatile (
        "mov %0, %%rsp\n\t"
        "mov $15, %%rax\n\t"
        "syscall\n\t"
        : : "r"(p_frame) : "memory"
    );
}

void final_stage();
void stage_000(); void stage_001(); void stage_002(); void stage_003(); void stage_004(); void stage_005(); void stage_006(); void stage_007();
void stage_008(); void stage_009(); void stage_010(); void stage_011(); void stage_012(); void stage_013(); void stage_014(); void stage_015();
void stage_016(); void stage_017(); void stage_018(); void stage_019(); void stage_020(); void stage_021(); void stage_022(); void stage_023();
void stage_024(); void stage_025(); void stage_026(); void stage_027(); void stage_028(); void stage_029(); void stage_030(); void stage_031();
void stage_032(); void stage_033(); void stage_034(); void stage_035(); void stage_036(); void stage_037(); void stage_038(); void stage_039();
void stage_040(); void stage_041(); void stage_042(); void stage_043(); void stage_044(); void stage_045(); void stage_046(); void stage_047();
void stage_048(); void stage_049(); void stage_050(); void stage_051(); void stage_052(); void stage_053(); void stage_054(); void stage_055();
void stage_056(); void stage_057(); void stage_058(); void stage_059(); void stage_060(); void stage_061(); void stage_062(); void stage_063();
void stage_064(); void stage_065(); void stage_066(); void stage_067(); void stage_068(); void stage_069(); void stage_070(); void stage_071();
void stage_072(); void stage_073(); void stage_074(); void stage_075(); void stage_076(); void stage_077(); void stage_078(); void stage_079();
void stage_080(); void stage_081(); void stage_082(); void stage_083(); void stage_084(); void stage_085(); void stage_086(); void stage_087();
void stage_088(); void stage_089(); void stage_090(); void stage_091(); void stage_092(); void stage_093(); void stage_094(); void stage_095();
void stage_096(); void stage_097(); void stage_098(); void stage_099(); void stage_100(); void stage_101(); void stage_102(); void stage_103();
void stage_104(); void stage_105(); void stage_106(); void stage_107(); void stage_108(); void stage_109(); void stage_110(); void stage_111();
void stage_112(); void stage_113(); void stage_114(); void stage_115(); void stage_116(); void stage_117(); void stage_118(); void stage_119();
void stage_120(); void stage_121(); void stage_122(); void stage_123(); void stage_124(); void stage_125(); void stage_126(); void stage_127();
void stage_128(); void stage_129(); void stage_130(); void stage_131(); void stage_132(); void stage_133(); void stage_134(); void stage_135();
void stage_136(); void stage_137(); void stage_138(); void stage_139(); void stage_140(); void stage_141(); void stage_142(); void stage_143();
void stage_144(); void stage_145(); void stage_146(); void stage_147(); void stage_148(); void stage_149(); void stage_150(); void stage_151();
void stage_152(); void stage_153(); void stage_154(); void stage_155(); void stage_156(); void stage_157(); void stage_158(); void stage_159();
void stage_160(); void stage_161(); void stage_162(); void stage_163(); void stage_164(); void stage_165(); void stage_166(); void stage_167();
void stage_168(); void stage_169(); void stage_170(); void stage_171(); void stage_172(); void stage_173(); void stage_174(); void stage_175();
void stage_176(); void stage_177(); void stage_178(); void stage_179(); void stage_180(); void stage_181(); void stage_182(); void stage_183();
void stage_184(); void stage_185(); void stage_186(); void stage_187(); void stage_188(); void stage_189(); void stage_190(); void stage_191();
void stage_192(); void stage_193(); void stage_194(); void stage_195(); void stage_196(); void stage_197(); void stage_198(); void stage_199();
void stage_200(); void stage_201(); void stage_202(); void stage_203(); void stage_204(); void stage_205(); void stage_206(); void stage_207();
void stage_208(); void stage_209(); void stage_210(); void stage_211(); void stage_212(); void stage_213(); void stage_214(); void stage_215();
void stage_216(); void stage_217(); void stage_218(); void stage_219(); void stage_220(); void stage_221(); void stage_222(); void stage_223();
void stage_224(); void stage_225(); void stage_226(); void stage_227(); void stage_228(); void stage_229(); void stage_230(); void stage_231();
void stage_232(); void stage_233(); void stage_234(); void stage_235(); void stage_236(); void stage_237(); void stage_238(); void stage_239();
void stage_240(); void stage_241(); void stage_242(); void stage_243(); void stage_244(); void stage_245(); void stage_246(); void stage_247();
void stage_248(); void stage_249(); void stage_250(); void stage_251(); void stage_252(); void stage_253(); void stage_254(); void stage_255();
void stage_256(); void stage_257(); void stage_258(); void stage_259(); void stage_260(); void stage_261(); void stage_262(); void stage_263();
void stage_264(); void stage_265(); void stage_266(); void stage_267(); void stage_268(); void stage_269(); void stage_270(); void stage_271();
void stage_272(); void stage_273(); void stage_274(); void stage_275(); void stage_276(); void stage_277(); void stage_278(); void stage_279();
void stage_280(); void stage_281(); void stage_282(); void stage_283(); void stage_284(); void stage_285(); void stage_286(); void stage_287();
void stage_288(); void stage_289(); void stage_290(); void stage_291(); void stage_292(); void stage_293(); void stage_294(); void stage_295();
void stage_296(); void stage_297(); void stage_298(); void stage_299(); void stage_300(); void stage_301(); void stage_302(); void stage_303();
void stage_304(); void stage_305(); void stage_306(); void stage_307(); void stage_308(); void stage_309(); void stage_310(); void stage_311();
void stage_312(); void stage_313(); void stage_314(); void stage_315(); void stage_316(); void stage_317(); void stage_318(); void stage_319();
void stage_320(); void stage_321(); void stage_322(); void stage_323(); void stage_324(); void stage_325(); void stage_326(); void stage_327();
void stage_328(); void stage_329(); void stage_330(); void stage_331(); void stage_332(); void stage_333(); void stage_334(); void stage_335();
void stage_336(); void stage_337(); void stage_338(); void stage_339(); void stage_340(); void stage_341(); void stage_342(); void stage_343();
void stage_344(); void stage_345(); void stage_346(); void stage_347(); void stage_348(); void stage_349(); void stage_350(); void stage_351();
void stage_352(); void stage_353(); void stage_354(); void stage_355(); void stage_356(); void stage_357(); void stage_358(); void stage_359();
void stage_360(); void stage_361(); void stage_362(); void stage_363(); void stage_364(); void stage_365(); void stage_366(); void stage_367();
void stage_368(); void stage_369(); void stage_370(); void stage_371(); void stage_372(); void stage_373(); void stage_374(); void stage_375();
void stage_376(); void stage_377(); void stage_378(); void stage_379(); void stage_380(); void stage_381(); void stage_382(); void stage_383();
void stage_384(); void stage_385(); void stage_386(); void stage_387(); void stage_388(); void stage_389(); void stage_390(); void stage_391();
void stage_392(); void stage_393(); void stage_394(); void stage_395(); void stage_396(); void stage_397(); void stage_398(); void stage_399();
void stage_400(); void stage_401(); void stage_402(); void stage_403(); void stage_404(); void stage_405(); void stage_406(); void stage_407();
void stage_408(); void stage_409(); void stage_410(); void stage_411(); void stage_412(); void stage_413(); void stage_414(); void stage_415();
void stage_416(); void stage_417(); void stage_418(); void stage_419(); void stage_420(); void stage_421(); void stage_422(); void stage_423();
void stage_424(); void stage_425(); void stage_426(); void stage_427(); void stage_428(); void stage_429(); void stage_430(); void stage_431();
void stage_432(); void stage_433(); void stage_434(); void stage_435(); void stage_436(); void stage_437(); void stage_438(); void stage_439();
void stage_440(); void stage_441(); void stage_442(); void stage_443(); void stage_444(); void stage_445(); void stage_446(); void stage_447();
void stage_448(); void stage_449(); void stage_450(); void stage_451(); void stage_452(); void stage_453(); void stage_454(); void stage_455();
void stage_456(); void stage_457(); void stage_458(); void stage_459(); void stage_460(); void stage_461(); void stage_462(); void stage_463();
void stage_464(); void stage_465(); void stage_466(); void stage_467(); void stage_468(); void stage_469(); void stage_470(); void stage_471();
void stage_472(); void stage_473(); void stage_474(); void stage_475(); void stage_476(); void stage_477(); void stage_478(); void stage_479();
void stage_480(); void stage_481(); void stage_482(); void stage_483(); void stage_484(); void stage_485(); void stage_486(); void stage_487();
void stage_488(); void stage_489(); void stage_490(); void stage_491(); void stage_492(); void stage_493(); void stage_494(); void stage_495();
void stage_496(); void stage_497(); void stage_498(); void stage_499(); void stage_500(); void stage_501(); void stage_502(); void stage_503();
void stage_504(); void stage_505(); void stage_506(); void stage_507(); void stage_508(); void stage_509(); void stage_510(); void stage_511();
void stage_512(); void stage_513(); void stage_514(); void stage_515(); void stage_516(); void stage_517(); void stage_518(); void stage_519();
void stage_520(); void stage_521(); void stage_522(); void stage_523(); void stage_524(); void stage_525(); void stage_526(); void stage_527();
void stage_528(); void stage_529(); void stage_530(); void stage_531(); void stage_532(); void stage_533(); void stage_534(); void stage_535();
void stage_536(); void stage_537(); void stage_538(); void stage_539(); void stage_540(); void stage_541(); void stage_542(); void stage_543();
void stage_544(); void stage_545(); void stage_546(); void stage_547(); void stage_548(); void stage_549(); void stage_550(); void stage_551();
void stage_552(); void stage_553(); void stage_554(); void stage_555(); void stage_556(); void stage_557(); void stage_558(); void stage_559();
void stage_560(); void stage_561(); void stage_562(); void stage_563(); void stage_564(); void stage_565(); void stage_566(); void stage_567();
void stage_568(); void stage_569(); void stage_570(); void stage_571(); void stage_572(); void stage_573(); void stage_574(); void stage_575();
void stage_576(); void stage_577(); void stage_578(); void stage_579(); void stage_580(); void stage_581(); void stage_582(); void stage_583();
void stage_584(); void stage_585(); void stage_586(); void stage_587(); void stage_588(); void stage_589(); void stage_590(); void stage_591();
void stage_592(); void stage_593(); void stage_594(); void stage_595(); void stage_596(); void stage_597(); void stage_598(); void stage_599();
void stage_600(); void stage_601(); void stage_602(); void stage_603(); void stage_604(); void stage_605(); void stage_606(); void stage_607();
void stage_608(); void stage_609(); void stage_610(); void stage_611(); void stage_612(); void stage_613(); void stage_614(); void stage_615();
void stage_616(); void stage_617(); void stage_618(); void stage_619(); void stage_620(); void stage_621(); void stage_622(); void stage_623();
void stage_624(); void stage_625(); void stage_626(); void stage_627(); void stage_628(); void stage_629(); void stage_630(); void stage_631();
void stage_632(); void stage_633(); void stage_634(); void stage_635(); void stage_636(); void stage_637(); void stage_638(); void stage_639();
void stage_640(); void stage_641(); void stage_642(); void stage_643(); void stage_644(); void stage_645(); void stage_646(); void stage_647();
void stage_648(); void stage_649(); void stage_650(); void stage_651(); void stage_652(); void stage_653(); void stage_654(); void stage_655();
void stage_656(); void stage_657(); void stage_658(); void stage_659(); void stage_660(); void stage_661(); void stage_662(); void stage_663();
void stage_664(); void stage_665(); void stage_666(); void stage_667(); void stage_668(); void stage_669(); void stage_670(); void stage_671();
void stage_672(); void stage_673(); void stage_674(); void stage_675(); void stage_676(); void stage_677(); void stage_678(); void stage_679();
void stage_680(); void stage_681(); void stage_682(); void stage_683(); void stage_684(); void stage_685(); void stage_686(); void stage_687();
void stage_688(); void stage_689(); void stage_690(); void stage_691(); void stage_692(); void stage_693(); void stage_694(); void stage_695();
void stage_696(); void stage_697(); void stage_698(); void stage_699(); void stage_700(); void stage_701(); void stage_702(); void stage_703();
void stage_704(); void stage_705(); void stage_706(); void stage_707(); void stage_708(); void stage_709(); void stage_710(); void stage_711();
void stage_712(); void stage_713(); void stage_714(); void stage_715(); void stage_716(); void stage_717(); void stage_718(); void stage_719();
void stage_720(); void stage_721(); void stage_722(); void stage_723(); void stage_724(); void stage_725(); void stage_726(); void stage_727();
void stage_728(); void stage_729(); void stage_730(); void stage_731(); void stage_732(); void stage_733(); void stage_734(); void stage_735();
void stage_736(); void stage_737(); void stage_738(); void stage_739(); void stage_740(); void stage_741(); void stage_742(); void stage_743();
void stage_744(); void stage_745(); void stage_746(); void stage_747(); void stage_748(); void stage_749(); void stage_750(); void stage_751();
void stage_752(); void stage_753(); void stage_754(); void stage_755(); void stage_756(); void stage_757(); void stage_758(); void stage_759();
void stage_760(); void stage_761(); void stage_762(); void stage_763(); void stage_764(); void stage_765(); void stage_766(); void stage_767();
void stage_768(); void stage_769(); void stage_770(); void stage_771(); void stage_772(); void stage_773(); void stage_774(); void stage_775();
void stage_776(); void stage_777(); void stage_778(); void stage_779(); void stage_780(); void stage_781(); void stage_782(); void stage_783();
void stage_784(); void stage_785(); void stage_786(); void stage_787(); void stage_788(); void stage_789(); void stage_790(); void stage_791();
void stage_792(); void stage_793(); void stage_794(); void stage_795(); void stage_796(); void stage_797(); void stage_798(); void stage_799();
void stage_800(); void stage_801(); void stage_802(); void stage_803(); void stage_804(); void stage_805(); void stage_806(); void stage_807();
void stage_808(); void stage_809(); void stage_810(); void stage_811(); void stage_812(); void stage_813(); void stage_814(); void stage_815();
void stage_816(); void stage_817(); void stage_818(); void stage_819(); void stage_820(); void stage_821(); void stage_822(); void stage_823();
void stage_824(); void stage_825(); void stage_826(); void stage_827(); void stage_828(); void stage_829(); void stage_830(); void stage_831();
void stage_832(); void stage_833(); void stage_834(); void stage_835(); void stage_836(); void stage_837(); void stage_838(); void stage_839();
void stage_840(); void stage_841(); void stage_842(); void stage_843(); void stage_844(); void stage_845(); void stage_846(); void stage_847();
void stage_848(); void stage_849(); void stage_850(); void stage_851(); void stage_852(); void stage_853(); void stage_854(); void stage_855();
void stage_856(); void stage_857(); void stage_858(); void stage_859(); void stage_860(); void stage_861(); void stage_862(); void stage_863();
void stage_864(); void stage_865(); void stage_866(); void stage_867(); void stage_868(); void stage_869(); void stage_870(); void stage_871();
void stage_872(); void stage_873(); void stage_874(); void stage_875(); void stage_876(); void stage_877(); void stage_878(); void stage_879();
void stage_880(); void stage_881(); void stage_882(); void stage_883(); void stage_884(); void stage_885(); void stage_886(); void stage_887();
void stage_888(); void stage_889(); void stage_890(); void stage_891(); void stage_892(); void stage_893(); void stage_894(); void stage_895();
void stage_896(); void stage_897(); void stage_898(); void stage_899(); void stage_900(); void stage_901(); void stage_902(); void stage_903();
void stage_904(); void stage_905(); void stage_906(); void stage_907(); void stage_908(); void stage_909(); void stage_910(); void stage_911();
void stage_912(); void stage_913(); void stage_914(); void stage_915(); void stage_916(); void stage_917(); void stage_918(); void stage_919();
void stage_920(); void stage_921(); void stage_922(); void stage_923(); void stage_924(); void stage_925(); void stage_926(); void stage_927();
void stage_928(); void stage_929(); void stage_930(); void stage_931(); void stage_932(); void stage_933(); void stage_934(); void stage_935();
void stage_936(); void stage_937(); void stage_938(); void stage_939(); void stage_940(); void stage_941(); void stage_942(); void stage_943();
void stage_944(); void stage_945(); void stage_946(); void stage_947(); void stage_948(); void stage_949(); void stage_950(); void stage_951();
void stage_952(); void stage_953(); void stage_954(); void stage_955(); void stage_956(); void stage_957(); void stage_958(); void stage_959();
void stage_960(); void stage_961(); void stage_962(); void stage_963(); void stage_964(); void stage_965(); void stage_966(); void stage_967();
void stage_968(); void stage_969(); void stage_970(); void stage_971(); void stage_972(); void stage_973(); void stage_974(); void stage_975();
void stage_976(); void stage_977(); void stage_978(); void stage_979(); void stage_980(); void stage_981(); void stage_982(); void stage_983();
void stage_984(); void stage_985(); void stage_986(); void stage_987(); void stage_988(); void stage_989(); void stage_990(); void stage_991();
void stage_992(); void stage_993(); void stage_994(); void stage_995(); void stage_996(); void stage_997(); void stage_998(); void stage_999();
void stage_1000(); void stage_1001(); void stage_1002(); void stage_1003(); void stage_1004(); void stage_1005(); void stage_1006(); void stage_1007();
void stage_1008(); void stage_1009(); void stage_1010(); void stage_1011(); void stage_1012(); void stage_1013(); void stage_1014(); void stage_1015();
void stage_1016(); void stage_1017(); void stage_1018(); void stage_1019(); void stage_1020(); void stage_1021(); void stage_1022(); void stage_1023();
void stage_1024(); void stage_1025(); void stage_1026(); void stage_1027(); void stage_1028(); void stage_1029(); void stage_1030(); void stage_1031();
void stage_1032(); void stage_1033(); void stage_1034(); void stage_1035(); void stage_1036(); void stage_1037(); void stage_1038(); void stage_1039();
void stage_1040(); void stage_1041(); void stage_1042(); void stage_1043(); void stage_1044(); void stage_1045(); void stage_1046(); void stage_1047();
void stage_1048(); void stage_1049(); void stage_1050(); void stage_1051(); void stage_1052(); void stage_1053(); void stage_1054(); void stage_1055();
void stage_1056(); void stage_1057(); void stage_1058(); void stage_1059(); void stage_1060(); void stage_1061(); void stage_1062(); void stage_1063();
void stage_1064(); void stage_1065(); void stage_1066(); void stage_1067(); void stage_1068(); void stage_1069(); void stage_1070(); void stage_1071();
void stage_1072(); void stage_1073(); void stage_1074(); void stage_1075(); void stage_1076(); void stage_1077(); void stage_1078(); void stage_1079();
void stage_1080(); void stage_1081(); void stage_1082(); void stage_1083(); void stage_1084(); void stage_1085(); void stage_1086(); void stage_1087();
void stage_1088(); void stage_1089(); void stage_1090(); void stage_1091(); void stage_1092(); void stage_1093(); void stage_1094(); void stage_1095();
void stage_1096(); void stage_1097(); void stage_1098(); void stage_1099(); void stage_1100(); void stage_1101(); void stage_1102(); void stage_1103();
void stage_1104(); void stage_1105(); void stage_1106(); void stage_1107(); void stage_1108(); void stage_1109(); void stage_1110(); void stage_1111();
void stage_1112(); void stage_1113(); void stage_1114(); void stage_1115(); void stage_1116(); void stage_1117(); void stage_1118(); void stage_1119();
void stage_1120(); void stage_1121(); void stage_1122(); void stage_1123(); void stage_1124(); void stage_1125(); void stage_1126(); void stage_1127();
void stage_1128(); void stage_1129(); void stage_1130(); void stage_1131(); void stage_1132(); void stage_1133(); void stage_1134(); void stage_1135();
void stage_1136(); void stage_1137(); void stage_1138(); void stage_1139(); void stage_1140(); void stage_1141(); void stage_1142(); void stage_1143();
void stage_1144(); void stage_1145(); void stage_1146(); void stage_1147(); void stage_1148(); void stage_1149(); void stage_1150(); void stage_1151();
void stage_1152(); void stage_1153(); void stage_1154(); void stage_1155(); void stage_1156(); void stage_1157(); void stage_1158(); void stage_1159();
void stage_1160(); void stage_1161(); void stage_1162(); void stage_1163(); void stage_1164(); void stage_1165(); void stage_1166(); void stage_1167();
void stage_1168(); void stage_1169(); void stage_1170(); void stage_1171(); void stage_1172(); void stage_1173(); void stage_1174(); void stage_1175();
void stage_1176(); void stage_1177(); void stage_1178(); void stage_1179(); void stage_1180(); void stage_1181(); void stage_1182(); void stage_1183();
void stage_1184(); void stage_1185(); void stage_1186(); void stage_1187(); void stage_1188(); void stage_1189(); void stage_1190(); void stage_1191();
void stage_1192(); void stage_1193(); void stage_1194(); void stage_1195(); void stage_1196(); void stage_1197(); void stage_1198(); void stage_1199();
void stage_1200(); void stage_1201(); void stage_1202(); void stage_1203(); void stage_1204(); void stage_1205(); void stage_1206(); void stage_1207();
void stage_1208(); void stage_1209(); void stage_1210(); void stage_1211(); void stage_1212(); void stage_1213(); void stage_1214(); void stage_1215();
void stage_1216(); void stage_1217(); void stage_1218(); void stage_1219(); void stage_1220(); void stage_1221(); void stage_1222(); void stage_1223();
void stage_1224(); void stage_1225(); void stage_1226(); void stage_1227(); void stage_1228(); void stage_1229(); void stage_1230(); void stage_1231();
void stage_1232(); void stage_1233(); void stage_1234(); void stage_1235(); void stage_1236(); void stage_1237(); void stage_1238(); void stage_1239();
void stage_1240(); void stage_1241(); void stage_1242(); void stage_1243(); void stage_1244(); void stage_1245(); void stage_1246(); void stage_1247();
void stage_1248(); void stage_1249(); void stage_1250(); void stage_1251(); void stage_1252(); void stage_1253(); void stage_1254(); void stage_1255();
void stage_1256(); void stage_1257(); void stage_1258(); void stage_1259(); void stage_1260(); void stage_1261(); void stage_1262(); void stage_1263();
void stage_1264(); void stage_1265(); void stage_1266(); void stage_1267(); void stage_1268(); void stage_1269(); void stage_1270(); void stage_1271();
void stage_1272(); void stage_1273(); void stage_1274(); void stage_1275(); void stage_1276(); void stage_1277(); void stage_1278(); void stage_1279();
void stage_1280(); void stage_1281(); void stage_1282(); void stage_1283(); void stage_1284(); void stage_1285(); void stage_1286(); void stage_1287();
void stage_1288(); void stage_1289(); void stage_1290(); void stage_1291(); void stage_1292(); void stage_1293(); void stage_1294(); void stage_1295();
void stage_1296(); void stage_1297(); void stage_1298(); void stage_1299(); void stage_1300(); void stage_1301(); void stage_1302(); void stage_1303();
void stage_1304(); void stage_1305(); void stage_1306(); void stage_1307(); void stage_1308(); void stage_1309(); void stage_1310(); void stage_1311();
void stage_1312(); void stage_1313(); void stage_1314(); void stage_1315(); void stage_1316(); void stage_1317(); void stage_1318(); void stage_1319();
void stage_1320(); void stage_1321(); void stage_1322(); void stage_1323(); void stage_1324(); void stage_1325(); void stage_1326(); void stage_1327();
void stage_1328(); void stage_1329(); void stage_1330(); void stage_1331(); void stage_1332(); void stage_1333(); void stage_1334(); void stage_1335();
void stage_1336(); void stage_1337(); void stage_1338(); void stage_1339(); void stage_1340(); void stage_1341(); void stage_1342(); void stage_1343();
void stage_1344(); void stage_1345(); void stage_1346(); void stage_1347(); void stage_1348(); void stage_1349(); void stage_1350(); void stage_1351();
void stage_1352(); void stage_1353(); void stage_1354(); void stage_1355(); void stage_1356(); void stage_1357(); void stage_1358(); void stage_1359();
void stage_1360(); void stage_1361(); void stage_1362(); void stage_1363(); void stage_1364(); void stage_1365(); void stage_1366(); void stage_1367();
void stage_1368(); void stage_1369(); void stage_1370(); void stage_1371(); void stage_1372(); void stage_1373(); void stage_1374(); void stage_1375();
void stage_1376(); void stage_1377(); void stage_1378(); void stage_1379(); void stage_1380(); void stage_1381(); void stage_1382(); void stage_1383();
void stage_1384(); void stage_1385(); void stage_1386(); void stage_1387(); void stage_1388(); void stage_1389(); void stage_1390(); void stage_1391();
void stage_1392(); void stage_1393(); void stage_1394(); void stage_1395(); void stage_1396(); void stage_1397(); void stage_1398(); void stage_1399();
void stage_1400(); void stage_1401(); void stage_1402(); void stage_1403(); void stage_1404(); void stage_1405(); void stage_1406(); void stage_1407();
void stage_1408(); void stage_1409(); void stage_1410(); void stage_1411(); void stage_1412(); void stage_1413(); void stage_1414(); void stage_1415();
void stage_1416(); void stage_1417(); void stage_1418(); void stage_1419(); void stage_1420(); void stage_1421(); void stage_1422(); void stage_1423();
void stage_1424(); void stage_1425(); void stage_1426(); void stage_1427(); void stage_1428(); void stage_1429(); void stage_1430(); void stage_1431();
void stage_1432(); void stage_1433(); void stage_1434(); void stage_1435(); void stage_1436(); void stage_1437(); void stage_1438(); void stage_1439();
void stage_1440(); void stage_1441(); void stage_1442(); void stage_1443(); void stage_1444(); void stage_1445(); void stage_1446(); void stage_1447();
void stage_1448(); void stage_1449(); void stage_1450(); void stage_1451(); void stage_1452(); void stage_1453(); void stage_1454(); void stage_1455();
void stage_1456(); void stage_1457(); void stage_1458(); void stage_1459(); void stage_1460(); void stage_1461(); void stage_1462(); void stage_1463();
void stage_1464(); void stage_1465(); void stage_1466(); void stage_1467(); void stage_1468(); void stage_1469(); void stage_1470(); void stage_1471();
void stage_1472(); void stage_1473(); void stage_1474(); void stage_1475(); void stage_1476(); void stage_1477(); void stage_1478(); void stage_1479();
void stage_1480(); void stage_1481(); void stage_1482(); void stage_1483(); void stage_1484(); void stage_1485(); void stage_1486(); void stage_1487();
void stage_1488(); void stage_1489(); void stage_1490(); void stage_1491(); void stage_1492(); void stage_1493(); void stage_1494(); void stage_1495();
void stage_1496(); void stage_1497(); void stage_1498(); void stage_1499(); void stage_1500(); void stage_1501(); void stage_1502(); void stage_1503();
void stage_1504(); void stage_1505(); void stage_1506(); void stage_1507(); void stage_1508(); void stage_1509(); void stage_1510(); void stage_1511();
void stage_1512(); void stage_1513(); void stage_1514(); void stage_1515(); void stage_1516(); void stage_1517(); void stage_1518(); void stage_1519();
void stage_1520(); void stage_1521(); void stage_1522(); void stage_1523(); void stage_1524(); void stage_1525(); void stage_1526(); void stage_1527();
void stage_1528(); void stage_1529(); void stage_1530(); void stage_1531(); void stage_1532(); void stage_1533(); void stage_1534(); void stage_1535();
void stage_1536(); void stage_1537(); void stage_1538(); void stage_1539(); void stage_1540(); void stage_1541(); void stage_1542(); void stage_1543();
void stage_1544(); void stage_1545(); void stage_1546(); void stage_1547(); void stage_1548(); void stage_1549(); void stage_1550(); void stage_1551();
void stage_1552(); void stage_1553(); void stage_1554(); void stage_1555(); void stage_1556(); void stage_1557(); void stage_1558(); void stage_1559();
void stage_1560(); void stage_1561(); void stage_1562(); void stage_1563(); void stage_1564(); void stage_1565(); void stage_1566(); void stage_1567();
void stage_1568(); void stage_1569(); void stage_1570(); void stage_1571(); void stage_1572(); void stage_1573(); void stage_1574(); void stage_1575();
void stage_1576(); void stage_1577(); void stage_1578(); void stage_1579(); void stage_1580(); void stage_1581(); void stage_1582(); void stage_1583();
void stage_1584(); void stage_1585(); void stage_1586(); void stage_1587(); void stage_1588(); void stage_1589(); void stage_1590(); void stage_1591();
void stage_1592(); void stage_1593(); void stage_1594(); void stage_1595(); void stage_1596(); void stage_1597(); void stage_1598(); void stage_1599();
void stage_1600(); void stage_1601(); void stage_1602(); void stage_1603(); void stage_1604(); void stage_1605(); void stage_1606(); void stage_1607();
void stage_1608(); void stage_1609(); void stage_1610(); void stage_1611(); void stage_1612(); void stage_1613(); void stage_1614(); void stage_1615();
void stage_1616(); void stage_1617(); void stage_1618(); void stage_1619(); void stage_1620(); void stage_1621(); void stage_1622(); void stage_1623();
void stage_1624(); void stage_1625(); void stage_1626(); void stage_1627(); void stage_1628(); void stage_1629(); void stage_1630(); void stage_1631();
void stage_1632(); void stage_1633(); void stage_1634(); void stage_1635(); void stage_1636(); void stage_1637(); void stage_1638(); void stage_1639();
void stage_1640(); void stage_1641(); void stage_1642(); void stage_1643(); void stage_1644(); void stage_1645(); void stage_1646(); void stage_1647();
void stage_1648(); void stage_1649(); void stage_1650(); void stage_1651(); void stage_1652(); void stage_1653(); void stage_1654(); void stage_1655();
void stage_1656(); void stage_1657(); void stage_1658(); void stage_1659(); void stage_1660(); void stage_1661(); void stage_1662(); void stage_1663();
void stage_1664(); void stage_1665(); void stage_1666(); void stage_1667(); void stage_1668(); void stage_1669(); void stage_1670(); void stage_1671();
void stage_1672(); void stage_1673(); void stage_1674(); void stage_1675(); void stage_1676(); void stage_1677(); void stage_1678(); void stage_1679();
void stage_1680(); void stage_1681(); void stage_1682(); void stage_1683(); void stage_1684(); void stage_1685(); void stage_1686(); void stage_1687();
void stage_1688(); void stage_1689(); void stage_1690(); void stage_1691(); void stage_1692(); void stage_1693(); void stage_1694(); void stage_1695();
void stage_1696(); void stage_1697(); void stage_1698(); void stage_1699(); void stage_1700(); void stage_1701(); void stage_1702(); void stage_1703();
void stage_1704(); void stage_1705(); void stage_1706(); void stage_1707(); void stage_1708(); void stage_1709(); void stage_1710(); void stage_1711();
void stage_1712(); void stage_1713(); void stage_1714(); void stage_1715(); void stage_1716(); void stage_1717(); void stage_1718(); void stage_1719();

unsigned long stage_base() {
    return (unsigned long)&stage_000;
}

unsigned long raw_stage_delta(int n) {
    unsigned long b = stage_base();
    switch (n) {
        case 0:  return (unsigned long)&stage_000 - b;
        case 1:  return (unsigned long)&stage_001 - b;
        case 2:  return (unsigned long)&stage_002 - b;
        case 3:  return (unsigned long)&stage_003 - b;
        case 4:  return (unsigned long)&stage_004 - b;
        case 5:  return (unsigned long)&stage_005 - b;
        case 6:  return (unsigned long)&stage_006 - b;
        case 7:  return (unsigned long)&stage_007 - b;
        case 8:  return (unsigned long)&stage_008 - b;
        case 9:  return (unsigned long)&stage_009 - b;
        case 10:  return (unsigned long)&stage_010 - b;
        case 11:  return (unsigned long)&stage_011 - b;
        case 12:  return (unsigned long)&stage_012 - b;
        case 13:  return (unsigned long)&stage_013 - b;
        case 14:  return (unsigned long)&stage_014 - b;
        case 15:  return (unsigned long)&stage_015 - b;
        case 16:  return (unsigned long)&stage_016 - b;
        case 17:  return (unsigned long)&stage_017 - b;
        case 18:  return (unsigned long)&stage_018 - b;
        case 19:  return (unsigned long)&stage_019 - b;
        case 20:  return (unsigned long)&stage_020 - b;
        case 21:  return (unsigned long)&stage_021 - b;
        case 22:  return (unsigned long)&stage_022 - b;
        case 23:  return (unsigned long)&stage_023 - b;
        case 24:  return (unsigned long)&stage_024 - b;
        case 25:  return (unsigned long)&stage_025 - b;
        case 26:  return (unsigned long)&stage_026 - b;
        case 27:  return (unsigned long)&stage_027 - b;
        case 28:  return (unsigned long)&stage_028 - b;
        case 29:  return (unsigned long)&stage_029 - b;
        case 30:  return (unsigned long)&stage_030 - b;
        case 31:  return (unsigned long)&stage_031 - b;
        case 32:  return (unsigned long)&stage_032 - b;
        case 33:  return (unsigned long)&stage_033 - b;
        case 34:  return (unsigned long)&stage_034 - b;
        case 35:  return (unsigned long)&stage_035 - b;
        case 36:  return (unsigned long)&stage_036 - b;
        case 37:  return (unsigned long)&stage_037 - b;
        case 38:  return (unsigned long)&stage_038 - b;
        case 39:  return (unsigned long)&stage_039 - b;
        case 40:  return (unsigned long)&stage_040 - b;
        case 41:  return (unsigned long)&stage_041 - b;
        case 42:  return (unsigned long)&stage_042 - b;
        case 43:  return (unsigned long)&stage_043 - b;
        case 44:  return (unsigned long)&stage_044 - b;
        case 45:  return (unsigned long)&stage_045 - b;
        case 46:  return (unsigned long)&stage_046 - b;
        case 47:  return (unsigned long)&stage_047 - b;
        case 48:  return (unsigned long)&stage_048 - b;
        case 49:  return (unsigned long)&stage_049 - b;
        case 50:  return (unsigned long)&stage_050 - b;
        case 51:  return (unsigned long)&stage_051 - b;
        case 52:  return (unsigned long)&stage_052 - b;
        case 53:  return (unsigned long)&stage_053 - b;
        case 54:  return (unsigned long)&stage_054 - b;
        case 55:  return (unsigned long)&stage_055 - b;
        case 56:  return (unsigned long)&stage_056 - b;
        case 57:  return (unsigned long)&stage_057 - b;
        case 58:  return (unsigned long)&stage_058 - b;
        case 59:  return (unsigned long)&stage_059 - b;
        case 60:  return (unsigned long)&stage_060 - b;
        case 61:  return (unsigned long)&stage_061 - b;
        case 62:  return (unsigned long)&stage_062 - b;
        case 63:  return (unsigned long)&stage_063 - b;
        case 64:  return (unsigned long)&stage_064 - b;
        case 65:  return (unsigned long)&stage_065 - b;
        case 66:  return (unsigned long)&stage_066 - b;
        case 67:  return (unsigned long)&stage_067 - b;
        case 68:  return (unsigned long)&stage_068 - b;
        case 69:  return (unsigned long)&stage_069 - b;
        case 70:  return (unsigned long)&stage_070 - b;
        case 71:  return (unsigned long)&stage_071 - b;
        case 72:  return (unsigned long)&stage_072 - b;
        case 73:  return (unsigned long)&stage_073 - b;
        case 74:  return (unsigned long)&stage_074 - b;
        case 75:  return (unsigned long)&stage_075 - b;
        case 76:  return (unsigned long)&stage_076 - b;
        case 77:  return (unsigned long)&stage_077 - b;
        case 78:  return (unsigned long)&stage_078 - b;
        case 79:  return (unsigned long)&stage_079 - b;
        case 80:  return (unsigned long)&stage_080 - b;
        case 81:  return (unsigned long)&stage_081 - b;
        case 82:  return (unsigned long)&stage_082 - b;
        case 83:  return (unsigned long)&stage_083 - b;
        case 84:  return (unsigned long)&stage_084 - b;
        case 85:  return (unsigned long)&stage_085 - b;
        case 86:  return (unsigned long)&stage_086 - b;
        case 87:  return (unsigned long)&stage_087 - b;
        case 88:  return (unsigned long)&stage_088 - b;
        case 89:  return (unsigned long)&stage_089 - b;
        case 90:  return (unsigned long)&stage_090 - b;
        case 91:  return (unsigned long)&stage_091 - b;
        case 92:  return (unsigned long)&stage_092 - b;
        case 93:  return (unsigned long)&stage_093 - b;
        case 94:  return (unsigned long)&stage_094 - b;
        case 95:  return (unsigned long)&stage_095 - b;
        case 96:  return (unsigned long)&stage_096 - b;
        case 97:  return (unsigned long)&stage_097 - b;
        case 98:  return (unsigned long)&stage_098 - b;
        case 99:  return (unsigned long)&stage_099 - b;
        case 100:  return (unsigned long)&stage_100 - b;
        case 101:  return (unsigned long)&stage_101 - b;
        case 102:  return (unsigned long)&stage_102 - b;
        case 103:  return (unsigned long)&stage_103 - b;
        case 104:  return (unsigned long)&stage_104 - b;
        case 105:  return (unsigned long)&stage_105 - b;
        case 106:  return (unsigned long)&stage_106 - b;
        case 107:  return (unsigned long)&stage_107 - b;
        case 108:  return (unsigned long)&stage_108 - b;
        case 109:  return (unsigned long)&stage_109 - b;
        case 110:  return (unsigned long)&stage_110 - b;
        case 111:  return (unsigned long)&stage_111 - b;
        case 112:  return (unsigned long)&stage_112 - b;
        case 113:  return (unsigned long)&stage_113 - b;
        case 114:  return (unsigned long)&stage_114 - b;
        case 115:  return (unsigned long)&stage_115 - b;
        case 116:  return (unsigned long)&stage_116 - b;
        case 117:  return (unsigned long)&stage_117 - b;
        case 118:  return (unsigned long)&stage_118 - b;
        case 119:  return (unsigned long)&stage_119 - b;
        case 120:  return (unsigned long)&stage_120 - b;
        case 121:  return (unsigned long)&stage_121 - b;
        case 122:  return (unsigned long)&stage_122 - b;
        case 123:  return (unsigned long)&stage_123 - b;
        case 124:  return (unsigned long)&stage_124 - b;
        case 125:  return (unsigned long)&stage_125 - b;
        case 126:  return (unsigned long)&stage_126 - b;
        case 127:  return (unsigned long)&stage_127 - b;
        case 128:  return (unsigned long)&stage_128 - b;
        case 129:  return (unsigned long)&stage_129 - b;
        case 130:  return (unsigned long)&stage_130 - b;
        case 131:  return (unsigned long)&stage_131 - b;
        case 132:  return (unsigned long)&stage_132 - b;
        case 133:  return (unsigned long)&stage_133 - b;
        case 134:  return (unsigned long)&stage_134 - b;
        case 135:  return (unsigned long)&stage_135 - b;
        case 136:  return (unsigned long)&stage_136 - b;
        case 137:  return (unsigned long)&stage_137 - b;
        case 138:  return (unsigned long)&stage_138 - b;
        case 139:  return (unsigned long)&stage_139 - b;
        case 140:  return (unsigned long)&stage_140 - b;
        case 141:  return (unsigned long)&stage_141 - b;
        case 142:  return (unsigned long)&stage_142 - b;
        case 143:  return (unsigned long)&stage_143 - b;
        case 144:  return (unsigned long)&stage_144 - b;
        case 145:  return (unsigned long)&stage_145 - b;
        case 146:  return (unsigned long)&stage_146 - b;
        case 147:  return (unsigned long)&stage_147 - b;
        case 148:  return (unsigned long)&stage_148 - b;
        case 149:  return (unsigned long)&stage_149 - b;
        case 150:  return (unsigned long)&stage_150 - b;
        case 151:  return (unsigned long)&stage_151 - b;
        case 152:  return (unsigned long)&stage_152 - b;
        case 153:  return (unsigned long)&stage_153 - b;
        case 154:  return (unsigned long)&stage_154 - b;
        case 155:  return (unsigned long)&stage_155 - b;
        case 156:  return (unsigned long)&stage_156 - b;
        case 157:  return (unsigned long)&stage_157 - b;
        case 158:  return (unsigned long)&stage_158 - b;
        case 159:  return (unsigned long)&stage_159 - b;
        case 160:  return (unsigned long)&stage_160 - b;
        case 161:  return (unsigned long)&stage_161 - b;
        case 162:  return (unsigned long)&stage_162 - b;
        case 163:  return (unsigned long)&stage_163 - b;
        case 164:  return (unsigned long)&stage_164 - b;
        case 165:  return (unsigned long)&stage_165 - b;
        case 166:  return (unsigned long)&stage_166 - b;
        case 167:  return (unsigned long)&stage_167 - b;
        case 168:  return (unsigned long)&stage_168 - b;
        case 169:  return (unsigned long)&stage_169 - b;
        case 170:  return (unsigned long)&stage_170 - b;
        case 171:  return (unsigned long)&stage_171 - b;
        case 172:  return (unsigned long)&stage_172 - b;
        case 173:  return (unsigned long)&stage_173 - b;
        case 174:  return (unsigned long)&stage_174 - b;
        case 175:  return (unsigned long)&stage_175 - b;
        case 176:  return (unsigned long)&stage_176 - b;
        case 177:  return (unsigned long)&stage_177 - b;
        case 178:  return (unsigned long)&stage_178 - b;
        case 179:  return (unsigned long)&stage_179 - b;
        case 180:  return (unsigned long)&stage_180 - b;
        case 181:  return (unsigned long)&stage_181 - b;
        case 182:  return (unsigned long)&stage_182 - b;
        case 183:  return (unsigned long)&stage_183 - b;
        case 184:  return (unsigned long)&stage_184 - b;
        case 185:  return (unsigned long)&stage_185 - b;
        case 186:  return (unsigned long)&stage_186 - b;
        case 187:  return (unsigned long)&stage_187 - b;
        case 188:  return (unsigned long)&stage_188 - b;
        case 189:  return (unsigned long)&stage_189 - b;
        case 190:  return (unsigned long)&stage_190 - b;
        case 191:  return (unsigned long)&stage_191 - b;
        case 192:  return (unsigned long)&stage_192 - b;
        case 193:  return (unsigned long)&stage_193 - b;
        case 194:  return (unsigned long)&stage_194 - b;
        case 195:  return (unsigned long)&stage_195 - b;
        case 196:  return (unsigned long)&stage_196 - b;
        case 197:  return (unsigned long)&stage_197 - b;
        case 198:  return (unsigned long)&stage_198 - b;
        case 199:  return (unsigned long)&stage_199 - b;
        case 200:  return (unsigned long)&stage_200 - b;
        case 201:  return (unsigned long)&stage_201 - b;
        case 202:  return (unsigned long)&stage_202 - b;
        case 203:  return (unsigned long)&stage_203 - b;
        case 204:  return (unsigned long)&stage_204 - b;
        case 205:  return (unsigned long)&stage_205 - b;
        case 206:  return (unsigned long)&stage_206 - b;
        case 207:  return (unsigned long)&stage_207 - b;
        case 208:  return (unsigned long)&stage_208 - b;
        case 209:  return (unsigned long)&stage_209 - b;
        case 210:  return (unsigned long)&stage_210 - b;
        case 211:  return (unsigned long)&stage_211 - b;
        case 212:  return (unsigned long)&stage_212 - b;
        case 213:  return (unsigned long)&stage_213 - b;
        case 214:  return (unsigned long)&stage_214 - b;
        case 215:  return (unsigned long)&stage_215 - b;
        case 216:  return (unsigned long)&stage_216 - b;
        case 217:  return (unsigned long)&stage_217 - b;
        case 218:  return (unsigned long)&stage_218 - b;
        case 219:  return (unsigned long)&stage_219 - b;
        case 220:  return (unsigned long)&stage_220 - b;
        case 221:  return (unsigned long)&stage_221 - b;
        case 222:  return (unsigned long)&stage_222 - b;
        case 223:  return (unsigned long)&stage_223 - b;
        case 224:  return (unsigned long)&stage_224 - b;
        case 225:  return (unsigned long)&stage_225 - b;
        case 226:  return (unsigned long)&stage_226 - b;
        case 227:  return (unsigned long)&stage_227 - b;
        case 228:  return (unsigned long)&stage_228 - b;
        case 229:  return (unsigned long)&stage_229 - b;
        case 230:  return (unsigned long)&stage_230 - b;
        case 231:  return (unsigned long)&stage_231 - b;
        case 232:  return (unsigned long)&stage_232 - b;
        case 233:  return (unsigned long)&stage_233 - b;
        case 234:  return (unsigned long)&stage_234 - b;
        case 235:  return (unsigned long)&stage_235 - b;
        case 236:  return (unsigned long)&stage_236 - b;
        case 237:  return (unsigned long)&stage_237 - b;
        case 238:  return (unsigned long)&stage_238 - b;
        case 239:  return (unsigned long)&stage_239 - b;
        case 240:  return (unsigned long)&stage_240 - b;
        case 241:  return (unsigned long)&stage_241 - b;
        case 242:  return (unsigned long)&stage_242 - b;
        case 243:  return (unsigned long)&stage_243 - b;
        case 244:  return (unsigned long)&stage_244 - b;
        case 245:  return (unsigned long)&stage_245 - b;
        case 246:  return (unsigned long)&stage_246 - b;
        case 247:  return (unsigned long)&stage_247 - b;
        case 248:  return (unsigned long)&stage_248 - b;
        case 249:  return (unsigned long)&stage_249 - b;
        case 250:  return (unsigned long)&stage_250 - b;
        case 251:  return (unsigned long)&stage_251 - b;
        case 252:  return (unsigned long)&stage_252 - b;
        case 253:  return (unsigned long)&stage_253 - b;
        case 254:  return (unsigned long)&stage_254 - b;
        case 255:  return (unsigned long)&stage_255 - b;
        case 256:  return (unsigned long)&stage_256 - b;
        case 257:  return (unsigned long)&stage_257 - b;
        case 258:  return (unsigned long)&stage_258 - b;
        case 259:  return (unsigned long)&stage_259 - b;
        case 260:  return (unsigned long)&stage_260 - b;
        case 261:  return (unsigned long)&stage_261 - b;
        case 262:  return (unsigned long)&stage_262 - b;
        case 263:  return (unsigned long)&stage_263 - b;
        case 264:  return (unsigned long)&stage_264 - b;
        case 265:  return (unsigned long)&stage_265 - b;
        case 266:  return (unsigned long)&stage_266 - b;
        case 267:  return (unsigned long)&stage_267 - b;
        case 268:  return (unsigned long)&stage_268 - b;
        case 269:  return (unsigned long)&stage_269 - b;
        case 270:  return (unsigned long)&stage_270 - b;
        case 271:  return (unsigned long)&stage_271 - b;
        case 272:  return (unsigned long)&stage_272 - b;
        case 273:  return (unsigned long)&stage_273 - b;
        case 274:  return (unsigned long)&stage_274 - b;
        case 275:  return (unsigned long)&stage_275 - b;
        case 276:  return (unsigned long)&stage_276 - b;
        case 277:  return (unsigned long)&stage_277 - b;
        case 278:  return (unsigned long)&stage_278 - b;
        case 279:  return (unsigned long)&stage_279 - b;
        case 280:  return (unsigned long)&stage_280 - b;
        case 281:  return (unsigned long)&stage_281 - b;
        case 282:  return (unsigned long)&stage_282 - b;
        case 283:  return (unsigned long)&stage_283 - b;
        case 284:  return (unsigned long)&stage_284 - b;
        case 285:  return (unsigned long)&stage_285 - b;
        case 286:  return (unsigned long)&stage_286 - b;
        case 287:  return (unsigned long)&stage_287 - b;
        case 288:  return (unsigned long)&stage_288 - b;
        case 289:  return (unsigned long)&stage_289 - b;
        case 290:  return (unsigned long)&stage_290 - b;
        case 291:  return (unsigned long)&stage_291 - b;
        case 292:  return (unsigned long)&stage_292 - b;
        case 293:  return (unsigned long)&stage_293 - b;
        case 294:  return (unsigned long)&stage_294 - b;
        case 295:  return (unsigned long)&stage_295 - b;
        case 296:  return (unsigned long)&stage_296 - b;
        case 297:  return (unsigned long)&stage_297 - b;
        case 298:  return (unsigned long)&stage_298 - b;
        case 299:  return (unsigned long)&stage_299 - b;
        case 300:  return (unsigned long)&stage_300 - b;
        case 301:  return (unsigned long)&stage_301 - b;
        case 302:  return (unsigned long)&stage_302 - b;
        case 303:  return (unsigned long)&stage_303 - b;
        case 304:  return (unsigned long)&stage_304 - b;
        case 305:  return (unsigned long)&stage_305 - b;
        case 306:  return (unsigned long)&stage_306 - b;
        case 307:  return (unsigned long)&stage_307 - b;
        case 308:  return (unsigned long)&stage_308 - b;
        case 309:  return (unsigned long)&stage_309 - b;
        case 310:  return (unsigned long)&stage_310 - b;
        case 311:  return (unsigned long)&stage_311 - b;
        case 312:  return (unsigned long)&stage_312 - b;
        case 313:  return (unsigned long)&stage_313 - b;
        case 314:  return (unsigned long)&stage_314 - b;
        case 315:  return (unsigned long)&stage_315 - b;
        case 316:  return (unsigned long)&stage_316 - b;
        case 317:  return (unsigned long)&stage_317 - b;
        case 318:  return (unsigned long)&stage_318 - b;
        case 319:  return (unsigned long)&stage_319 - b;
        case 320:  return (unsigned long)&stage_320 - b;
        case 321:  return (unsigned long)&stage_321 - b;
        case 322:  return (unsigned long)&stage_322 - b;
        case 323:  return (unsigned long)&stage_323 - b;
        case 324:  return (unsigned long)&stage_324 - b;
        case 325:  return (unsigned long)&stage_325 - b;
        case 326:  return (unsigned long)&stage_326 - b;
        case 327:  return (unsigned long)&stage_327 - b;
        case 328:  return (unsigned long)&stage_328 - b;
        case 329:  return (unsigned long)&stage_329 - b;
        case 330:  return (unsigned long)&stage_330 - b;
        case 331:  return (unsigned long)&stage_331 - b;
        case 332:  return (unsigned long)&stage_332 - b;
        case 333:  return (unsigned long)&stage_333 - b;
        case 334:  return (unsigned long)&stage_334 - b;
        case 335:  return (unsigned long)&stage_335 - b;
        case 336:  return (unsigned long)&stage_336 - b;
        case 337:  return (unsigned long)&stage_337 - b;
        case 338:  return (unsigned long)&stage_338 - b;
        case 339:  return (unsigned long)&stage_339 - b;
        case 340:  return (unsigned long)&stage_340 - b;
        case 341:  return (unsigned long)&stage_341 - b;
        case 342:  return (unsigned long)&stage_342 - b;
        case 343:  return (unsigned long)&stage_343 - b;
        case 344:  return (unsigned long)&stage_344 - b;
        case 345:  return (unsigned long)&stage_345 - b;
        case 346:  return (unsigned long)&stage_346 - b;
        case 347:  return (unsigned long)&stage_347 - b;
        case 348:  return (unsigned long)&stage_348 - b;
        case 349:  return (unsigned long)&stage_349 - b;
        case 350:  return (unsigned long)&stage_350 - b;
        case 351:  return (unsigned long)&stage_351 - b;
        case 352:  return (unsigned long)&stage_352 - b;
        case 353:  return (unsigned long)&stage_353 - b;
        case 354:  return (unsigned long)&stage_354 - b;
        case 355:  return (unsigned long)&stage_355 - b;
        case 356:  return (unsigned long)&stage_356 - b;
        case 357:  return (unsigned long)&stage_357 - b;
        case 358:  return (unsigned long)&stage_358 - b;
        case 359:  return (unsigned long)&stage_359 - b;
        case 360:  return (unsigned long)&stage_360 - b;
        case 361:  return (unsigned long)&stage_361 - b;
        case 362:  return (unsigned long)&stage_362 - b;
        case 363:  return (unsigned long)&stage_363 - b;
        case 364:  return (unsigned long)&stage_364 - b;
        case 365:  return (unsigned long)&stage_365 - b;
        case 366:  return (unsigned long)&stage_366 - b;
        case 367:  return (unsigned long)&stage_367 - b;
        case 368:  return (unsigned long)&stage_368 - b;
        case 369:  return (unsigned long)&stage_369 - b;
        case 370:  return (unsigned long)&stage_370 - b;
        case 371:  return (unsigned long)&stage_371 - b;
        case 372:  return (unsigned long)&stage_372 - b;
        case 373:  return (unsigned long)&stage_373 - b;
        case 374:  return (unsigned long)&stage_374 - b;
        case 375:  return (unsigned long)&stage_375 - b;
        case 376:  return (unsigned long)&stage_376 - b;
        case 377:  return (unsigned long)&stage_377 - b;
        case 378:  return (unsigned long)&stage_378 - b;
        case 379:  return (unsigned long)&stage_379 - b;
        case 380:  return (unsigned long)&stage_380 - b;
        case 381:  return (unsigned long)&stage_381 - b;
        case 382:  return (unsigned long)&stage_382 - b;
        case 383:  return (unsigned long)&stage_383 - b;
        case 384:  return (unsigned long)&stage_384 - b;
        case 385:  return (unsigned long)&stage_385 - b;
        case 386:  return (unsigned long)&stage_386 - b;
        case 387:  return (unsigned long)&stage_387 - b;
        case 388:  return (unsigned long)&stage_388 - b;
        case 389:  return (unsigned long)&stage_389 - b;
        case 390:  return (unsigned long)&stage_390 - b;
        case 391:  return (unsigned long)&stage_391 - b;
        case 392:  return (unsigned long)&stage_392 - b;
        case 393:  return (unsigned long)&stage_393 - b;
        case 394:  return (unsigned long)&stage_394 - b;
        case 395:  return (unsigned long)&stage_395 - b;
        case 396:  return (unsigned long)&stage_396 - b;
        case 397:  return (unsigned long)&stage_397 - b;
        case 398:  return (unsigned long)&stage_398 - b;
        case 399:  return (unsigned long)&stage_399 - b;
        case 400:  return (unsigned long)&stage_400 - b;
        case 401:  return (unsigned long)&stage_401 - b;
        case 402:  return (unsigned long)&stage_402 - b;
        case 403:  return (unsigned long)&stage_403 - b;
        case 404:  return (unsigned long)&stage_404 - b;
        case 405:  return (unsigned long)&stage_405 - b;
        case 406:  return (unsigned long)&stage_406 - b;
        case 407:  return (unsigned long)&stage_407 - b;
        case 408:  return (unsigned long)&stage_408 - b;
        case 409:  return (unsigned long)&stage_409 - b;
        case 410:  return (unsigned long)&stage_410 - b;
        case 411:  return (unsigned long)&stage_411 - b;
        case 412:  return (unsigned long)&stage_412 - b;
        case 413:  return (unsigned long)&stage_413 - b;
        case 414:  return (unsigned long)&stage_414 - b;
        case 415:  return (unsigned long)&stage_415 - b;
        case 416:  return (unsigned long)&stage_416 - b;
        case 417:  return (unsigned long)&stage_417 - b;
        case 418:  return (unsigned long)&stage_418 - b;
        case 419:  return (unsigned long)&stage_419 - b;
        case 420:  return (unsigned long)&stage_420 - b;
        case 421:  return (unsigned long)&stage_421 - b;
        case 422:  return (unsigned long)&stage_422 - b;
        case 423:  return (unsigned long)&stage_423 - b;
        case 424:  return (unsigned long)&stage_424 - b;
        case 425:  return (unsigned long)&stage_425 - b;
        case 426:  return (unsigned long)&stage_426 - b;
        case 427:  return (unsigned long)&stage_427 - b;
        case 428:  return (unsigned long)&stage_428 - b;
        case 429:  return (unsigned long)&stage_429 - b;
        case 430:  return (unsigned long)&stage_430 - b;
        case 431:  return (unsigned long)&stage_431 - b;
        case 432:  return (unsigned long)&stage_432 - b;
        case 433:  return (unsigned long)&stage_433 - b;
        case 434:  return (unsigned long)&stage_434 - b;
        case 435:  return (unsigned long)&stage_435 - b;
        case 436:  return (unsigned long)&stage_436 - b;
        case 437:  return (unsigned long)&stage_437 - b;
        case 438:  return (unsigned long)&stage_438 - b;
        case 439:  return (unsigned long)&stage_439 - b;
        case 440:  return (unsigned long)&stage_440 - b;
        case 441:  return (unsigned long)&stage_441 - b;
        case 442:  return (unsigned long)&stage_442 - b;
        case 443:  return (unsigned long)&stage_443 - b;
        case 444:  return (unsigned long)&stage_444 - b;
        case 445:  return (unsigned long)&stage_445 - b;
        case 446:  return (unsigned long)&stage_446 - b;
        case 447:  return (unsigned long)&stage_447 - b;
        case 448:  return (unsigned long)&stage_448 - b;
        case 449:  return (unsigned long)&stage_449 - b;
        case 450:  return (unsigned long)&stage_450 - b;
        case 451:  return (unsigned long)&stage_451 - b;
        case 452:  return (unsigned long)&stage_452 - b;
        case 453:  return (unsigned long)&stage_453 - b;
        case 454:  return (unsigned long)&stage_454 - b;
        case 455:  return (unsigned long)&stage_455 - b;
        case 456:  return (unsigned long)&stage_456 - b;
        case 457:  return (unsigned long)&stage_457 - b;
        case 458:  return (unsigned long)&stage_458 - b;
        case 459:  return (unsigned long)&stage_459 - b;
        case 460:  return (unsigned long)&stage_460 - b;
        case 461:  return (unsigned long)&stage_461 - b;
        case 462:  return (unsigned long)&stage_462 - b;
        case 463:  return (unsigned long)&stage_463 - b;
        case 464:  return (unsigned long)&stage_464 - b;
        case 465:  return (unsigned long)&stage_465 - b;
        case 466:  return (unsigned long)&stage_466 - b;
        case 467:  return (unsigned long)&stage_467 - b;
        case 468:  return (unsigned long)&stage_468 - b;
        case 469:  return (unsigned long)&stage_469 - b;
        case 470:  return (unsigned long)&stage_470 - b;
        case 471:  return (unsigned long)&stage_471 - b;
        case 472:  return (unsigned long)&stage_472 - b;
        case 473:  return (unsigned long)&stage_473 - b;
        case 474:  return (unsigned long)&stage_474 - b;
        case 475:  return (unsigned long)&stage_475 - b;
        case 476:  return (unsigned long)&stage_476 - b;
        case 477:  return (unsigned long)&stage_477 - b;
        case 478:  return (unsigned long)&stage_478 - b;
        case 479:  return (unsigned long)&stage_479 - b;
        case 480:  return (unsigned long)&stage_480 - b;
        case 481:  return (unsigned long)&stage_481 - b;
        case 482:  return (unsigned long)&stage_482 - b;
        case 483:  return (unsigned long)&stage_483 - b;
        case 484:  return (unsigned long)&stage_484 - b;
        case 485:  return (unsigned long)&stage_485 - b;
        case 486:  return (unsigned long)&stage_486 - b;
        case 487:  return (unsigned long)&stage_487 - b;
        case 488:  return (unsigned long)&stage_488 - b;
        case 489:  return (unsigned long)&stage_489 - b;
        case 490:  return (unsigned long)&stage_490 - b;
        case 491:  return (unsigned long)&stage_491 - b;
        case 492:  return (unsigned long)&stage_492 - b;
        case 493:  return (unsigned long)&stage_493 - b;
        case 494:  return (unsigned long)&stage_494 - b;
        case 495:  return (unsigned long)&stage_495 - b;
        case 496:  return (unsigned long)&stage_496 - b;
        case 497:  return (unsigned long)&stage_497 - b;
        case 498:  return (unsigned long)&stage_498 - b;
        case 499:  return (unsigned long)&stage_499 - b;
        case 500:  return (unsigned long)&stage_500 - b;
        case 501:  return (unsigned long)&stage_501 - b;
        case 502:  return (unsigned long)&stage_502 - b;
        case 503:  return (unsigned long)&stage_503 - b;
        case 504:  return (unsigned long)&stage_504 - b;
        case 505:  return (unsigned long)&stage_505 - b;
        case 506:  return (unsigned long)&stage_506 - b;
        case 507:  return (unsigned long)&stage_507 - b;
        case 508:  return (unsigned long)&stage_508 - b;
        case 509:  return (unsigned long)&stage_509 - b;
        case 510:  return (unsigned long)&stage_510 - b;
        case 511:  return (unsigned long)&stage_511 - b;
        case 512:  return (unsigned long)&stage_512 - b;
        case 513:  return (unsigned long)&stage_513 - b;
        case 514:  return (unsigned long)&stage_514 - b;
        case 515:  return (unsigned long)&stage_515 - b;
        case 516:  return (unsigned long)&stage_516 - b;
        case 517:  return (unsigned long)&stage_517 - b;
        case 518:  return (unsigned long)&stage_518 - b;
        case 519:  return (unsigned long)&stage_519 - b;
        case 520:  return (unsigned long)&stage_520 - b;
        case 521:  return (unsigned long)&stage_521 - b;
        case 522:  return (unsigned long)&stage_522 - b;
        case 523:  return (unsigned long)&stage_523 - b;
        case 524:  return (unsigned long)&stage_524 - b;
        case 525:  return (unsigned long)&stage_525 - b;
        case 526:  return (unsigned long)&stage_526 - b;
        case 527:  return (unsigned long)&stage_527 - b;
        case 528:  return (unsigned long)&stage_528 - b;
        case 529:  return (unsigned long)&stage_529 - b;
        case 530:  return (unsigned long)&stage_530 - b;
        case 531:  return (unsigned long)&stage_531 - b;
        case 532:  return (unsigned long)&stage_532 - b;
        case 533:  return (unsigned long)&stage_533 - b;
        case 534:  return (unsigned long)&stage_534 - b;
        case 535:  return (unsigned long)&stage_535 - b;
        case 536:  return (unsigned long)&stage_536 - b;
        case 537:  return (unsigned long)&stage_537 - b;
        case 538:  return (unsigned long)&stage_538 - b;
        case 539:  return (unsigned long)&stage_539 - b;
        case 540:  return (unsigned long)&stage_540 - b;
        case 541:  return (unsigned long)&stage_541 - b;
        case 542:  return (unsigned long)&stage_542 - b;
        case 543:  return (unsigned long)&stage_543 - b;
        case 544:  return (unsigned long)&stage_544 - b;
        case 545:  return (unsigned long)&stage_545 - b;
        case 546:  return (unsigned long)&stage_546 - b;
        case 547:  return (unsigned long)&stage_547 - b;
        case 548:  return (unsigned long)&stage_548 - b;
        case 549:  return (unsigned long)&stage_549 - b;
        case 550:  return (unsigned long)&stage_550 - b;
        case 551:  return (unsigned long)&stage_551 - b;
        case 552:  return (unsigned long)&stage_552 - b;
        case 553:  return (unsigned long)&stage_553 - b;
        case 554:  return (unsigned long)&stage_554 - b;
        case 555:  return (unsigned long)&stage_555 - b;
        case 556:  return (unsigned long)&stage_556 - b;
        case 557:  return (unsigned long)&stage_557 - b;
        case 558:  return (unsigned long)&stage_558 - b;
        case 559:  return (unsigned long)&stage_559 - b;
        case 560:  return (unsigned long)&stage_560 - b;
        case 561:  return (unsigned long)&stage_561 - b;
        case 562:  return (unsigned long)&stage_562 - b;
        case 563:  return (unsigned long)&stage_563 - b;
        case 564:  return (unsigned long)&stage_564 - b;
        case 565:  return (unsigned long)&stage_565 - b;
        case 566:  return (unsigned long)&stage_566 - b;
        case 567:  return (unsigned long)&stage_567 - b;
        case 568:  return (unsigned long)&stage_568 - b;
        case 569:  return (unsigned long)&stage_569 - b;
        case 570:  return (unsigned long)&stage_570 - b;
        case 571:  return (unsigned long)&stage_571 - b;
        case 572:  return (unsigned long)&stage_572 - b;
        case 573:  return (unsigned long)&stage_573 - b;
        case 574:  return (unsigned long)&stage_574 - b;
        case 575:  return (unsigned long)&stage_575 - b;
        case 576:  return (unsigned long)&stage_576 - b;
        case 577:  return (unsigned long)&stage_577 - b;
        case 578:  return (unsigned long)&stage_578 - b;
        case 579:  return (unsigned long)&stage_579 - b;
        case 580:  return (unsigned long)&stage_580 - b;
        case 581:  return (unsigned long)&stage_581 - b;
        case 582:  return (unsigned long)&stage_582 - b;
        case 583:  return (unsigned long)&stage_583 - b;
        case 584:  return (unsigned long)&stage_584 - b;
        case 585:  return (unsigned long)&stage_585 - b;
        case 586:  return (unsigned long)&stage_586 - b;
        case 587:  return (unsigned long)&stage_587 - b;
        case 588:  return (unsigned long)&stage_588 - b;
        case 589:  return (unsigned long)&stage_589 - b;
        case 590:  return (unsigned long)&stage_590 - b;
        case 591:  return (unsigned long)&stage_591 - b;
        case 592:  return (unsigned long)&stage_592 - b;
        case 593:  return (unsigned long)&stage_593 - b;
        case 594:  return (unsigned long)&stage_594 - b;
        case 595:  return (unsigned long)&stage_595 - b;
        case 596:  return (unsigned long)&stage_596 - b;
        case 597:  return (unsigned long)&stage_597 - b;
        case 598:  return (unsigned long)&stage_598 - b;
        case 599:  return (unsigned long)&stage_599 - b;
        case 600:  return (unsigned long)&stage_600 - b;
        case 601:  return (unsigned long)&stage_601 - b;
        case 602:  return (unsigned long)&stage_602 - b;
        case 603:  return (unsigned long)&stage_603 - b;
        case 604:  return (unsigned long)&stage_604 - b;
        case 605:  return (unsigned long)&stage_605 - b;
        case 606:  return (unsigned long)&stage_606 - b;
        case 607:  return (unsigned long)&stage_607 - b;
        case 608:  return (unsigned long)&stage_608 - b;
        case 609:  return (unsigned long)&stage_609 - b;
        case 610:  return (unsigned long)&stage_610 - b;
        case 611:  return (unsigned long)&stage_611 - b;
        case 612:  return (unsigned long)&stage_612 - b;
        case 613:  return (unsigned long)&stage_613 - b;
        case 614:  return (unsigned long)&stage_614 - b;
        case 615:  return (unsigned long)&stage_615 - b;
        case 616:  return (unsigned long)&stage_616 - b;
        case 617:  return (unsigned long)&stage_617 - b;
        case 618:  return (unsigned long)&stage_618 - b;
        case 619:  return (unsigned long)&stage_619 - b;
        case 620:  return (unsigned long)&stage_620 - b;
        case 621:  return (unsigned long)&stage_621 - b;
        case 622:  return (unsigned long)&stage_622 - b;
        case 623:  return (unsigned long)&stage_623 - b;
        case 624:  return (unsigned long)&stage_624 - b;
        case 625:  return (unsigned long)&stage_625 - b;
        case 626:  return (unsigned long)&stage_626 - b;
        case 627:  return (unsigned long)&stage_627 - b;
        case 628:  return (unsigned long)&stage_628 - b;
        case 629:  return (unsigned long)&stage_629 - b;
        case 630:  return (unsigned long)&stage_630 - b;
        case 631:  return (unsigned long)&stage_631 - b;
        case 632:  return (unsigned long)&stage_632 - b;
        case 633:  return (unsigned long)&stage_633 - b;
        case 634:  return (unsigned long)&stage_634 - b;
        case 635:  return (unsigned long)&stage_635 - b;
        case 636:  return (unsigned long)&stage_636 - b;
        case 637:  return (unsigned long)&stage_637 - b;
        case 638:  return (unsigned long)&stage_638 - b;
        case 639:  return (unsigned long)&stage_639 - b;
        case 640:  return (unsigned long)&stage_640 - b;
        case 641:  return (unsigned long)&stage_641 - b;
        case 642:  return (unsigned long)&stage_642 - b;
        case 643:  return (unsigned long)&stage_643 - b;
        case 644:  return (unsigned long)&stage_644 - b;
        case 645:  return (unsigned long)&stage_645 - b;
        case 646:  return (unsigned long)&stage_646 - b;
        case 647:  return (unsigned long)&stage_647 - b;
        case 648:  return (unsigned long)&stage_648 - b;
        case 649:  return (unsigned long)&stage_649 - b;
        case 650:  return (unsigned long)&stage_650 - b;
        case 651:  return (unsigned long)&stage_651 - b;
        case 652:  return (unsigned long)&stage_652 - b;
        case 653:  return (unsigned long)&stage_653 - b;
        case 654:  return (unsigned long)&stage_654 - b;
        case 655:  return (unsigned long)&stage_655 - b;
        case 656:  return (unsigned long)&stage_656 - b;
        case 657:  return (unsigned long)&stage_657 - b;
        case 658:  return (unsigned long)&stage_658 - b;
        case 659:  return (unsigned long)&stage_659 - b;
        case 660:  return (unsigned long)&stage_660 - b;
        case 661:  return (unsigned long)&stage_661 - b;
        case 662:  return (unsigned long)&stage_662 - b;
        case 663:  return (unsigned long)&stage_663 - b;
        case 664:  return (unsigned long)&stage_664 - b;
        case 665:  return (unsigned long)&stage_665 - b;
        case 666:  return (unsigned long)&stage_666 - b;
        case 667:  return (unsigned long)&stage_667 - b;
        case 668:  return (unsigned long)&stage_668 - b;
        case 669:  return (unsigned long)&stage_669 - b;
        case 670:  return (unsigned long)&stage_670 - b;
        case 671:  return (unsigned long)&stage_671 - b;
        case 672:  return (unsigned long)&stage_672 - b;
        case 673:  return (unsigned long)&stage_673 - b;
        case 674:  return (unsigned long)&stage_674 - b;
        case 675:  return (unsigned long)&stage_675 - b;
        case 676:  return (unsigned long)&stage_676 - b;
        case 677:  return (unsigned long)&stage_677 - b;
        case 678:  return (unsigned long)&stage_678 - b;
        case 679:  return (unsigned long)&stage_679 - b;
        case 680:  return (unsigned long)&stage_680 - b;
        case 681:  return (unsigned long)&stage_681 - b;
        case 682:  return (unsigned long)&stage_682 - b;
        case 683:  return (unsigned long)&stage_683 - b;
        case 684:  return (unsigned long)&stage_684 - b;
        case 685:  return (unsigned long)&stage_685 - b;
        case 686:  return (unsigned long)&stage_686 - b;
        case 687:  return (unsigned long)&stage_687 - b;
        case 688:  return (unsigned long)&stage_688 - b;
        case 689:  return (unsigned long)&stage_689 - b;
        case 690:  return (unsigned long)&stage_690 - b;
        case 691:  return (unsigned long)&stage_691 - b;
        case 692:  return (unsigned long)&stage_692 - b;
        case 693:  return (unsigned long)&stage_693 - b;
        case 694:  return (unsigned long)&stage_694 - b;
        case 695:  return (unsigned long)&stage_695 - b;
        case 696:  return (unsigned long)&stage_696 - b;
        case 697:  return (unsigned long)&stage_697 - b;
        case 698:  return (unsigned long)&stage_698 - b;
        case 699:  return (unsigned long)&stage_699 - b;
        case 700:  return (unsigned long)&stage_700 - b;
        case 701:  return (unsigned long)&stage_701 - b;
        case 702:  return (unsigned long)&stage_702 - b;
        case 703:  return (unsigned long)&stage_703 - b;
        case 704:  return (unsigned long)&stage_704 - b;
        case 705:  return (unsigned long)&stage_705 - b;
        case 706:  return (unsigned long)&stage_706 - b;
        case 707:  return (unsigned long)&stage_707 - b;
        case 708:  return (unsigned long)&stage_708 - b;
        case 709:  return (unsigned long)&stage_709 - b;
        case 710:  return (unsigned long)&stage_710 - b;
        case 711:  return (unsigned long)&stage_711 - b;
        case 712:  return (unsigned long)&stage_712 - b;
        case 713:  return (unsigned long)&stage_713 - b;
        case 714:  return (unsigned long)&stage_714 - b;
        case 715:  return (unsigned long)&stage_715 - b;
        case 716:  return (unsigned long)&stage_716 - b;
        case 717:  return (unsigned long)&stage_717 - b;
        case 718:  return (unsigned long)&stage_718 - b;
        case 719:  return (unsigned long)&stage_719 - b;
        case 720:  return (unsigned long)&stage_720 - b;
        case 721:  return (unsigned long)&stage_721 - b;
        case 722:  return (unsigned long)&stage_722 - b;
        case 723:  return (unsigned long)&stage_723 - b;
        case 724:  return (unsigned long)&stage_724 - b;
        case 725:  return (unsigned long)&stage_725 - b;
        case 726:  return (unsigned long)&stage_726 - b;
        case 727:  return (unsigned long)&stage_727 - b;
        case 728:  return (unsigned long)&stage_728 - b;
        case 729:  return (unsigned long)&stage_729 - b;
        case 730:  return (unsigned long)&stage_730 - b;
        case 731:  return (unsigned long)&stage_731 - b;
        case 732:  return (unsigned long)&stage_732 - b;
        case 733:  return (unsigned long)&stage_733 - b;
        case 734:  return (unsigned long)&stage_734 - b;
        case 735:  return (unsigned long)&stage_735 - b;
        case 736:  return (unsigned long)&stage_736 - b;
        case 737:  return (unsigned long)&stage_737 - b;
        case 738:  return (unsigned long)&stage_738 - b;
        case 739:  return (unsigned long)&stage_739 - b;
        case 740:  return (unsigned long)&stage_740 - b;
        case 741:  return (unsigned long)&stage_741 - b;
        case 742:  return (unsigned long)&stage_742 - b;
        case 743:  return (unsigned long)&stage_743 - b;
        case 744:  return (unsigned long)&stage_744 - b;
        case 745:  return (unsigned long)&stage_745 - b;
        case 746:  return (unsigned long)&stage_746 - b;
        case 747:  return (unsigned long)&stage_747 - b;
        case 748:  return (unsigned long)&stage_748 - b;
        case 749:  return (unsigned long)&stage_749 - b;
        case 750:  return (unsigned long)&stage_750 - b;
        case 751:  return (unsigned long)&stage_751 - b;
        case 752:  return (unsigned long)&stage_752 - b;
        case 753:  return (unsigned long)&stage_753 - b;
        case 754:  return (unsigned long)&stage_754 - b;
        case 755:  return (unsigned long)&stage_755 - b;
        case 756:  return (unsigned long)&stage_756 - b;
        case 757:  return (unsigned long)&stage_757 - b;
        case 758:  return (unsigned long)&stage_758 - b;
        case 759:  return (unsigned long)&stage_759 - b;
        case 760:  return (unsigned long)&stage_760 - b;
        case 761:  return (unsigned long)&stage_761 - b;
        case 762:  return (unsigned long)&stage_762 - b;
        case 763:  return (unsigned long)&stage_763 - b;
        case 764:  return (unsigned long)&stage_764 - b;
        case 765:  return (unsigned long)&stage_765 - b;
        case 766:  return (unsigned long)&stage_766 - b;
        case 767:  return (unsigned long)&stage_767 - b;
        case 768:  return (unsigned long)&stage_768 - b;
        case 769:  return (unsigned long)&stage_769 - b;
        case 770:  return (unsigned long)&stage_770 - b;
        case 771:  return (unsigned long)&stage_771 - b;
        case 772:  return (unsigned long)&stage_772 - b;
        case 773:  return (unsigned long)&stage_773 - b;
        case 774:  return (unsigned long)&stage_774 - b;
        case 775:  return (unsigned long)&stage_775 - b;
        case 776:  return (unsigned long)&stage_776 - b;
        case 777:  return (unsigned long)&stage_777 - b;
        case 778:  return (unsigned long)&stage_778 - b;
        case 779:  return (unsigned long)&stage_779 - b;
        case 780:  return (unsigned long)&stage_780 - b;
        case 781:  return (unsigned long)&stage_781 - b;
        case 782:  return (unsigned long)&stage_782 - b;
        case 783:  return (unsigned long)&stage_783 - b;
        case 784:  return (unsigned long)&stage_784 - b;
        case 785:  return (unsigned long)&stage_785 - b;
        case 786:  return (unsigned long)&stage_786 - b;
        case 787:  return (unsigned long)&stage_787 - b;
        case 788:  return (unsigned long)&stage_788 - b;
        case 789:  return (unsigned long)&stage_789 - b;
        case 790:  return (unsigned long)&stage_790 - b;
        case 791:  return (unsigned long)&stage_791 - b;
        case 792:  return (unsigned long)&stage_792 - b;
        case 793:  return (unsigned long)&stage_793 - b;
        case 794:  return (unsigned long)&stage_794 - b;
        case 795:  return (unsigned long)&stage_795 - b;
        case 796:  return (unsigned long)&stage_796 - b;
        case 797:  return (unsigned long)&stage_797 - b;
        case 798:  return (unsigned long)&stage_798 - b;
        case 799:  return (unsigned long)&stage_799 - b;
        case 800:  return (unsigned long)&stage_800 - b;
        case 801:  return (unsigned long)&stage_801 - b;
        case 802:  return (unsigned long)&stage_802 - b;
        case 803:  return (unsigned long)&stage_803 - b;
        case 804:  return (unsigned long)&stage_804 - b;
        case 805:  return (unsigned long)&stage_805 - b;
        case 806:  return (unsigned long)&stage_806 - b;
        case 807:  return (unsigned long)&stage_807 - b;
        case 808:  return (unsigned long)&stage_808 - b;
        case 809:  return (unsigned long)&stage_809 - b;
        case 810:  return (unsigned long)&stage_810 - b;
        case 811:  return (unsigned long)&stage_811 - b;
        case 812:  return (unsigned long)&stage_812 - b;
        case 813:  return (unsigned long)&stage_813 - b;
        case 814:  return (unsigned long)&stage_814 - b;
        case 815:  return (unsigned long)&stage_815 - b;
        case 816:  return (unsigned long)&stage_816 - b;
        case 817:  return (unsigned long)&stage_817 - b;
        case 818:  return (unsigned long)&stage_818 - b;
        case 819:  return (unsigned long)&stage_819 - b;
        case 820:  return (unsigned long)&stage_820 - b;
        case 821:  return (unsigned long)&stage_821 - b;
        case 822:  return (unsigned long)&stage_822 - b;
        case 823:  return (unsigned long)&stage_823 - b;
        case 824:  return (unsigned long)&stage_824 - b;
        case 825:  return (unsigned long)&stage_825 - b;
        case 826:  return (unsigned long)&stage_826 - b;
        case 827:  return (unsigned long)&stage_827 - b;
        case 828:  return (unsigned long)&stage_828 - b;
        case 829:  return (unsigned long)&stage_829 - b;
        case 830:  return (unsigned long)&stage_830 - b;
        case 831:  return (unsigned long)&stage_831 - b;
        case 832:  return (unsigned long)&stage_832 - b;
        case 833:  return (unsigned long)&stage_833 - b;
        case 834:  return (unsigned long)&stage_834 - b;
        case 835:  return (unsigned long)&stage_835 - b;
        case 836:  return (unsigned long)&stage_836 - b;
        case 837:  return (unsigned long)&stage_837 - b;
        case 838:  return (unsigned long)&stage_838 - b;
        case 839:  return (unsigned long)&stage_839 - b;
        case 840:  return (unsigned long)&stage_840 - b;
        case 841:  return (unsigned long)&stage_841 - b;
        case 842:  return (unsigned long)&stage_842 - b;
        case 843:  return (unsigned long)&stage_843 - b;
        case 844:  return (unsigned long)&stage_844 - b;
        case 845:  return (unsigned long)&stage_845 - b;
        case 846:  return (unsigned long)&stage_846 - b;
        case 847:  return (unsigned long)&stage_847 - b;
        case 848:  return (unsigned long)&stage_848 - b;
        case 849:  return (unsigned long)&stage_849 - b;
        case 850:  return (unsigned long)&stage_850 - b;
        case 851:  return (unsigned long)&stage_851 - b;
        case 852:  return (unsigned long)&stage_852 - b;
        case 853:  return (unsigned long)&stage_853 - b;
        case 854:  return (unsigned long)&stage_854 - b;
        case 855:  return (unsigned long)&stage_855 - b;
        case 856:  return (unsigned long)&stage_856 - b;
        case 857:  return (unsigned long)&stage_857 - b;
        case 858:  return (unsigned long)&stage_858 - b;
        case 859:  return (unsigned long)&stage_859 - b;
        case 860:  return (unsigned long)&stage_860 - b;
        case 861:  return (unsigned long)&stage_861 - b;
        case 862:  return (unsigned long)&stage_862 - b;
        case 863:  return (unsigned long)&stage_863 - b;
        case 864:  return (unsigned long)&stage_864 - b;
        case 865:  return (unsigned long)&stage_865 - b;
        case 866:  return (unsigned long)&stage_866 - b;
        case 867:  return (unsigned long)&stage_867 - b;
        case 868:  return (unsigned long)&stage_868 - b;
        case 869:  return (unsigned long)&stage_869 - b;
        case 870:  return (unsigned long)&stage_870 - b;
        case 871:  return (unsigned long)&stage_871 - b;
        case 872:  return (unsigned long)&stage_872 - b;
        case 873:  return (unsigned long)&stage_873 - b;
        case 874:  return (unsigned long)&stage_874 - b;
        case 875:  return (unsigned long)&stage_875 - b;
        case 876:  return (unsigned long)&stage_876 - b;
        case 877:  return (unsigned long)&stage_877 - b;
        case 878:  return (unsigned long)&stage_878 - b;
        case 879:  return (unsigned long)&stage_879 - b;
        case 880:  return (unsigned long)&stage_880 - b;
        case 881:  return (unsigned long)&stage_881 - b;
        case 882:  return (unsigned long)&stage_882 - b;
        case 883:  return (unsigned long)&stage_883 - b;
        case 884:  return (unsigned long)&stage_884 - b;
        case 885:  return (unsigned long)&stage_885 - b;
        case 886:  return (unsigned long)&stage_886 - b;
        case 887:  return (unsigned long)&stage_887 - b;
        case 888:  return (unsigned long)&stage_888 - b;
        case 889:  return (unsigned long)&stage_889 - b;
        case 890:  return (unsigned long)&stage_890 - b;
        case 891:  return (unsigned long)&stage_891 - b;
        case 892:  return (unsigned long)&stage_892 - b;
        case 893:  return (unsigned long)&stage_893 - b;
        case 894:  return (unsigned long)&stage_894 - b;
        case 895:  return (unsigned long)&stage_895 - b;
        case 896:  return (unsigned long)&stage_896 - b;
        case 897:  return (unsigned long)&stage_897 - b;
        case 898:  return (unsigned long)&stage_898 - b;
        case 899:  return (unsigned long)&stage_899 - b;
        case 900:  return (unsigned long)&stage_900 - b;
        case 901:  return (unsigned long)&stage_901 - b;
        case 902:  return (unsigned long)&stage_902 - b;
        case 903:  return (unsigned long)&stage_903 - b;
        case 904:  return (unsigned long)&stage_904 - b;
        case 905:  return (unsigned long)&stage_905 - b;
        case 906:  return (unsigned long)&stage_906 - b;
        case 907:  return (unsigned long)&stage_907 - b;
        case 908:  return (unsigned long)&stage_908 - b;
        case 909:  return (unsigned long)&stage_909 - b;
        case 910:  return (unsigned long)&stage_910 - b;
        case 911:  return (unsigned long)&stage_911 - b;
        case 912:  return (unsigned long)&stage_912 - b;
        case 913:  return (unsigned long)&stage_913 - b;
        case 914:  return (unsigned long)&stage_914 - b;
        case 915:  return (unsigned long)&stage_915 - b;
        case 916:  return (unsigned long)&stage_916 - b;
        case 917:  return (unsigned long)&stage_917 - b;
        case 918:  return (unsigned long)&stage_918 - b;
        case 919:  return (unsigned long)&stage_919 - b;
        case 920:  return (unsigned long)&stage_920 - b;
        case 921:  return (unsigned long)&stage_921 - b;
        case 922:  return (unsigned long)&stage_922 - b;
        case 923:  return (unsigned long)&stage_923 - b;
        case 924:  return (unsigned long)&stage_924 - b;
        case 925:  return (unsigned long)&stage_925 - b;
        case 926:  return (unsigned long)&stage_926 - b;
        case 927:  return (unsigned long)&stage_927 - b;
        case 928:  return (unsigned long)&stage_928 - b;
        case 929:  return (unsigned long)&stage_929 - b;
        case 930:  return (unsigned long)&stage_930 - b;
        case 931:  return (unsigned long)&stage_931 - b;
        case 932:  return (unsigned long)&stage_932 - b;
        case 933:  return (unsigned long)&stage_933 - b;
        case 934:  return (unsigned long)&stage_934 - b;
        case 935:  return (unsigned long)&stage_935 - b;
        case 936:  return (unsigned long)&stage_936 - b;
        case 937:  return (unsigned long)&stage_937 - b;
        case 938:  return (unsigned long)&stage_938 - b;
        case 939:  return (unsigned long)&stage_939 - b;
        case 940:  return (unsigned long)&stage_940 - b;
        case 941:  return (unsigned long)&stage_941 - b;
        case 942:  return (unsigned long)&stage_942 - b;
        case 943:  return (unsigned long)&stage_943 - b;
        case 944:  return (unsigned long)&stage_944 - b;
        case 945:  return (unsigned long)&stage_945 - b;
        case 946:  return (unsigned long)&stage_946 - b;
        case 947:  return (unsigned long)&stage_947 - b;
        case 948:  return (unsigned long)&stage_948 - b;
        case 949:  return (unsigned long)&stage_949 - b;
        case 950:  return (unsigned long)&stage_950 - b;
        case 951:  return (unsigned long)&stage_951 - b;
        case 952:  return (unsigned long)&stage_952 - b;
        case 953:  return (unsigned long)&stage_953 - b;
        case 954:  return (unsigned long)&stage_954 - b;
        case 955:  return (unsigned long)&stage_955 - b;
        case 956:  return (unsigned long)&stage_956 - b;
        case 957:  return (unsigned long)&stage_957 - b;
        case 958:  return (unsigned long)&stage_958 - b;
        case 959:  return (unsigned long)&stage_959 - b;
        case 960:  return (unsigned long)&stage_960 - b;
        case 961:  return (unsigned long)&stage_961 - b;
        case 962:  return (unsigned long)&stage_962 - b;
        case 963:  return (unsigned long)&stage_963 - b;
        case 964:  return (unsigned long)&stage_964 - b;
        case 965:  return (unsigned long)&stage_965 - b;
        case 966:  return (unsigned long)&stage_966 - b;
        case 967:  return (unsigned long)&stage_967 - b;
        case 968:  return (unsigned long)&stage_968 - b;
        case 969:  return (unsigned long)&stage_969 - b;
        case 970:  return (unsigned long)&stage_970 - b;
        case 971:  return (unsigned long)&stage_971 - b;
        case 972:  return (unsigned long)&stage_972 - b;
        case 973:  return (unsigned long)&stage_973 - b;
        case 974:  return (unsigned long)&stage_974 - b;
        case 975:  return (unsigned long)&stage_975 - b;
        case 976:  return (unsigned long)&stage_976 - b;
        case 977:  return (unsigned long)&stage_977 - b;
        case 978:  return (unsigned long)&stage_978 - b;
        case 979:  return (unsigned long)&stage_979 - b;
        case 980:  return (unsigned long)&stage_980 - b;
        case 981:  return (unsigned long)&stage_981 - b;
        case 982:  return (unsigned long)&stage_982 - b;
        case 983:  return (unsigned long)&stage_983 - b;
        case 984:  return (unsigned long)&stage_984 - b;
        case 985:  return (unsigned long)&stage_985 - b;
        case 986:  return (unsigned long)&stage_986 - b;
        case 987:  return (unsigned long)&stage_987 - b;
        case 988:  return (unsigned long)&stage_988 - b;
        case 989:  return (unsigned long)&stage_989 - b;
        case 990:  return (unsigned long)&stage_990 - b;
        case 991:  return (unsigned long)&stage_991 - b;
        case 992:  return (unsigned long)&stage_992 - b;
        case 993:  return (unsigned long)&stage_993 - b;
        case 994:  return (unsigned long)&stage_994 - b;
        case 995:  return (unsigned long)&stage_995 - b;
        case 996:  return (unsigned long)&stage_996 - b;
        case 997:  return (unsigned long)&stage_997 - b;
        case 998:  return (unsigned long)&stage_998 - b;
        case 999:  return (unsigned long)&stage_999 - b;
        case 1000:  return (unsigned long)&stage_1000 - b;
        case 1001:  return (unsigned long)&stage_1001 - b;
        case 1002:  return (unsigned long)&stage_1002 - b;
        case 1003:  return (unsigned long)&stage_1003 - b;
        case 1004:  return (unsigned long)&stage_1004 - b;
        case 1005:  return (unsigned long)&stage_1005 - b;
        case 1006:  return (unsigned long)&stage_1006 - b;
        case 1007:  return (unsigned long)&stage_1007 - b;
        case 1008:  return (unsigned long)&stage_1008 - b;
        case 1009:  return (unsigned long)&stage_1009 - b;
        case 1010:  return (unsigned long)&stage_1010 - b;
        case 1011:  return (unsigned long)&stage_1011 - b;
        case 1012:  return (unsigned long)&stage_1012 - b;
        case 1013:  return (unsigned long)&stage_1013 - b;
        case 1014:  return (unsigned long)&stage_1014 - b;
        case 1015:  return (unsigned long)&stage_1015 - b;
        case 1016:  return (unsigned long)&stage_1016 - b;
        case 1017:  return (unsigned long)&stage_1017 - b;
        case 1018:  return (unsigned long)&stage_1018 - b;
        case 1019:  return (unsigned long)&stage_1019 - b;
        case 1020:  return (unsigned long)&stage_1020 - b;
        case 1021:  return (unsigned long)&stage_1021 - b;
        case 1022:  return (unsigned long)&stage_1022 - b;
        case 1023:  return (unsigned long)&stage_1023 - b;
        case 1024:  return (unsigned long)&stage_1024 - b;
        case 1025:  return (unsigned long)&stage_1025 - b;
        case 1026:  return (unsigned long)&stage_1026 - b;
        case 1027:  return (unsigned long)&stage_1027 - b;
        case 1028:  return (unsigned long)&stage_1028 - b;
        case 1029:  return (unsigned long)&stage_1029 - b;
        case 1030:  return (unsigned long)&stage_1030 - b;
        case 1031:  return (unsigned long)&stage_1031 - b;
        case 1032:  return (unsigned long)&stage_1032 - b;
        case 1033:  return (unsigned long)&stage_1033 - b;
        case 1034:  return (unsigned long)&stage_1034 - b;
        case 1035:  return (unsigned long)&stage_1035 - b;
        case 1036:  return (unsigned long)&stage_1036 - b;
        case 1037:  return (unsigned long)&stage_1037 - b;
        case 1038:  return (unsigned long)&stage_1038 - b;
        case 1039:  return (unsigned long)&stage_1039 - b;
        case 1040:  return (unsigned long)&stage_1040 - b;
        case 1041:  return (unsigned long)&stage_1041 - b;
        case 1042:  return (unsigned long)&stage_1042 - b;
        case 1043:  return (unsigned long)&stage_1043 - b;
        case 1044:  return (unsigned long)&stage_1044 - b;
        case 1045:  return (unsigned long)&stage_1045 - b;
        case 1046:  return (unsigned long)&stage_1046 - b;
        case 1047:  return (unsigned long)&stage_1047 - b;
        case 1048:  return (unsigned long)&stage_1048 - b;
        case 1049:  return (unsigned long)&stage_1049 - b;
        case 1050:  return (unsigned long)&stage_1050 - b;
        case 1051:  return (unsigned long)&stage_1051 - b;
        case 1052:  return (unsigned long)&stage_1052 - b;
        case 1053:  return (unsigned long)&stage_1053 - b;
        case 1054:  return (unsigned long)&stage_1054 - b;
        case 1055:  return (unsigned long)&stage_1055 - b;
        case 1056:  return (unsigned long)&stage_1056 - b;
        case 1057:  return (unsigned long)&stage_1057 - b;
        case 1058:  return (unsigned long)&stage_1058 - b;
        case 1059:  return (unsigned long)&stage_1059 - b;
        case 1060:  return (unsigned long)&stage_1060 - b;
        case 1061:  return (unsigned long)&stage_1061 - b;
        case 1062:  return (unsigned long)&stage_1062 - b;
        case 1063:  return (unsigned long)&stage_1063 - b;
        case 1064:  return (unsigned long)&stage_1064 - b;
        case 1065:  return (unsigned long)&stage_1065 - b;
        case 1066:  return (unsigned long)&stage_1066 - b;
        case 1067:  return (unsigned long)&stage_1067 - b;
        case 1068:  return (unsigned long)&stage_1068 - b;
        case 1069:  return (unsigned long)&stage_1069 - b;
        case 1070:  return (unsigned long)&stage_1070 - b;
        case 1071:  return (unsigned long)&stage_1071 - b;
        case 1072:  return (unsigned long)&stage_1072 - b;
        case 1073:  return (unsigned long)&stage_1073 - b;
        case 1074:  return (unsigned long)&stage_1074 - b;
        case 1075:  return (unsigned long)&stage_1075 - b;
        case 1076:  return (unsigned long)&stage_1076 - b;
        case 1077:  return (unsigned long)&stage_1077 - b;
        case 1078:  return (unsigned long)&stage_1078 - b;
        case 1079:  return (unsigned long)&stage_1079 - b;
        case 1080:  return (unsigned long)&stage_1080 - b;
        case 1081:  return (unsigned long)&stage_1081 - b;
        case 1082:  return (unsigned long)&stage_1082 - b;
        case 1083:  return (unsigned long)&stage_1083 - b;
        case 1084:  return (unsigned long)&stage_1084 - b;
        case 1085:  return (unsigned long)&stage_1085 - b;
        case 1086:  return (unsigned long)&stage_1086 - b;
        case 1087:  return (unsigned long)&stage_1087 - b;
        case 1088:  return (unsigned long)&stage_1088 - b;
        case 1089:  return (unsigned long)&stage_1089 - b;
        case 1090:  return (unsigned long)&stage_1090 - b;
        case 1091:  return (unsigned long)&stage_1091 - b;
        case 1092:  return (unsigned long)&stage_1092 - b;
        case 1093:  return (unsigned long)&stage_1093 - b;
        case 1094:  return (unsigned long)&stage_1094 - b;
        case 1095:  return (unsigned long)&stage_1095 - b;
        case 1096:  return (unsigned long)&stage_1096 - b;
        case 1097:  return (unsigned long)&stage_1097 - b;
        case 1098:  return (unsigned long)&stage_1098 - b;
        case 1099:  return (unsigned long)&stage_1099 - b;
        case 1100:  return (unsigned long)&stage_1100 - b;
        case 1101:  return (unsigned long)&stage_1101 - b;
        case 1102:  return (unsigned long)&stage_1102 - b;
        case 1103:  return (unsigned long)&stage_1103 - b;
        case 1104:  return (unsigned long)&stage_1104 - b;
        case 1105:  return (unsigned long)&stage_1105 - b;
        case 1106:  return (unsigned long)&stage_1106 - b;
        case 1107:  return (unsigned long)&stage_1107 - b;
        case 1108:  return (unsigned long)&stage_1108 - b;
        case 1109:  return (unsigned long)&stage_1109 - b;
        case 1110:  return (unsigned long)&stage_1110 - b;
        case 1111:  return (unsigned long)&stage_1111 - b;
        case 1112:  return (unsigned long)&stage_1112 - b;
        case 1113:  return (unsigned long)&stage_1113 - b;
        case 1114:  return (unsigned long)&stage_1114 - b;
        case 1115:  return (unsigned long)&stage_1115 - b;
        case 1116:  return (unsigned long)&stage_1116 - b;
        case 1117:  return (unsigned long)&stage_1117 - b;
        case 1118:  return (unsigned long)&stage_1118 - b;
        case 1119:  return (unsigned long)&stage_1119 - b;
        case 1120:  return (unsigned long)&stage_1120 - b;
        case 1121:  return (unsigned long)&stage_1121 - b;
        case 1122:  return (unsigned long)&stage_1122 - b;
        case 1123:  return (unsigned long)&stage_1123 - b;
        case 1124:  return (unsigned long)&stage_1124 - b;
        case 1125:  return (unsigned long)&stage_1125 - b;
        case 1126:  return (unsigned long)&stage_1126 - b;
        case 1127:  return (unsigned long)&stage_1127 - b;
        case 1128:  return (unsigned long)&stage_1128 - b;
        case 1129:  return (unsigned long)&stage_1129 - b;
        case 1130:  return (unsigned long)&stage_1130 - b;
        case 1131:  return (unsigned long)&stage_1131 - b;
        case 1132:  return (unsigned long)&stage_1132 - b;
        case 1133:  return (unsigned long)&stage_1133 - b;
        case 1134:  return (unsigned long)&stage_1134 - b;
        case 1135:  return (unsigned long)&stage_1135 - b;
        case 1136:  return (unsigned long)&stage_1136 - b;
        case 1137:  return (unsigned long)&stage_1137 - b;
        case 1138:  return (unsigned long)&stage_1138 - b;
        case 1139:  return (unsigned long)&stage_1139 - b;
        case 1140:  return (unsigned long)&stage_1140 - b;
        case 1141:  return (unsigned long)&stage_1141 - b;
        case 1142:  return (unsigned long)&stage_1142 - b;
        case 1143:  return (unsigned long)&stage_1143 - b;
        case 1144:  return (unsigned long)&stage_1144 - b;
        case 1145:  return (unsigned long)&stage_1145 - b;
        case 1146:  return (unsigned long)&stage_1146 - b;
        case 1147:  return (unsigned long)&stage_1147 - b;
        case 1148:  return (unsigned long)&stage_1148 - b;
        case 1149:  return (unsigned long)&stage_1149 - b;
        case 1150:  return (unsigned long)&stage_1150 - b;
        case 1151:  return (unsigned long)&stage_1151 - b;
        case 1152:  return (unsigned long)&stage_1152 - b;
        case 1153:  return (unsigned long)&stage_1153 - b;
        case 1154:  return (unsigned long)&stage_1154 - b;
        case 1155:  return (unsigned long)&stage_1155 - b;
        case 1156:  return (unsigned long)&stage_1156 - b;
        case 1157:  return (unsigned long)&stage_1157 - b;
        case 1158:  return (unsigned long)&stage_1158 - b;
        case 1159:  return (unsigned long)&stage_1159 - b;
        case 1160:  return (unsigned long)&stage_1160 - b;
        case 1161:  return (unsigned long)&stage_1161 - b;
        case 1162:  return (unsigned long)&stage_1162 - b;
        case 1163:  return (unsigned long)&stage_1163 - b;
        case 1164:  return (unsigned long)&stage_1164 - b;
        case 1165:  return (unsigned long)&stage_1165 - b;
        case 1166:  return (unsigned long)&stage_1166 - b;
        case 1167:  return (unsigned long)&stage_1167 - b;
        case 1168:  return (unsigned long)&stage_1168 - b;
        case 1169:  return (unsigned long)&stage_1169 - b;
        case 1170:  return (unsigned long)&stage_1170 - b;
        case 1171:  return (unsigned long)&stage_1171 - b;
        case 1172:  return (unsigned long)&stage_1172 - b;
        case 1173:  return (unsigned long)&stage_1173 - b;
        case 1174:  return (unsigned long)&stage_1174 - b;
        case 1175:  return (unsigned long)&stage_1175 - b;
        case 1176:  return (unsigned long)&stage_1176 - b;
        case 1177:  return (unsigned long)&stage_1177 - b;
        case 1178:  return (unsigned long)&stage_1178 - b;
        case 1179:  return (unsigned long)&stage_1179 - b;
        case 1180:  return (unsigned long)&stage_1180 - b;
        case 1181:  return (unsigned long)&stage_1181 - b;
        case 1182:  return (unsigned long)&stage_1182 - b;
        case 1183:  return (unsigned long)&stage_1183 - b;
        case 1184:  return (unsigned long)&stage_1184 - b;
        case 1185:  return (unsigned long)&stage_1185 - b;
        case 1186:  return (unsigned long)&stage_1186 - b;
        case 1187:  return (unsigned long)&stage_1187 - b;
        case 1188:  return (unsigned long)&stage_1188 - b;
        case 1189:  return (unsigned long)&stage_1189 - b;
        case 1190:  return (unsigned long)&stage_1190 - b;
        case 1191:  return (unsigned long)&stage_1191 - b;
        case 1192:  return (unsigned long)&stage_1192 - b;
        case 1193:  return (unsigned long)&stage_1193 - b;
        case 1194:  return (unsigned long)&stage_1194 - b;
        case 1195:  return (unsigned long)&stage_1195 - b;
        case 1196:  return (unsigned long)&stage_1196 - b;
        case 1197:  return (unsigned long)&stage_1197 - b;
        case 1198:  return (unsigned long)&stage_1198 - b;
        case 1199:  return (unsigned long)&stage_1199 - b;
        case 1200:  return (unsigned long)&stage_1200 - b;
        case 1201:  return (unsigned long)&stage_1201 - b;
        case 1202:  return (unsigned long)&stage_1202 - b;
        case 1203:  return (unsigned long)&stage_1203 - b;
        case 1204:  return (unsigned long)&stage_1204 - b;
        case 1205:  return (unsigned long)&stage_1205 - b;
        case 1206:  return (unsigned long)&stage_1206 - b;
        case 1207:  return (unsigned long)&stage_1207 - b;
        case 1208:  return (unsigned long)&stage_1208 - b;
        case 1209:  return (unsigned long)&stage_1209 - b;
        case 1210:  return (unsigned long)&stage_1210 - b;
        case 1211:  return (unsigned long)&stage_1211 - b;
        case 1212:  return (unsigned long)&stage_1212 - b;
        case 1213:  return (unsigned long)&stage_1213 - b;
        case 1214:  return (unsigned long)&stage_1214 - b;
        case 1215:  return (unsigned long)&stage_1215 - b;
        case 1216:  return (unsigned long)&stage_1216 - b;
        case 1217:  return (unsigned long)&stage_1217 - b;
        case 1218:  return (unsigned long)&stage_1218 - b;
        case 1219:  return (unsigned long)&stage_1219 - b;
        case 1220:  return (unsigned long)&stage_1220 - b;
        case 1221:  return (unsigned long)&stage_1221 - b;
        case 1222:  return (unsigned long)&stage_1222 - b;
        case 1223:  return (unsigned long)&stage_1223 - b;
        case 1224:  return (unsigned long)&stage_1224 - b;
        case 1225:  return (unsigned long)&stage_1225 - b;
        case 1226:  return (unsigned long)&stage_1226 - b;
        case 1227:  return (unsigned long)&stage_1227 - b;
        case 1228:  return (unsigned long)&stage_1228 - b;
        case 1229:  return (unsigned long)&stage_1229 - b;
        case 1230:  return (unsigned long)&stage_1230 - b;
        case 1231:  return (unsigned long)&stage_1231 - b;
        case 1232:  return (unsigned long)&stage_1232 - b;
        case 1233:  return (unsigned long)&stage_1233 - b;
        case 1234:  return (unsigned long)&stage_1234 - b;
        case 1235:  return (unsigned long)&stage_1235 - b;
        case 1236:  return (unsigned long)&stage_1236 - b;
        case 1237:  return (unsigned long)&stage_1237 - b;
        case 1238:  return (unsigned long)&stage_1238 - b;
        case 1239:  return (unsigned long)&stage_1239 - b;
        case 1240:  return (unsigned long)&stage_1240 - b;
        case 1241:  return (unsigned long)&stage_1241 - b;
        case 1242:  return (unsigned long)&stage_1242 - b;
        case 1243:  return (unsigned long)&stage_1243 - b;
        case 1244:  return (unsigned long)&stage_1244 - b;
        case 1245:  return (unsigned long)&stage_1245 - b;
        case 1246:  return (unsigned long)&stage_1246 - b;
        case 1247:  return (unsigned long)&stage_1247 - b;
        case 1248:  return (unsigned long)&stage_1248 - b;
        case 1249:  return (unsigned long)&stage_1249 - b;
        case 1250:  return (unsigned long)&stage_1250 - b;
        case 1251:  return (unsigned long)&stage_1251 - b;
        case 1252:  return (unsigned long)&stage_1252 - b;
        case 1253:  return (unsigned long)&stage_1253 - b;
        case 1254:  return (unsigned long)&stage_1254 - b;
        case 1255:  return (unsigned long)&stage_1255 - b;
        case 1256:  return (unsigned long)&stage_1256 - b;
        case 1257:  return (unsigned long)&stage_1257 - b;
        case 1258:  return (unsigned long)&stage_1258 - b;
        case 1259:  return (unsigned long)&stage_1259 - b;
        case 1260:  return (unsigned long)&stage_1260 - b;
        case 1261:  return (unsigned long)&stage_1261 - b;
        case 1262:  return (unsigned long)&stage_1262 - b;
        case 1263:  return (unsigned long)&stage_1263 - b;
        case 1264:  return (unsigned long)&stage_1264 - b;
        case 1265:  return (unsigned long)&stage_1265 - b;
        case 1266:  return (unsigned long)&stage_1266 - b;
        case 1267:  return (unsigned long)&stage_1267 - b;
        case 1268:  return (unsigned long)&stage_1268 - b;
        case 1269:  return (unsigned long)&stage_1269 - b;
        case 1270:  return (unsigned long)&stage_1270 - b;
        case 1271:  return (unsigned long)&stage_1271 - b;
        case 1272:  return (unsigned long)&stage_1272 - b;
        case 1273:  return (unsigned long)&stage_1273 - b;
        case 1274:  return (unsigned long)&stage_1274 - b;
        case 1275:  return (unsigned long)&stage_1275 - b;
        case 1276:  return (unsigned long)&stage_1276 - b;
        case 1277:  return (unsigned long)&stage_1277 - b;
        case 1278:  return (unsigned long)&stage_1278 - b;
        case 1279:  return (unsigned long)&stage_1279 - b;
        case 1280:  return (unsigned long)&stage_1280 - b;
        case 1281:  return (unsigned long)&stage_1281 - b;
        case 1282:  return (unsigned long)&stage_1282 - b;
        case 1283:  return (unsigned long)&stage_1283 - b;
        case 1284:  return (unsigned long)&stage_1284 - b;
        case 1285:  return (unsigned long)&stage_1285 - b;
        case 1286:  return (unsigned long)&stage_1286 - b;
        case 1287:  return (unsigned long)&stage_1287 - b;
        case 1288:  return (unsigned long)&stage_1288 - b;
        case 1289:  return (unsigned long)&stage_1289 - b;
        case 1290:  return (unsigned long)&stage_1290 - b;
        case 1291:  return (unsigned long)&stage_1291 - b;
        case 1292:  return (unsigned long)&stage_1292 - b;
        case 1293:  return (unsigned long)&stage_1293 - b;
        case 1294:  return (unsigned long)&stage_1294 - b;
        case 1295:  return (unsigned long)&stage_1295 - b;
        case 1296:  return (unsigned long)&stage_1296 - b;
        case 1297:  return (unsigned long)&stage_1297 - b;
        case 1298:  return (unsigned long)&stage_1298 - b;
        case 1299:  return (unsigned long)&stage_1299 - b;
        case 1300:  return (unsigned long)&stage_1300 - b;
        case 1301:  return (unsigned long)&stage_1301 - b;
        case 1302:  return (unsigned long)&stage_1302 - b;
        case 1303:  return (unsigned long)&stage_1303 - b;
        case 1304:  return (unsigned long)&stage_1304 - b;
        case 1305:  return (unsigned long)&stage_1305 - b;
        case 1306:  return (unsigned long)&stage_1306 - b;
        case 1307:  return (unsigned long)&stage_1307 - b;
        case 1308:  return (unsigned long)&stage_1308 - b;
        case 1309:  return (unsigned long)&stage_1309 - b;
        case 1310:  return (unsigned long)&stage_1310 - b;
        case 1311:  return (unsigned long)&stage_1311 - b;
        case 1312:  return (unsigned long)&stage_1312 - b;
        case 1313:  return (unsigned long)&stage_1313 - b;
        case 1314:  return (unsigned long)&stage_1314 - b;
        case 1315:  return (unsigned long)&stage_1315 - b;
        case 1316:  return (unsigned long)&stage_1316 - b;
        case 1317:  return (unsigned long)&stage_1317 - b;
        case 1318:  return (unsigned long)&stage_1318 - b;
        case 1319:  return (unsigned long)&stage_1319 - b;
        case 1320:  return (unsigned long)&stage_1320 - b;
        case 1321:  return (unsigned long)&stage_1321 - b;
        case 1322:  return (unsigned long)&stage_1322 - b;
        case 1323:  return (unsigned long)&stage_1323 - b;
        case 1324:  return (unsigned long)&stage_1324 - b;
        case 1325:  return (unsigned long)&stage_1325 - b;
        case 1326:  return (unsigned long)&stage_1326 - b;
        case 1327:  return (unsigned long)&stage_1327 - b;
        case 1328:  return (unsigned long)&stage_1328 - b;
        case 1329:  return (unsigned long)&stage_1329 - b;
        case 1330:  return (unsigned long)&stage_1330 - b;
        case 1331:  return (unsigned long)&stage_1331 - b;
        case 1332:  return (unsigned long)&stage_1332 - b;
        case 1333:  return (unsigned long)&stage_1333 - b;
        case 1334:  return (unsigned long)&stage_1334 - b;
        case 1335:  return (unsigned long)&stage_1335 - b;
        case 1336:  return (unsigned long)&stage_1336 - b;
        case 1337:  return (unsigned long)&stage_1337 - b;
        case 1338:  return (unsigned long)&stage_1338 - b;
        case 1339:  return (unsigned long)&stage_1339 - b;
        case 1340:  return (unsigned long)&stage_1340 - b;
        case 1341:  return (unsigned long)&stage_1341 - b;
        case 1342:  return (unsigned long)&stage_1342 - b;
        case 1343:  return (unsigned long)&stage_1343 - b;
        case 1344:  return (unsigned long)&stage_1344 - b;
        case 1345:  return (unsigned long)&stage_1345 - b;
        case 1346:  return (unsigned long)&stage_1346 - b;
        case 1347:  return (unsigned long)&stage_1347 - b;
        case 1348:  return (unsigned long)&stage_1348 - b;
        case 1349:  return (unsigned long)&stage_1349 - b;
        case 1350:  return (unsigned long)&stage_1350 - b;
        case 1351:  return (unsigned long)&stage_1351 - b;
        case 1352:  return (unsigned long)&stage_1352 - b;
        case 1353:  return (unsigned long)&stage_1353 - b;
        case 1354:  return (unsigned long)&stage_1354 - b;
        case 1355:  return (unsigned long)&stage_1355 - b;
        case 1356:  return (unsigned long)&stage_1356 - b;
        case 1357:  return (unsigned long)&stage_1357 - b;
        case 1358:  return (unsigned long)&stage_1358 - b;
        case 1359:  return (unsigned long)&stage_1359 - b;
        case 1360:  return (unsigned long)&stage_1360 - b;
        case 1361:  return (unsigned long)&stage_1361 - b;
        case 1362:  return (unsigned long)&stage_1362 - b;
        case 1363:  return (unsigned long)&stage_1363 - b;
        case 1364:  return (unsigned long)&stage_1364 - b;
        case 1365:  return (unsigned long)&stage_1365 - b;
        case 1366:  return (unsigned long)&stage_1366 - b;
        case 1367:  return (unsigned long)&stage_1367 - b;
        case 1368:  return (unsigned long)&stage_1368 - b;
        case 1369:  return (unsigned long)&stage_1369 - b;
        case 1370:  return (unsigned long)&stage_1370 - b;
        case 1371:  return (unsigned long)&stage_1371 - b;
        case 1372:  return (unsigned long)&stage_1372 - b;
        case 1373:  return (unsigned long)&stage_1373 - b;
        case 1374:  return (unsigned long)&stage_1374 - b;
        case 1375:  return (unsigned long)&stage_1375 - b;
        case 1376:  return (unsigned long)&stage_1376 - b;
        case 1377:  return (unsigned long)&stage_1377 - b;
        case 1378:  return (unsigned long)&stage_1378 - b;
        case 1379:  return (unsigned long)&stage_1379 - b;
        case 1380:  return (unsigned long)&stage_1380 - b;
        case 1381:  return (unsigned long)&stage_1381 - b;
        case 1382:  return (unsigned long)&stage_1382 - b;
        case 1383:  return (unsigned long)&stage_1383 - b;
        case 1384:  return (unsigned long)&stage_1384 - b;
        case 1385:  return (unsigned long)&stage_1385 - b;
        case 1386:  return (unsigned long)&stage_1386 - b;
        case 1387:  return (unsigned long)&stage_1387 - b;
        case 1388:  return (unsigned long)&stage_1388 - b;
        case 1389:  return (unsigned long)&stage_1389 - b;
        case 1390:  return (unsigned long)&stage_1390 - b;
        case 1391:  return (unsigned long)&stage_1391 - b;
        case 1392:  return (unsigned long)&stage_1392 - b;
        case 1393:  return (unsigned long)&stage_1393 - b;
        case 1394:  return (unsigned long)&stage_1394 - b;
        case 1395:  return (unsigned long)&stage_1395 - b;
        case 1396:  return (unsigned long)&stage_1396 - b;
        case 1397:  return (unsigned long)&stage_1397 - b;
        case 1398:  return (unsigned long)&stage_1398 - b;
        case 1399:  return (unsigned long)&stage_1399 - b;
        case 1400:  return (unsigned long)&stage_1400 - b;
        case 1401:  return (unsigned long)&stage_1401 - b;
        case 1402:  return (unsigned long)&stage_1402 - b;
        case 1403:  return (unsigned long)&stage_1403 - b;
        case 1404:  return (unsigned long)&stage_1404 - b;
        case 1405:  return (unsigned long)&stage_1405 - b;
        case 1406:  return (unsigned long)&stage_1406 - b;
        case 1407:  return (unsigned long)&stage_1407 - b;
        case 1408:  return (unsigned long)&stage_1408 - b;
        case 1409:  return (unsigned long)&stage_1409 - b;
        case 1410:  return (unsigned long)&stage_1410 - b;
        case 1411:  return (unsigned long)&stage_1411 - b;
        case 1412:  return (unsigned long)&stage_1412 - b;
        case 1413:  return (unsigned long)&stage_1413 - b;
        case 1414:  return (unsigned long)&stage_1414 - b;
        case 1415:  return (unsigned long)&stage_1415 - b;
        case 1416:  return (unsigned long)&stage_1416 - b;
        case 1417:  return (unsigned long)&stage_1417 - b;
        case 1418:  return (unsigned long)&stage_1418 - b;
        case 1419:  return (unsigned long)&stage_1419 - b;
        case 1420:  return (unsigned long)&stage_1420 - b;
        case 1421:  return (unsigned long)&stage_1421 - b;
        case 1422:  return (unsigned long)&stage_1422 - b;
        case 1423:  return (unsigned long)&stage_1423 - b;
        case 1424:  return (unsigned long)&stage_1424 - b;
        case 1425:  return (unsigned long)&stage_1425 - b;
        case 1426:  return (unsigned long)&stage_1426 - b;
        case 1427:  return (unsigned long)&stage_1427 - b;
        case 1428:  return (unsigned long)&stage_1428 - b;
        case 1429:  return (unsigned long)&stage_1429 - b;
        case 1430:  return (unsigned long)&stage_1430 - b;
        case 1431:  return (unsigned long)&stage_1431 - b;
        case 1432:  return (unsigned long)&stage_1432 - b;
        case 1433:  return (unsigned long)&stage_1433 - b;
        case 1434:  return (unsigned long)&stage_1434 - b;
        case 1435:  return (unsigned long)&stage_1435 - b;
        case 1436:  return (unsigned long)&stage_1436 - b;
        case 1437:  return (unsigned long)&stage_1437 - b;
        case 1438:  return (unsigned long)&stage_1438 - b;
        case 1439:  return (unsigned long)&stage_1439 - b;
        case 1440:  return (unsigned long)&stage_1440 - b;
        case 1441:  return (unsigned long)&stage_1441 - b;
        case 1442:  return (unsigned long)&stage_1442 - b;
        case 1443:  return (unsigned long)&stage_1443 - b;
        case 1444:  return (unsigned long)&stage_1444 - b;
        case 1445:  return (unsigned long)&stage_1445 - b;
        case 1446:  return (unsigned long)&stage_1446 - b;
        case 1447:  return (unsigned long)&stage_1447 - b;
        case 1448:  return (unsigned long)&stage_1448 - b;
        case 1449:  return (unsigned long)&stage_1449 - b;
        case 1450:  return (unsigned long)&stage_1450 - b;
        case 1451:  return (unsigned long)&stage_1451 - b;
        case 1452:  return (unsigned long)&stage_1452 - b;
        case 1453:  return (unsigned long)&stage_1453 - b;
        case 1454:  return (unsigned long)&stage_1454 - b;
        case 1455:  return (unsigned long)&stage_1455 - b;
        case 1456:  return (unsigned long)&stage_1456 - b;
        case 1457:  return (unsigned long)&stage_1457 - b;
        case 1458:  return (unsigned long)&stage_1458 - b;
        case 1459:  return (unsigned long)&stage_1459 - b;
        case 1460:  return (unsigned long)&stage_1460 - b;
        case 1461:  return (unsigned long)&stage_1461 - b;
        case 1462:  return (unsigned long)&stage_1462 - b;
        case 1463:  return (unsigned long)&stage_1463 - b;
        case 1464:  return (unsigned long)&stage_1464 - b;
        case 1465:  return (unsigned long)&stage_1465 - b;
        case 1466:  return (unsigned long)&stage_1466 - b;
        case 1467:  return (unsigned long)&stage_1467 - b;
        case 1468:  return (unsigned long)&stage_1468 - b;
        case 1469:  return (unsigned long)&stage_1469 - b;
        case 1470:  return (unsigned long)&stage_1470 - b;
        case 1471:  return (unsigned long)&stage_1471 - b;
        case 1472:  return (unsigned long)&stage_1472 - b;
        case 1473:  return (unsigned long)&stage_1473 - b;
        case 1474:  return (unsigned long)&stage_1474 - b;
        case 1475:  return (unsigned long)&stage_1475 - b;
        case 1476:  return (unsigned long)&stage_1476 - b;
        case 1477:  return (unsigned long)&stage_1477 - b;
        case 1478:  return (unsigned long)&stage_1478 - b;
        case 1479:  return (unsigned long)&stage_1479 - b;
        case 1480:  return (unsigned long)&stage_1480 - b;
        case 1481:  return (unsigned long)&stage_1481 - b;
        case 1482:  return (unsigned long)&stage_1482 - b;
        case 1483:  return (unsigned long)&stage_1483 - b;
        case 1484:  return (unsigned long)&stage_1484 - b;
        case 1485:  return (unsigned long)&stage_1485 - b;
        case 1486:  return (unsigned long)&stage_1486 - b;
        case 1487:  return (unsigned long)&stage_1487 - b;
        case 1488:  return (unsigned long)&stage_1488 - b;
        case 1489:  return (unsigned long)&stage_1489 - b;
        case 1490:  return (unsigned long)&stage_1490 - b;
        case 1491:  return (unsigned long)&stage_1491 - b;
        case 1492:  return (unsigned long)&stage_1492 - b;
        case 1493:  return (unsigned long)&stage_1493 - b;
        case 1494:  return (unsigned long)&stage_1494 - b;
        case 1495:  return (unsigned long)&stage_1495 - b;
        case 1496:  return (unsigned long)&stage_1496 - b;
        case 1497:  return (unsigned long)&stage_1497 - b;
        case 1498:  return (unsigned long)&stage_1498 - b;
        case 1499:  return (unsigned long)&stage_1499 - b;
        case 1500:  return (unsigned long)&stage_1500 - b;
        case 1501:  return (unsigned long)&stage_1501 - b;
        case 1502:  return (unsigned long)&stage_1502 - b;
        case 1503:  return (unsigned long)&stage_1503 - b;
        case 1504:  return (unsigned long)&stage_1504 - b;
        case 1505:  return (unsigned long)&stage_1505 - b;
        case 1506:  return (unsigned long)&stage_1506 - b;
        case 1507:  return (unsigned long)&stage_1507 - b;
        case 1508:  return (unsigned long)&stage_1508 - b;
        case 1509:  return (unsigned long)&stage_1509 - b;
        case 1510:  return (unsigned long)&stage_1510 - b;
        case 1511:  return (unsigned long)&stage_1511 - b;
        case 1512:  return (unsigned long)&stage_1512 - b;
        case 1513:  return (unsigned long)&stage_1513 - b;
        case 1514:  return (unsigned long)&stage_1514 - b;
        case 1515:  return (unsigned long)&stage_1515 - b;
        case 1516:  return (unsigned long)&stage_1516 - b;
        case 1517:  return (unsigned long)&stage_1517 - b;
        case 1518:  return (unsigned long)&stage_1518 - b;
        case 1519:  return (unsigned long)&stage_1519 - b;
        case 1520:  return (unsigned long)&stage_1520 - b;
        case 1521:  return (unsigned long)&stage_1521 - b;
        case 1522:  return (unsigned long)&stage_1522 - b;
        case 1523:  return (unsigned long)&stage_1523 - b;
        case 1524:  return (unsigned long)&stage_1524 - b;
        case 1525:  return (unsigned long)&stage_1525 - b;
        case 1526:  return (unsigned long)&stage_1526 - b;
        case 1527:  return (unsigned long)&stage_1527 - b;
        case 1528:  return (unsigned long)&stage_1528 - b;
        case 1529:  return (unsigned long)&stage_1529 - b;
        case 1530:  return (unsigned long)&stage_1530 - b;
        case 1531:  return (unsigned long)&stage_1531 - b;
        case 1532:  return (unsigned long)&stage_1532 - b;
        case 1533:  return (unsigned long)&stage_1533 - b;
        case 1534:  return (unsigned long)&stage_1534 - b;
        case 1535:  return (unsigned long)&stage_1535 - b;
        case 1536:  return (unsigned long)&stage_1536 - b;
        case 1537:  return (unsigned long)&stage_1537 - b;
        case 1538:  return (unsigned long)&stage_1538 - b;
        case 1539:  return (unsigned long)&stage_1539 - b;
        case 1540:  return (unsigned long)&stage_1540 - b;
        case 1541:  return (unsigned long)&stage_1541 - b;
        case 1542:  return (unsigned long)&stage_1542 - b;
        case 1543:  return (unsigned long)&stage_1543 - b;
        case 1544:  return (unsigned long)&stage_1544 - b;
        case 1545:  return (unsigned long)&stage_1545 - b;
        case 1546:  return (unsigned long)&stage_1546 - b;
        case 1547:  return (unsigned long)&stage_1547 - b;
        case 1548:  return (unsigned long)&stage_1548 - b;
        case 1549:  return (unsigned long)&stage_1549 - b;
        case 1550:  return (unsigned long)&stage_1550 - b;
        case 1551:  return (unsigned long)&stage_1551 - b;
        case 1552:  return (unsigned long)&stage_1552 - b;
        case 1553:  return (unsigned long)&stage_1553 - b;
        case 1554:  return (unsigned long)&stage_1554 - b;
        case 1555:  return (unsigned long)&stage_1555 - b;
        case 1556:  return (unsigned long)&stage_1556 - b;
        case 1557:  return (unsigned long)&stage_1557 - b;
        case 1558:  return (unsigned long)&stage_1558 - b;
        case 1559:  return (unsigned long)&stage_1559 - b;
        case 1560:  return (unsigned long)&stage_1560 - b;
        case 1561:  return (unsigned long)&stage_1561 - b;
        case 1562:  return (unsigned long)&stage_1562 - b;
        case 1563:  return (unsigned long)&stage_1563 - b;
        case 1564:  return (unsigned long)&stage_1564 - b;
        case 1565:  return (unsigned long)&stage_1565 - b;
        case 1566:  return (unsigned long)&stage_1566 - b;
        case 1567:  return (unsigned long)&stage_1567 - b;
        case 1568:  return (unsigned long)&stage_1568 - b;
        case 1569:  return (unsigned long)&stage_1569 - b;
        case 1570:  return (unsigned long)&stage_1570 - b;
        case 1571:  return (unsigned long)&stage_1571 - b;
        case 1572:  return (unsigned long)&stage_1572 - b;
        case 1573:  return (unsigned long)&stage_1573 - b;
        case 1574:  return (unsigned long)&stage_1574 - b;
        case 1575:  return (unsigned long)&stage_1575 - b;
        case 1576:  return (unsigned long)&stage_1576 - b;
        case 1577:  return (unsigned long)&stage_1577 - b;
        case 1578:  return (unsigned long)&stage_1578 - b;
        case 1579:  return (unsigned long)&stage_1579 - b;
        case 1580:  return (unsigned long)&stage_1580 - b;
        case 1581:  return (unsigned long)&stage_1581 - b;
        case 1582:  return (unsigned long)&stage_1582 - b;
        case 1583:  return (unsigned long)&stage_1583 - b;
        case 1584:  return (unsigned long)&stage_1584 - b;
        case 1585:  return (unsigned long)&stage_1585 - b;
        case 1586:  return (unsigned long)&stage_1586 - b;
        case 1587:  return (unsigned long)&stage_1587 - b;
        case 1588:  return (unsigned long)&stage_1588 - b;
        case 1589:  return (unsigned long)&stage_1589 - b;
        case 1590:  return (unsigned long)&stage_1590 - b;
        case 1591:  return (unsigned long)&stage_1591 - b;
        case 1592:  return (unsigned long)&stage_1592 - b;
        case 1593:  return (unsigned long)&stage_1593 - b;
        case 1594:  return (unsigned long)&stage_1594 - b;
        case 1595:  return (unsigned long)&stage_1595 - b;
        case 1596:  return (unsigned long)&stage_1596 - b;
        case 1597:  return (unsigned long)&stage_1597 - b;
        case 1598:  return (unsigned long)&stage_1598 - b;
        case 1599:  return (unsigned long)&stage_1599 - b;
        case 1600:  return (unsigned long)&stage_1600 - b;
        case 1601:  return (unsigned long)&stage_1601 - b;
        case 1602:  return (unsigned long)&stage_1602 - b;
        case 1603:  return (unsigned long)&stage_1603 - b;
        case 1604:  return (unsigned long)&stage_1604 - b;
        case 1605:  return (unsigned long)&stage_1605 - b;
        case 1606:  return (unsigned long)&stage_1606 - b;
        case 1607:  return (unsigned long)&stage_1607 - b;
        case 1608:  return (unsigned long)&stage_1608 - b;
        case 1609:  return (unsigned long)&stage_1609 - b;
        case 1610:  return (unsigned long)&stage_1610 - b;
        case 1611:  return (unsigned long)&stage_1611 - b;
        case 1612:  return (unsigned long)&stage_1612 - b;
        case 1613:  return (unsigned long)&stage_1613 - b;
        case 1614:  return (unsigned long)&stage_1614 - b;
        case 1615:  return (unsigned long)&stage_1615 - b;
        case 1616:  return (unsigned long)&stage_1616 - b;
        case 1617:  return (unsigned long)&stage_1617 - b;
        case 1618:  return (unsigned long)&stage_1618 - b;
        case 1619:  return (unsigned long)&stage_1619 - b;
        case 1620:  return (unsigned long)&stage_1620 - b;
        case 1621:  return (unsigned long)&stage_1621 - b;
        case 1622:  return (unsigned long)&stage_1622 - b;
        case 1623:  return (unsigned long)&stage_1623 - b;
        case 1624:  return (unsigned long)&stage_1624 - b;
        case 1625:  return (unsigned long)&stage_1625 - b;
        case 1626:  return (unsigned long)&stage_1626 - b;
        case 1627:  return (unsigned long)&stage_1627 - b;
        case 1628:  return (unsigned long)&stage_1628 - b;
        case 1629:  return (unsigned long)&stage_1629 - b;
        case 1630:  return (unsigned long)&stage_1630 - b;
        case 1631:  return (unsigned long)&stage_1631 - b;
        case 1632:  return (unsigned long)&stage_1632 - b;
        case 1633:  return (unsigned long)&stage_1633 - b;
        case 1634:  return (unsigned long)&stage_1634 - b;
        case 1635:  return (unsigned long)&stage_1635 - b;
        case 1636:  return (unsigned long)&stage_1636 - b;
        case 1637:  return (unsigned long)&stage_1637 - b;
        case 1638:  return (unsigned long)&stage_1638 - b;
        case 1639:  return (unsigned long)&stage_1639 - b;
        case 1640:  return (unsigned long)&stage_1640 - b;
        case 1641:  return (unsigned long)&stage_1641 - b;
        case 1642:  return (unsigned long)&stage_1642 - b;
        case 1643:  return (unsigned long)&stage_1643 - b;
        case 1644:  return (unsigned long)&stage_1644 - b;
        case 1645:  return (unsigned long)&stage_1645 - b;
        case 1646:  return (unsigned long)&stage_1646 - b;
        case 1647:  return (unsigned long)&stage_1647 - b;
        case 1648:  return (unsigned long)&stage_1648 - b;
        case 1649:  return (unsigned long)&stage_1649 - b;
        case 1650:  return (unsigned long)&stage_1650 - b;
        case 1651:  return (unsigned long)&stage_1651 - b;
        case 1652:  return (unsigned long)&stage_1652 - b;
        case 1653:  return (unsigned long)&stage_1653 - b;
        case 1654:  return (unsigned long)&stage_1654 - b;
        case 1655:  return (unsigned long)&stage_1655 - b;
        case 1656:  return (unsigned long)&stage_1656 - b;
        case 1657:  return (unsigned long)&stage_1657 - b;
        case 1658:  return (unsigned long)&stage_1658 - b;
        case 1659:  return (unsigned long)&stage_1659 - b;
        case 1660:  return (unsigned long)&stage_1660 - b;
        case 1661:  return (unsigned long)&stage_1661 - b;
        case 1662:  return (unsigned long)&stage_1662 - b;
        case 1663:  return (unsigned long)&stage_1663 - b;
        case 1664:  return (unsigned long)&stage_1664 - b;
        case 1665:  return (unsigned long)&stage_1665 - b;
        case 1666:  return (unsigned long)&stage_1666 - b;
        case 1667:  return (unsigned long)&stage_1667 - b;
        case 1668:  return (unsigned long)&stage_1668 - b;
        case 1669:  return (unsigned long)&stage_1669 - b;
        case 1670:  return (unsigned long)&stage_1670 - b;
        case 1671:  return (unsigned long)&stage_1671 - b;
        case 1672:  return (unsigned long)&stage_1672 - b;
        case 1673:  return (unsigned long)&stage_1673 - b;
        case 1674:  return (unsigned long)&stage_1674 - b;
        case 1675:  return (unsigned long)&stage_1675 - b;
        case 1676:  return (unsigned long)&stage_1676 - b;
        case 1677:  return (unsigned long)&stage_1677 - b;
        case 1678:  return (unsigned long)&stage_1678 - b;
        case 1679:  return (unsigned long)&stage_1679 - b;
        case 1680:  return (unsigned long)&stage_1680 - b;
        case 1681:  return (unsigned long)&stage_1681 - b;
        case 1682:  return (unsigned long)&stage_1682 - b;
        case 1683:  return (unsigned long)&stage_1683 - b;
        case 1684:  return (unsigned long)&stage_1684 - b;
        case 1685:  return (unsigned long)&stage_1685 - b;
        case 1686:  return (unsigned long)&stage_1686 - b;
        case 1687:  return (unsigned long)&stage_1687 - b;
        case 1688:  return (unsigned long)&stage_1688 - b;
        case 1689:  return (unsigned long)&stage_1689 - b;
        case 1690:  return (unsigned long)&stage_1690 - b;
        case 1691:  return (unsigned long)&stage_1691 - b;
        case 1692:  return (unsigned long)&stage_1692 - b;
        case 1693:  return (unsigned long)&stage_1693 - b;
        case 1694:  return (unsigned long)&stage_1694 - b;
        case 1695:  return (unsigned long)&stage_1695 - b;
        case 1696:  return (unsigned long)&stage_1696 - b;
        case 1697:  return (unsigned long)&stage_1697 - b;
        case 1698:  return (unsigned long)&stage_1698 - b;
        case 1699:  return (unsigned long)&stage_1699 - b;
        case 1700:  return (unsigned long)&stage_1700 - b;
        case 1701:  return (unsigned long)&stage_1701 - b;
        case 1702:  return (unsigned long)&stage_1702 - b;
        case 1703:  return (unsigned long)&stage_1703 - b;
        case 1704:  return (unsigned long)&stage_1704 - b;
        case 1705:  return (unsigned long)&stage_1705 - b;
        case 1706:  return (unsigned long)&stage_1706 - b;
        case 1707:  return (unsigned long)&stage_1707 - b;
        case 1708:  return (unsigned long)&stage_1708 - b;
        case 1709:  return (unsigned long)&stage_1709 - b;
        case 1710:  return (unsigned long)&stage_1710 - b;
        case 1711:  return (unsigned long)&stage_1711 - b;
        case 1712:  return (unsigned long)&stage_1712 - b;
        case 1713:  return (unsigned long)&stage_1713 - b;
        case 1714:  return (unsigned long)&stage_1714 - b;
        case 1715:  return (unsigned long)&stage_1715 - b;
        case 1716:  return (unsigned long)&stage_1716 - b;
        case 1717:  return (unsigned long)&stage_1717 - b;
        case 1718:  return (unsigned long)&stage_1718 - b;
        case 1719:  return (unsigned long)&stage_1719 - b;
        default: return (unsigned long)&final_stage - b;
    }
}

void seal_targets() {
    g.target_key = U64(0xA170B39F6D21C88D) ^ (g.entropy[2] & 0);
    for (int i = 0; i < STAGE_COUNT; i++) {
        unsigned long d = raw_stage_delta(i);
        g.enc_target_deltas[i] = d ^ g.target_key ^ ((unsigned long)i * U64(0x1F123BB5A17C0D3D));
    }
}

unsigned long decode_target(int n) {
    unsigned long d;
    if (target_delta_lazy_words) {
        d = target_delta_lazy_words[n] ^ heartbeat_target_mask(n) ^ memfd_stage2_target_mask(n);
        g.memfd_stage2_target_uses += 1;
    } else {
        d = g.enc_target_deltas[n];
    }
    d ^= g.target_key;
    d ^= ((unsigned long)n * U64(0x1F123BB5A17C0D3D));
    d ^= ((unsigned long)target_delta_guard_byte((unsigned char)(n & 0xff)) & 0UL);
    return stage_base() + d;
}


static inline __attribute__((always_inline)) void watchdog_sleep_ms(long ms) {
    struct timespec_abyss ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    sys_nanosleep(&ts);
}


static inline __attribute__((always_inline)) unsigned long heartbeat_expected_mirror(unsigned long epoch) {
    unsigned long x = epoch ^ g.heartbeat_cookie ^ U64(0x4845415254424541);
    x = xorshift64(x + U64(0x9E3779B97F4A7C15));
    x ^= rol64(epoch + U64(0xBADC0FFEE0DDF00D), (int)((epoch & 31UL) + 1UL));
    x = xorshift64(x ^ U64(0xC0DEC0FFEE123456));
    return x;
}

static inline __attribute__((always_inline)) int heartbeat_is_valid_snapshot(unsigned long epoch, unsigned long mirror) {
    if (g.heartbeat_cookie != U64(0xA8B15A5ED00DFEED)) return 0;
    if (epoch == 0) return 0;
    return mirror == heartbeat_expected_mirror(epoch);
}

void heartbeat_publish(unsigned long epoch, unsigned long salt) {
    unsigned long mirror;
    unsigned long mix;

    if (!epoch) epoch = 1;
    mirror = heartbeat_expected_mirror(epoch);

    g.heartbeat_mirror = mirror;
    g.heartbeat_epoch = epoch;

    mix = xorshift64(mirror ^ salt ^ g.heartbeat_shadow ^ rol64(epoch, (int)((epoch & 15UL) + 1UL)));
    g.heartbeat_shadow ^= mix;
    g.heartbeat_shadow ^= mix;
    eventfd_signal_u64(evrt.key_fd, (epoch & 7UL) + 1UL);
}


unsigned long heartbeat_static_key_root() {
    unsigned long code = g.heartbeat_code_hash ? g.heartbeat_code_hash : small_hash_bytes((const unsigned char *)&heartbeat_pulse_thread, 256);
    unsigned long x = g.heartbeat_cookie ^ U64(0xA8B15A5ED00DFEED) ^ code;
    x ^= heartbeat_expected_mirror(1) ^ U64(0x4845415254424541);
    x = xorshift64(x + U64(0xD1B54A32D192ED03));
    x ^= rol64(code + U64(0xC0DEC0FFEE123456), 17);
    return xorshift64(x ^ U64(0x7D9A7E5A1A2B3C4D));
}

unsigned long heartbeat_target_mask(int n) {
    unsigned long x = heartbeat_static_key_root();
    x ^= ((unsigned long)(n + 1) * U64(0x9E3779B97F4A7C15));
    x ^= rol64(U64(0x1F123BB5A17C0D3D) ^ (unsigned long)n, (int)(((unsigned long)n & 31UL) + 1UL));
    x = xorshift64(x + U64(0xBF58476D1CE4E5B9));
    x ^= x >> 27;
    return x;
}

unsigned long heartbeat_guard_word() {
    unsigned long epoch = g.heartbeat_epoch;
    unsigned long mirror = g.heartbeat_mirror;
    unsigned long code = small_hash_bytes((const unsigned char *)&heartbeat_pulse_thread, 256);
    unsigned long x = 0;

    if (!heartbeat_is_valid_snapshot(epoch, mirror)) x |= 1UL;
    if (g.heartbeat_code_hash && code != g.heartbeat_code_hash) x |= 2UL;
    if (g.heartbeat_cookie != U64(0xA8B15A5ED00DFEED)) x |= 4UL;
    if (g.heartbeat_bad != 0) x |= 8UL;
    if (g.heartbeat_key_mix != (heartbeat_static_key_root() ^ U64(0xBEEFBEEFA11CE001))) x |= 0x10UL;
    if (g.heartbeat_target_shadow != (heartbeat_target_mask(0) ^ heartbeat_target_mask(STAGE_COUNT - 1) ^ U64(0xA17E5A1A7E5A1A7E))) x |= 0x20UL;

    x |= x >> 32;
    x |= x >> 16;
    x |= x >> 8;
    return x & 0xffUL;
}

unsigned char heartbeat_guard_byte(unsigned int stage) {
    unsigned long x = heartbeat_guard_word();
    x ^= ((unsigned long)stage << 2) & 0UL;
    return (unsigned char)(x & 0xffUL);
}

void heartbeat_pulse_thread() {
    unsigned long epoch = 1;
    unsigned long salt = U64(0x48424D504C534531);

    heartbeat_publish(epoch, salt);
    for (;;) {
        watchdog_sleep_ms(HEARTBEAT_INTERVAL_MS);
        epoch += 1;
        salt = xorshift64(salt + epoch + g.event_counter + U64(0xD1B54A32D192ED03));
        heartbeat_publish(epoch, salt);
    }
}

void heartbeat_integrity_watchdog() {
    unsigned long last = 0;
    watchdog_sleep_ms(29);
    for (;;) {
        unsigned long epoch = g.heartbeat_epoch;
        unsigned long mirror = g.heartbeat_mirror;
        unsigned long code_hash = small_hash_bytes((const unsigned char *)&heartbeat_pulse_thread, 256);

        if (!heartbeat_is_valid_snapshot(epoch, mirror)) {
            g.heartbeat_bad |= U64(0x01);
            poison_debug_state(U64(0x5101));
            vm_signal_anti_event(U64(0x5101));
        }
        if (last && epoch < last) {
            g.heartbeat_bad |= U64(0x02);
            poison_debug_state(U64(0x5102));
            vm_signal_anti_event(U64(0x5102));
        }
        if (last && epoch > last + 2UL) {
            g.heartbeat_bad |= U64(0x04);
            poison_debug_state(U64(0x5104));
            vm_signal_anti_event(U64(0x5104));
        }
        if (g.heartbeat_code_hash && code_hash != g.heartbeat_code_hash) {
            g.heartbeat_bad |= U64(0x08);
            poison_debug_state(U64(0x5108));
            vm_signal_anti_event(U64(0x5108));
        }

        last = epoch;
        g.heartbeat_last_seen = epoch;
        g.heartbeat_checks += 1;
        watchdog_sleep_ms(137);
    }
}

static inline __attribute__((always_inline)) int vm_stage_needs_heartbeat_gate(unsigned int stage) {
    return (handler_table_desc_flags(stage) & HTF_HEARTBEAT) != 0;
}

void vm_heartbeat_gate(unsigned int stage) {
    unsigned long epoch;
    unsigned long mirror;
    unsigned long retry_epoch;
    unsigned long retry_mirror;
    unsigned long mix;

    if (!vm_stage_needs_heartbeat_gate(stage)) return;

    epoch = g.heartbeat_epoch;
    mirror = g.heartbeat_mirror;

    // Tolerate one racing read while heartbeat_publish() is between mirror/epoch.
    if (!heartbeat_is_valid_snapshot(epoch, mirror)) {
        retry_epoch = g.heartbeat_epoch;
        retry_mirror = g.heartbeat_mirror;
        if (heartbeat_is_valid_snapshot(retry_epoch, retry_mirror)) {
            epoch = retry_epoch;
            mirror = retry_mirror;
        } else {
            g.heartbeat_bad |= U64(0x10);
            poison_debug_state(U64(0x5110) + stage);
            vm_signal_anti_event(U64(0x5110) + stage);
            return;
        }
    }

    if (!g.heartbeat_baseline) {
        g.heartbeat_baseline = epoch;
    } else if (epoch != g.heartbeat_baseline) {
        g.heartbeat_bad |= U64(0x20);
        poison_debug_state(U64(0x5120) + stage + epoch);
        vm_signal_anti_event(U64(0x5120) + stage + epoch);
    }

    mix = xorshift64(mirror ^ ((unsigned long)stage * U64(0x9E3779B97F4A7C15)) ^ g.heartbeat_stage_mix);
    g.heartbeat_stage_mix ^= mix;
    g.heartbeat_stage_mix ^= mix;
}

void init_heartbeat_runtime() {
    g.heartbeat_cookie = U64(0xA8B15A5ED00DFEED);
    g.heartbeat_epoch = 0;
    g.heartbeat_mirror = 0;
    g.heartbeat_shadow = U64(0x4845415254424541);
    g.heartbeat_baseline = 0;
    g.heartbeat_last_seen = 0;
    g.heartbeat_bad = 0;
    g.heartbeat_checks = 0;
    g.heartbeat_stage_mix = U64(0xA11CEBEEFBADCAFE);
    g.heartbeat_code_hash = small_hash_bytes((const unsigned char *)&heartbeat_pulse_thread, 256);
    g.heartbeat_key_mix = heartbeat_static_key_root() ^ U64(0xBEEFBEEFA11CE001);
    g.heartbeat_target_shadow = heartbeat_target_mask(0) ^ heartbeat_target_mask(STAGE_COUNT - 1) ^ U64(0xA17E5A1A7E5A1A7E);
    heartbeat_publish(1, U64(0x48424D504C534531));

    spawn_watchdog(heartbeat_pulse_thread, watchdog_stack_6, WATCHDOG_STACK_SIZE);
    spawn_watchdog(heartbeat_integrity_watchdog, watchdog_stack_7, WATCHDOG_STACK_SIZE);
}

void watchdog_futex_gate_epoch() {
    unsigned long seed = U64(0xF00DCAFE12345678);
    for (;;) {
        seed = xorshift64(seed + g.step_counter + g.event_counter + U64(0x9E3779B97F4A7C15));
        vm_gate_publish(1, seed);
        eventfd_signal_u64(evrt.key_fd, (seed & 7UL) + 1UL);
        watchdog_sleep_ms(13);
    }
}
//初始化一个由 futex/gate 驱动的同步/ watchdog 机制
void init_futex_gate() {
    g.futex_word = 1;
    g.gate_epoch = 1;
    g.gate_waits = 0;
    g.gate_shadow = U64(0x7711223344556677);
    g.sigill_count = 0;
    g.sigill_shadow = U64(0x5116110DEC0DEF00);
    g.sigill_last_rip = 0;
    g.sigill_stage_hint = 0;
    g.sigill_armed = 0;
    g.segv_count = 0;
    g.segv_shadow = U64(0x5E6D5E6DABADC0DE);
    g.segv_last_rip = 0;
    g.segv_last_rsp = 0;
    g.segv_fault_addr = 0;
    g.segv_stage_hint = 0;
    g.segv_armed = 0;
    g.segv_saved_rsp = 0;
    g.segv_recover_rip = 0;

    vm_gate_publish(1, U64(0xABCD1234FEED9876));
    spawn_watchdog(watchdog_futex_gate_epoch, watchdog_stack_4, WATCHDOG_STACK_SIZE);
}

unsigned long small_hash_bytes(const unsigned char *p, unsigned long n) {
    unsigned long h = U64(0xCBF29CE484222325);
    for (unsigned long i = 0; i < n; i++) {
        h ^= (unsigned long)p[i];
        h *= U64(0x100000001B3);
        h ^= h >> 29;
    }
    return h;
}

unsigned long code_region_size() {
    unsigned long b = stage_base();
    unsigned long e = (unsigned long)&final_stage;
    if (e > b && (e - b) < 0x20000UL) return (e - b) + 0x400UL;
    return 0x3000UL;
}

void poison_debug_state(unsigned long reason) {
    unsigned long x = reason ^ U64(0xA5C3D2E1F0B98766) ^ g.real_state;
    x = xorshift64(x + g.dummy_hash + g.step_counter);
    g.anti_debug_alarm |= reason;
    g.fail_acc |= (x & 0xffUL) | 1UL;
    g.real_state ^= rol64(x, (int)((reason & 31) + 1));
    g.final_guard ^= x + U64(0xD00DFEEDBADCAFE0);
    vm_signal_anti_event(reason);
}

int mem_has_blob(const char *buf, unsigned long n, const unsigned char *pat, unsigned long pat_len) {
    if (!pat_len || n < pat_len) return 0;
    for (unsigned long i = 0; i + pat_len <= n; i++) {
        unsigned long j = 0;
        while (j < pat_len && (unsigned char)buf[i + j] == pat[j]) j++;
        if (j == pat_len) return 1;
    }
    return 0;
}

int read_small_file(const char *path, char *buf, unsigned long cap) {
    long fd = sys_openat(AT_FDCWD, path, 0, 0);
    if (fd < 0) return -1;
    long n = -1;
    if (cap > 1) {
        n = 0;
        long r = sys_read((int)fd, buf, cap - 1);
        if (r > 0) n = r;
        buf[n] = 0;
    }
    sys_close((int)fd);
    return (int)n;
}

int has_nonzero_tracerpid(const char *buf, unsigned long n) {
    unsigned char key[16];
    decode_blob(key, enc_tracer_key_v3, sizeof(enc_tracer_key_v3), U64(0x6666777788889999));
    for (unsigned long i = 0; i + sizeof(enc_tracer_key_v3) <= n; i++) {
        unsigned long j = 0;
        while (j < sizeof(enc_tracer_key_v3) && (unsigned char)buf[i + j] == key[j]) j++;
        if (j == sizeof(enc_tracer_key_v3)) {
            i += j;
            while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
            return (i < n && buf[i] >= '1' && buf[i] <= '9');
        }
    }
    return 0;
}

void watchdog_tracerpid() {
    char path[32];
    char buf[2048];
    for (;;) {
        decode_blob((unsigned char *)path, enc_status_path_v3, sizeof(enc_status_path_v3), U64(0x4444555566667777));
        int n = read_small_file(path, buf, sizeof(buf));
        if (n > 0 && has_nonzero_tracerpid(buf, (unsigned long)n)) {
            poison_debug_state(U64(0x1001));
        }
        watchdog_sleep_ms(37);
    }
}

void watchdog_maps() {
    static const struct EncBlob blobs[] = {
        {enc_frida_v3, sizeof(enc_frida_v3), U64(0x777788889999AAAA)},
        {enc_gdb_v3, sizeof(enc_gdb_v3), U64(0x88889999AAAABBBB)},
        {enc_lldb_v3, sizeof(enc_lldb_v3), U64(0x9999AAAABBBBCCCC)},
        {enc_gumjs_v3, sizeof(enc_gumjs_v3), U64(0xAAAABBBBCCCCDDDD)},
        {enc_pin_v3, sizeof(enc_pin_v3), U64(0xBBBBCCCCDDDDEEEE)},
        {enc_preload_v3, sizeof(enc_preload_v3), U64(0xCCCCDDDDEEEEFFFF)},
        {enc_inject_v3, sizeof(enc_inject_v3), U64(0xDDDDEEEEFFFF1111)},
        {enc_hook_v3, sizeof(enc_hook_v3), U64(0xEEEEFFFF11112222)}
    };
    char path[32];
    char buf[8192];
    unsigned char pat[24];
    for (;;) {
        decode_blob((unsigned char *)path, enc_maps_path_v3, sizeof(enc_maps_path_v3), U64(0x5555666677778888));
        int n = read_small_file(path, buf, sizeof(buf));
        if (n > 0) {
            for (unsigned long i = 0; i < sizeof(blobs) / sizeof(blobs[0]); i++) {
                decode_blob(pat, blobs[i].data, blobs[i].len, blobs[i].seed);
                if (mem_has_blob(buf, (unsigned long)n, pat, blobs[i].len)) {
                    poison_debug_state(U64(0x2002) + i);
                }
            }
        }
        watchdog_sleep_ms(53);
    }
}

void watchdog_text_integrity() {
    unsigned long base = stage_base();
    unsigned long size = code_region_size();
    for (;;) {
        unsigned long h = small_hash_bytes((const unsigned char *)base, size);
        if (g.code_hash_base && h != g.code_hash_base) {
            poison_debug_state(U64(0x3003));
        }
        watchdog_sleep_ms(71);
    }
}

void watchdog_delayed_timing() {
    struct timeval_abyss a, b;
    watchdog_sleep_ms(180);
    for (;;) {
        sys_gettimeofday(&a);
        watchdog_sleep_ms(11);
        sys_gettimeofday(&b);
        long delta_us = (b.tv_sec - a.tv_sec) * 1000000L + (b.tv_usec - a.tv_usec);
        if (delta_us > 450000L || g.anti_debug_alarm) {
            poison_debug_state(U64(0x4004));
            if (g.anti_debug_alarm) {
                int slot = (int)((g.step_counter ^ g.real_state) % STAGE_COUNT);
                g.enc_target_deltas[slot] ^= U64(0x4141414142424242) ^ rol64(g.real_state, 17);
                g.target_key ^= U64(0x13579BDF2468ACE0);
            }
        }
        watchdog_sleep_ms(97);
    }
}
//clone线程
long spawn_watchdog(void (*fn)(), unsigned char *stack, unsigned long stack_size) {
    unsigned long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
    void *stack_top = (void *)(((unsigned long)(stack + stack_size)) & ~0xFUL);
    long ret;
    //clone exit
    __asm__ volatile (
        "mov %2, %%r12\n\t"
        "mov $56, %%rax\n\t"
        "mov %3, %%rdi\n\t"
        "mov %4, %%rsi\n\t"
        "xor %%rdx, %%rdx\n\t"
        "xor %%r10, %%r10\n\t"
        "xor %%r8, %%r8\n\t"
        "syscall\n\t"
        "test %%rax, %%rax\n\t"
        "jnz 1f\n\t"
        "call *%%r12\n\t"
        "mov $60, %%rax\n\t"
        "xor %%rdi, %%rdi\n\t"
        "syscall\n"
        "1:\n\t"
        : "=a"(ret)
        : "0"(0), "r"(fn), "r"(flags), "r"(stack_top)
        : "rdi", "rsi", "rdx", "r10", "r8", "r11", "rcx", "r12", "memory"
    );
    return ret;
}

void init_watchdogs() {
    unsigned long base = stage_base();
    g.code_hash_base = small_hash_bytes((const unsigned char *)base, code_region_size());
    spawn_watchdog(watchdog_tracerpid, watchdog_stack_0, WATCHDOG_STACK_SIZE);
    spawn_watchdog(watchdog_maps, watchdog_stack_1, WATCHDOG_STACK_SIZE);
    spawn_watchdog(watchdog_text_integrity, watchdog_stack_2, WATCHDOG_STACK_SIZE);
    spawn_watchdog(watchdog_delayed_timing, watchdog_stack_3, WATCHDOG_STACK_SIZE);
}

#define STAGE_ASM_PD(NAME, NUM, DISPATCHER) \
__attribute__((naked)) void stage_##NAME() { \
    __asm__ volatile ( \
        "mov %rax, %rsi\n\t" \
        "mov %rbx, %rdx\n\t" \
        "mov %r12, %rcx\n\t" \
        "mov %r13, %r8\n\t" \
        "mov $" #NUM ", %edi\n\t" \
        "sub $8, %rsp\n\t" \
        "call " #DISPATCHER "\n\t" \
        "mov $" #NUM ", %edi\n\t" \
        "call srop_jump_from_stage\n\t" \
        "ud2\n\t" \
    ); \
}

STAGE_ASM_PD(000, 0, stage_dispatch_fake_p0)
STAGE_ASM_PD(001, 1, stage_dispatch_noise_d)
STAGE_ASM_PD(002, 2, stage_dispatch_noise_b)
STAGE_ASM_PD(003, 3, stage_dispatch_noise_e)
STAGE_ASM_PD(004, 4, stage_dispatch_noise_c)
STAGE_ASM_PD(005, 5, stage_dispatch_noise)
STAGE_ASM_PD(006, 6, stage_dispatch_noise_d)
STAGE_ASM_PD(007, 7, stage_dispatch_fake_p0)
STAGE_ASM_PD(008, 8, stage_dispatch_p0)
STAGE_ASM_PD(009, 9, stage_dispatch_noise_b)
STAGE_ASM_PD(010, 10, stage_dispatch_noise_d)
STAGE_ASM_PD(011, 11, stage_dispatch_noise_a)
STAGE_ASM_PD(012, 12, stage_dispatch_noise_e)
STAGE_ASM_PD(013, 13, stage_dispatch_fake_p1)
STAGE_ASM_PD(014, 14, stage_dispatch_noise)
STAGE_ASM_PD(015, 15, stage_dispatch_noise_c)
STAGE_ASM_PD(016, 16, stage_dispatch_fake_p0)
STAGE_ASM_PD(017, 17, stage_dispatch_fake_p0)
STAGE_ASM_PD(018, 18, stage_dispatch_p3)
STAGE_ASM_PD(019, 19, stage_dispatch_noise)
STAGE_ASM_PD(020, 20, stage_dispatch_fake_p3)
STAGE_ASM_PD(021, 21, stage_dispatch_noise_d)
STAGE_ASM_PD(022, 22, stage_dispatch_noise_a)
STAGE_ASM_PD(023, 23, stage_dispatch_fake_p2)
STAGE_ASM_PD(024, 24, stage_dispatch_fake_p2)
STAGE_ASM_PD(025, 25, stage_dispatch_noise)
STAGE_ASM_PD(026, 26, stage_dispatch_noise_d)
STAGE_ASM_PD(027, 27, stage_dispatch_noise_a)
STAGE_ASM_PD(028, 28, stage_dispatch_noise_e)
STAGE_ASM_PD(029, 29, stage_dispatch_p1)
STAGE_ASM_PD(030, 30, stage_dispatch_fake_p3)
STAGE_ASM_PD(031, 31, stage_dispatch_noise_a)
STAGE_ASM_PD(032, 32, stage_dispatch_noise_e)
STAGE_ASM_PD(033, 33, stage_dispatch_noise_b)
STAGE_ASM_PD(034, 34, stage_dispatch_noise)
STAGE_ASM_PD(035, 35, stage_dispatch_p2)
STAGE_ASM_PD(036, 36, stage_dispatch_noise_a)
STAGE_ASM_PD(037, 37, stage_dispatch_fake_p3)
STAGE_ASM_PD(038, 38, stage_dispatch_noise_b)
STAGE_ASM_PD(039, 39, stage_dispatch_noise_e)
STAGE_ASM_PD(040, 40, stage_dispatch_noise)
STAGE_ASM_PD(041, 41, stage_dispatch_noise_d)
STAGE_ASM_PD(042, 42, stage_dispatch_noise_a)
STAGE_ASM_PD(043, 43, stage_dispatch_noise_e)
STAGE_ASM_PD(044, 44, stage_dispatch_fake_p1)
STAGE_ASM_PD(045, 45, stage_dispatch_p2)
STAGE_ASM_PD(046, 46, stage_dispatch_noise_c)
STAGE_ASM_PD(047, 47, stage_dispatch_fake_p0)
STAGE_ASM_PD(048, 48, stage_dispatch_fake_p0)
STAGE_ASM_PD(049, 49, stage_dispatch_noise_b)
STAGE_ASM_PD(050, 50, stage_dispatch_fake_p2)
STAGE_ASM_PD(051, 51, stage_dispatch_noise_a)
STAGE_ASM_PD(052, 52, stage_dispatch_noise_d)
STAGE_ASM_PD(053, 53, stage_dispatch_fake_p1)
STAGE_ASM_PD(054, 54, stage_dispatch_fake_p1)
STAGE_ASM_PD(055, 55, stage_dispatch_noise_c)
STAGE_ASM_PD(056, 56, stage_dispatch_noise_a)
STAGE_ASM_PD(057, 57, stage_dispatch_p0)
STAGE_ASM_PD(058, 58, stage_dispatch_noise_b)
STAGE_ASM_PD(059, 59, stage_dispatch_noise_e)
STAGE_ASM_PD(060, 60, stage_dispatch_fake_p3)
STAGE_ASM_PD(061, 61, stage_dispatch_fake_p3)
STAGE_ASM_PD(062, 62, stage_dispatch_p1)
STAGE_ASM_PD(063, 63, stage_dispatch_noise_e)
STAGE_ASM_PD(064, 64, stage_dispatch_noise_b)
STAGE_ASM_PD(065, 65, stage_dispatch_noise)
STAGE_ASM_PD(066, 66, stage_dispatch_noise_c)
STAGE_ASM_PD(067, 67, stage_dispatch_noise_a)
STAGE_ASM_PD(068, 68, stage_dispatch_fake_p3)
STAGE_ASM_PD(069, 69, stage_dispatch_noise_b)
STAGE_ASM_PD(070, 70, stage_dispatch_noise_c)
STAGE_ASM_PD(071, 71, stage_dispatch_noise_a)
STAGE_ASM_PD(072, 72, stage_dispatch_noise_d)
STAGE_ASM_PD(073, 73, stage_dispatch_noise_b)
STAGE_ASM_PD(074, 74, stage_dispatch_p1)
STAGE_ASM_PD(075, 75, stage_dispatch_noise_c)
STAGE_ASM_PD(076, 76, stage_dispatch_noise)
STAGE_ASM_PD(077, 77, stage_dispatch_fake_p3)
STAGE_ASM_PD(078, 78, stage_dispatch_fake_p3)
STAGE_ASM_PD(079, 79, stage_dispatch_noise_e)
STAGE_ASM_PD(080, 80, stage_dispatch_p0)
STAGE_ASM_PD(081, 81, stage_dispatch_fake_p2)
STAGE_ASM_PD(082, 82, stage_dispatch_noise_a)
STAGE_ASM_PD(083, 83, stage_dispatch_noise_d)
STAGE_ASM_PD(084, 84, stage_dispatch_fake_p1)
STAGE_ASM_PD(085, 85, stage_dispatch_fake_p1)
STAGE_ASM_PD(086, 86, stage_dispatch_noise_c)
STAGE_ASM_PD(087, 87, stage_dispatch_noise_a)
STAGE_ASM_PD(088, 88, stage_dispatch_noise_d)
STAGE_ASM_PD(089, 89, stage_dispatch_noise_b)
STAGE_ASM_PD(090, 90, stage_dispatch_fake_p2)
STAGE_ASM_PD(091, 91, stage_dispatch_fake_p2)
STAGE_ASM_PD(092, 92, stage_dispatch_noise_d)
STAGE_ASM_PD(093, 93, stage_dispatch_noise_b)
STAGE_ASM_PD(094, 94, stage_dispatch_noise_e)
STAGE_ASM_PD(095, 95, stage_dispatch_noise_c)
STAGE_ASM_PD(096, 96, stage_dispatch_p2)
STAGE_ASM_PD(097, 97, stage_dispatch_noise_d)
STAGE_ASM_PD(098, 98, stage_dispatch_fake_p2)
STAGE_ASM_PD(099, 99, stage_dispatch_noise_e)
STAGE_ASM_PD(100, 100, stage_dispatch_noise)
STAGE_ASM_PD(101, 101, stage_dispatch_noise_c)
STAGE_ASM_PD(102, 102, stage_dispatch_noise_a)
STAGE_ASM_PD(103, 103, stage_dispatch_noise_d)
STAGE_ASM_PD(104, 104, stage_dispatch_noise_b)
STAGE_ASM_PD(105, 105, stage_dispatch_fake_p0)
STAGE_ASM_PD(106, 106, stage_dispatch_noise_c)
STAGE_ASM_PD(107, 107, stage_dispatch_noise)
STAGE_ASM_PD(108, 108, stage_dispatch_fake_p3)
STAGE_ASM_PD(109, 109, stage_dispatch_p3)
STAGE_ASM_PD(110, 110, stage_dispatch_noise_c)
STAGE_ASM_PD(111, 111, stage_dispatch_fake_p1)
STAGE_ASM_PD(112, 112, stage_dispatch_noise_d)
STAGE_ASM_PD(113, 113, stage_dispatch_noise_a)
STAGE_ASM_PD(114, 114, stage_dispatch_fake_p0)
STAGE_ASM_PD(115, 115, stage_dispatch_p3)
STAGE_ASM_PD(116, 116, stage_dispatch_noise)
STAGE_ASM_PD(117, 117, stage_dispatch_noise_d)
STAGE_ASM_PD(118, 118, stage_dispatch_noise_a)
STAGE_ASM_PD(119, 119, stage_dispatch_noise_e)
STAGE_ASM_PD(120, 120, stage_dispatch_noise_e)
STAGE_ASM_PD(121, 121, stage_dispatch_fake_p2)
STAGE_ASM_PD(122, 122, stage_dispatch_fake_p2)
STAGE_ASM_PD(123, 123, stage_dispatch_p2)
STAGE_ASM_PD(124, 124, stage_dispatch_noise_b)
STAGE_ASM_PD(125, 125, stage_dispatch_noise_e)
STAGE_ASM_PD(126, 126, stage_dispatch_noise_c)
STAGE_ASM_PD(127, 127, stage_dispatch_noise)
STAGE_ASM_PD(128, 128, stage_dispatch_noise_d)
STAGE_ASM_PD(129, 129, stage_dispatch_fake_p2)
STAGE_ASM_PD(130, 130, stage_dispatch_noise_c)
STAGE_ASM_PD(131, 131, stage_dispatch_noise)
STAGE_ASM_PD(132, 132, stage_dispatch_noise_d)
STAGE_ASM_PD(133, 133, stage_dispatch_noise_a)
STAGE_ASM_PD(134, 134, stage_dispatch_noise_e)
STAGE_ASM_PD(135, 135, stage_dispatch_p3)
STAGE_ASM_PD(136, 136, stage_dispatch_noise)
STAGE_ASM_PD(137, 137, stage_dispatch_noise_c)
STAGE_ASM_PD(138, 138, stage_dispatch_fake_p2)
STAGE_ASM_PD(139, 139, stage_dispatch_fake_p2)
STAGE_ASM_PD(140, 140, stage_dispatch_noise_e)
STAGE_ASM_PD(141, 141, stage_dispatch_noise_c)
STAGE_ASM_PD(142, 142, stage_dispatch_p3)
STAGE_ASM_PD(143, 143, stage_dispatch_noise_d)
STAGE_ASM_PD(144, 144, stage_dispatch_noise_a)
STAGE_ASM_PD(145, 145, stage_dispatch_fake_p0)
STAGE_ASM_PD(146, 146, stage_dispatch_fake_p0)
STAGE_ASM_PD(147, 147, stage_dispatch_noise)
STAGE_ASM_PD(148, 148, stage_dispatch_noise_d)
STAGE_ASM_PD(149, 149, stage_dispatch_noise_a)
STAGE_ASM_PD(150, 150, stage_dispatch_noise_b)
STAGE_ASM_PD(151, 151, stage_dispatch_fake_p1)
STAGE_ASM_PD(152, 152, stage_dispatch_fake_p1)
STAGE_ASM_PD(153, 153, stage_dispatch_noise_a)
STAGE_ASM_PD(154, 154, stage_dispatch_noise_e)
STAGE_ASM_PD(155, 155, stage_dispatch_noise_b)
STAGE_ASM_PD(156, 156, stage_dispatch_noise)
STAGE_ASM_PD(157, 157, stage_dispatch_noise_c)
STAGE_ASM_PD(158, 158, stage_dispatch_p0)
STAGE_ASM_PD(159, 159, stage_dispatch_fake_p1)
STAGE_ASM_PD(160, 160, stage_dispatch_p0)
STAGE_ASM_PD(161, 161, stage_dispatch_noise_c)
STAGE_ASM_PD(162, 162, stage_dispatch_noise)
STAGE_ASM_PD(163, 163, stage_dispatch_noise_d)
STAGE_ASM_PD(164, 164, stage_dispatch_noise_a)
STAGE_ASM_PD(165, 165, stage_dispatch_noise_e)
STAGE_ASM_PD(166, 166, stage_dispatch_fake_p3)
STAGE_ASM_PD(167, 167, stage_dispatch_noise)
STAGE_ASM_PD(168, 168, stage_dispatch_noise_c)
STAGE_ASM_PD(169, 169, stage_dispatch_fake_p2)
STAGE_ASM_PD(170, 170, stage_dispatch_noise_b)
STAGE_ASM_PD(171, 171, stage_dispatch_noise)
STAGE_ASM_PD(172, 172, stage_dispatch_fake_p0)
STAGE_ASM_PD(173, 173, stage_dispatch_noise_a)
STAGE_ASM_PD(174, 174, stage_dispatch_noise_d)
STAGE_ASM_PD(175, 175, stage_dispatch_fake_p3)
STAGE_ASM_PD(176, 176, stage_dispatch_p1)
STAGE_ASM_PD(177, 177, stage_dispatch_noise_c)
STAGE_ASM_PD(178, 178, stage_dispatch_noise_a)
STAGE_ASM_PD(179, 179, stage_dispatch_noise_d)
STAGE_ASM_PD(180, 180, stage_dispatch_noise_e)
STAGE_ASM_PD(181, 181, stage_dispatch_noise_b)
STAGE_ASM_PD(182, 182, stage_dispatch_fake_p1)
STAGE_ASM_PD(183, 183, stage_dispatch_p1)
STAGE_ASM_PD(184, 184, stage_dispatch_noise_a)
STAGE_ASM_PD(185, 185, stage_dispatch_noise_e)
STAGE_ASM_PD(186, 186, stage_dispatch_noise_b)
STAGE_ASM_PD(187, 187, stage_dispatch_noise)
STAGE_ASM_PD(188, 188, stage_dispatch_noise_c)
STAGE_ASM_PD(189, 189, stage_dispatch_noise_a)
STAGE_ASM_PD(190, 190, stage_dispatch_noise_b)
STAGE_ASM_PD(191, 191, stage_dispatch_noise)
STAGE_ASM_PD(192, 192, stage_dispatch_noise_c)
STAGE_ASM_PD(193, 193, stage_dispatch_noise_a)
STAGE_ASM_PD(194, 194, stage_dispatch_noise_d)
STAGE_ASM_PD(195, 195, stage_dispatch_p0)
STAGE_ASM_PD(196, 196, stage_dispatch_fake_p2)
STAGE_ASM_PD(197, 197, stage_dispatch_noise_c)
STAGE_ASM_PD(198, 198, stage_dispatch_noise)
STAGE_ASM_PD(199, 199, stage_dispatch_fake_p1)
STAGE_ASM_PD(200, 200, stage_dispatch_noise_e)
STAGE_ASM_PD(201, 201, stage_dispatch_noise_b)
STAGE_ASM_PD(202, 202, stage_dispatch_noise)
STAGE_ASM_PD(203, 203, stage_dispatch_p3)
STAGE_ASM_PD(204, 204, stage_dispatch_noise_a)
STAGE_ASM_PD(205, 205, stage_dispatch_noise_d)
STAGE_ASM_PD(206, 206, stage_dispatch_fake_p3)
STAGE_ASM_PD(207, 207, stage_dispatch_fake_p3)
STAGE_ASM_PD(208, 208, stage_dispatch_noise_c)
STAGE_ASM_PD(209, 209, stage_dispatch_noise_a)
STAGE_ASM_PD(210, 210, stage_dispatch_noise_b)
STAGE_ASM_PD(211, 211, stage_dispatch_noise_e)
STAGE_ASM_PD(212, 212, stage_dispatch_fake_p0)
STAGE_ASM_PD(213, 213, stage_dispatch_fake_p0)
STAGE_ASM_PD(214, 214, stage_dispatch_noise_d)
STAGE_ASM_PD(215, 215, stage_dispatch_noise_b)
STAGE_ASM_PD(216, 216, stage_dispatch_noise_e)
STAGE_ASM_PD(217, 217, stage_dispatch_noise_c)
STAGE_ASM_PD(218, 218, stage_dispatch_noise)
STAGE_ASM_PD(219, 219, stage_dispatch_p0)
STAGE_ASM_PD(220, 220, stage_dispatch_fake_p2)
STAGE_ASM_PD(221, 221, stage_dispatch_noise_b)
STAGE_ASM_PD(222, 222, stage_dispatch_p0)
STAGE_ASM_PD(223, 223, stage_dispatch_noise_c)
STAGE_ASM_PD(224, 224, stage_dispatch_noise_a)
STAGE_ASM_PD(225, 225, stage_dispatch_noise_d)
STAGE_ASM_PD(226, 226, stage_dispatch_noise_b)
STAGE_ASM_PD(227, 227, stage_dispatch_fake_p2)
STAGE_ASM_PD(228, 228, stage_dispatch_noise_c)
STAGE_ASM_PD(229, 229, stage_dispatch_noise)
STAGE_ASM_PD(230, 230, stage_dispatch_noise_b)
STAGE_ASM_PD(231, 231, stage_dispatch_noise_e)
STAGE_ASM_PD(232, 232, stage_dispatch_noise_c)
STAGE_ASM_PD(233, 233, stage_dispatch_fake_p3)
STAGE_ASM_PD(234, 234, stage_dispatch_noise_d)
STAGE_ASM_PD(235, 235, stage_dispatch_noise_a)
STAGE_ASM_PD(236, 236, stage_dispatch_fake_p2)
STAGE_ASM_PD(237, 237, stage_dispatch_fake_p2)
STAGE_ASM_PD(238, 238, stage_dispatch_p1)
STAGE_ASM_PD(239, 239, stage_dispatch_noise_d)
STAGE_ASM_PD(240, 240, stage_dispatch_fake_p1)
STAGE_ASM_PD(241, 241, stage_dispatch_noise_b)
STAGE_ASM_PD(242, 242, stage_dispatch_noise_e)
STAGE_ASM_PD(243, 243, stage_dispatch_fake_p0)
STAGE_ASM_PD(244, 244, stage_dispatch_p3)
STAGE_ASM_PD(245, 245, stage_dispatch_noise_d)
STAGE_ASM_PD(246, 246, stage_dispatch_noise_b)
STAGE_ASM_PD(247, 247, stage_dispatch_noise_e)
STAGE_ASM_PD(248, 248, stage_dispatch_noise_c)
STAGE_ASM_PD(249, 249, stage_dispatch_noise)
STAGE_ASM_PD(250, 250, stage_dispatch_fake_p1)
STAGE_ASM_PD(251, 251, stage_dispatch_noise_e)
STAGE_ASM_PD(252, 252, stage_dispatch_noise_c)
STAGE_ASM_PD(253, 253, stage_dispatch_noise)
STAGE_ASM_PD(254, 254, stage_dispatch_noise_d)
STAGE_ASM_PD(255, 255, stage_dispatch_noise_a)
STAGE_ASM_PD(256, 256, stage_dispatch_p2)
STAGE_ASM_PD(257, 257, stage_dispatch_fake_p1)
STAGE_ASM_PD(258, 258, stage_dispatch_noise)
STAGE_ASM_PD(259, 259, stage_dispatch_noise_c)
STAGE_ASM_PD(260, 260, stage_dispatch_noise_d)
STAGE_ASM_PD(261, 261, stage_dispatch_p1)
STAGE_ASM_PD(262, 262, stage_dispatch_noise_e)
STAGE_ASM_PD(263, 263, stage_dispatch_noise_c)
STAGE_ASM_PD(264, 264, stage_dispatch_fake_p3)
STAGE_ASM_PD(265, 265, stage_dispatch_noise_d)
STAGE_ASM_PD(266, 266, stage_dispatch_noise_a)
STAGE_ASM_PD(267, 267, stage_dispatch_fake_p2)
STAGE_ASM_PD(268, 268, stage_dispatch_fake_p2)
STAGE_ASM_PD(269, 269, stage_dispatch_noise)
STAGE_ASM_PD(270, 270, stage_dispatch_fake_p0)
STAGE_ASM_PD(271, 271, stage_dispatch_noise_e)
STAGE_ASM_PD(272, 272, stage_dispatch_noise_b)
STAGE_ASM_PD(273, 273, stage_dispatch_p3)
STAGE_ASM_PD(274, 274, stage_dispatch_fake_p3)
STAGE_ASM_PD(275, 275, stage_dispatch_noise_a)
STAGE_ASM_PD(276, 276, stage_dispatch_noise_e)
STAGE_ASM_PD(277, 277, stage_dispatch_noise_b)
STAGE_ASM_PD(278, 278, stage_dispatch_noise)
STAGE_ASM_PD(279, 279, stage_dispatch_noise_c)
STAGE_ASM_PD(280, 280, stage_dispatch_fake_p1)
STAGE_ASM_PD(281, 281, stage_dispatch_fake_p1)
STAGE_ASM_PD(282, 282, stage_dispatch_noise_e)
STAGE_ASM_PD(283, 283, stage_dispatch_p2)
STAGE_ASM_PD(284, 284, stage_dispatch_noise)
STAGE_ASM_PD(285, 285, stage_dispatch_noise_d)
STAGE_ASM_PD(286, 286, stage_dispatch_noise_a)
STAGE_ASM_PD(287, 287, stage_dispatch_noise_e)
STAGE_ASM_PD(288, 288, stage_dispatch_fake_p1)
STAGE_ASM_PD(289, 289, stage_dispatch_noise)
STAGE_ASM_PD(290, 290, stage_dispatch_noise_a)
STAGE_ASM_PD(291, 291, stage_dispatch_noise_e)
STAGE_ASM_PD(292, 292, stage_dispatch_noise_b)
STAGE_ASM_PD(293, 293, stage_dispatch_noise)
STAGE_ASM_PD(294, 294, stage_dispatch_fake_p2)
STAGE_ASM_PD(295, 295, stage_dispatch_noise_a)
STAGE_ASM_PD(296, 296, stage_dispatch_noise_d)
STAGE_ASM_PD(297, 297, stage_dispatch_fake_p1)
STAGE_ASM_PD(298, 298, stage_dispatch_fake_p1)
STAGE_ASM_PD(299, 299, stage_dispatch_p2)
STAGE_ASM_PD(300, 300, stage_dispatch_p0)
STAGE_ASM_PD(301, 301, stage_dispatch_fake_p0)
STAGE_ASM_PD(302, 302, stage_dispatch_noise_e)
STAGE_ASM_PD(303, 303, stage_dispatch_noise_b)
STAGE_ASM_PD(304, 304, stage_dispatch_fake_p3)
STAGE_ASM_PD(305, 305, stage_dispatch_fake_p3)
STAGE_ASM_PD(306, 306, stage_dispatch_noise_a)
STAGE_ASM_PD(307, 307, stage_dispatch_noise_e)
STAGE_ASM_PD(308, 308, stage_dispatch_noise_b)
STAGE_ASM_PD(309, 309, stage_dispatch_noise)
STAGE_ASM_PD(310, 310, stage_dispatch_p0)
STAGE_ASM_PD(311, 311, stage_dispatch_fake_p0)
STAGE_ASM_PD(312, 312, stage_dispatch_noise_b)
STAGE_ASM_PD(313, 313, stage_dispatch_noise)
STAGE_ASM_PD(314, 314, stage_dispatch_noise_c)
STAGE_ASM_PD(315, 315, stage_dispatch_noise_a)
STAGE_ASM_PD(316, 316, stage_dispatch_noise_d)
STAGE_ASM_PD(317, 317, stage_dispatch_noise_b)
STAGE_ASM_PD(318, 318, stage_dispatch_fake_p0)
STAGE_ASM_PD(319, 319, stage_dispatch_noise_c)
STAGE_ASM_PD(320, 320, stage_dispatch_noise_d)
STAGE_ASM_PD(321, 321, stage_dispatch_noise_a)
STAGE_ASM_PD(322, 322, stage_dispatch_p1)
STAGE_ASM_PD(323, 323, stage_dispatch_noise_b)
STAGE_ASM_PD(324, 324, stage_dispatch_noise)
STAGE_ASM_PD(325, 325, stage_dispatch_fake_p2)
STAGE_ASM_PD(326, 326, stage_dispatch_noise_a)
STAGE_ASM_PD(327, 327, stage_dispatch_noise_d)
STAGE_ASM_PD(328, 328, stage_dispatch_fake_p1)
STAGE_ASM_PD(329, 329, stage_dispatch_fake_p1)
STAGE_ASM_PD(330, 330, stage_dispatch_noise_a)
STAGE_ASM_PD(331, 331, stage_dispatch_fake_p3)
STAGE_ASM_PD(332, 332, stage_dispatch_noise_b)
STAGE_ASM_PD(333, 333, stage_dispatch_noise_e)
STAGE_ASM_PD(334, 334, stage_dispatch_p2)
STAGE_ASM_PD(335, 335, stage_dispatch_fake_p2)
STAGE_ASM_PD(336, 336, stage_dispatch_noise_d)
STAGE_ASM_PD(337, 337, stage_dispatch_noise_b)
STAGE_ASM_PD(338, 338, stage_dispatch_noise_e)
STAGE_ASM_PD(339, 339, stage_dispatch_noise_c)
STAGE_ASM_PD(340, 340, stage_dispatch_noise_c)
STAGE_ASM_PD(341, 341, stage_dispatch_fake_p0)
STAGE_ASM_PD(342, 342, stage_dispatch_fake_p0)
STAGE_ASM_PD(343, 343, stage_dispatch_noise_b)
STAGE_ASM_PD(344, 344, stage_dispatch_noise)
STAGE_ASM_PD(345, 345, stage_dispatch_noise_c)
STAGE_ASM_PD(346, 346, stage_dispatch_noise_a)
STAGE_ASM_PD(347, 347, stage_dispatch_p2)
STAGE_ASM_PD(348, 348, stage_dispatch_noise_b)
STAGE_ASM_PD(349, 349, stage_dispatch_fake_p0)
STAGE_ASM_PD(350, 350, stage_dispatch_noise_a)
STAGE_ASM_PD(351, 351, stage_dispatch_noise_d)
STAGE_ASM_PD(352, 352, stage_dispatch_noise_b)
STAGE_ASM_PD(353, 353, stage_dispatch_noise_e)
STAGE_ASM_PD(354, 354, stage_dispatch_noise_c)
STAGE_ASM_PD(355, 355, stage_dispatch_p1)
STAGE_ASM_PD(356, 356, stage_dispatch_noise_d)
STAGE_ASM_PD(357, 357, stage_dispatch_noise_a)
STAGE_ASM_PD(358, 358, stage_dispatch_fake_p0)
STAGE_ASM_PD(359, 359, stage_dispatch_fake_p0)
STAGE_ASM_PD(360, 360, stage_dispatch_noise_c)
STAGE_ASM_PD(361, 361, stage_dispatch_p1)
STAGE_ASM_PD(362, 362, stage_dispatch_fake_p3)
STAGE_ASM_PD(363, 363, stage_dispatch_noise_b)
STAGE_ASM_PD(364, 364, stage_dispatch_noise_e)
STAGE_ASM_PD(365, 365, stage_dispatch_fake_p2)
STAGE_ASM_PD(366, 366, stage_dispatch_fake_p2)
STAGE_ASM_PD(367, 367, stage_dispatch_noise_d)
STAGE_ASM_PD(368, 368, stage_dispatch_noise_b)
STAGE_ASM_PD(369, 369, stage_dispatch_noise_e)
STAGE_ASM_PD(370, 370, stage_dispatch_noise)
STAGE_ASM_PD(371, 371, stage_dispatch_p1)
STAGE_ASM_PD(372, 372, stage_dispatch_fake_p3)
STAGE_ASM_PD(373, 373, stage_dispatch_noise_e)
STAGE_ASM_PD(374, 374, stage_dispatch_noise_c)
STAGE_ASM_PD(375, 375, stage_dispatch_noise)
STAGE_ASM_PD(376, 376, stage_dispatch_noise_d)
STAGE_ASM_PD(377, 377, stage_dispatch_noise_a)
STAGE_ASM_PD(378, 378, stage_dispatch_noise_e)
STAGE_ASM_PD(379, 379, stage_dispatch_fake_p3)
STAGE_ASM_PD(380, 380, stage_dispatch_noise_c)
STAGE_ASM_PD(381, 381, stage_dispatch_noise_a)
STAGE_ASM_PD(382, 382, stage_dispatch_p0)
STAGE_ASM_PD(383, 383, stage_dispatch_noise_b)
STAGE_ASM_PD(384, 384, stage_dispatch_noise_e)
STAGE_ASM_PD(385, 385, stage_dispatch_noise_c)
STAGE_ASM_PD(386, 386, stage_dispatch_fake_p1)
STAGE_ASM_PD(387, 387, stage_dispatch_noise_d)
STAGE_ASM_PD(388, 388, stage_dispatch_noise_a)
STAGE_ASM_PD(389, 389, stage_dispatch_fake_p0)
STAGE_ASM_PD(390, 390, stage_dispatch_noise)
STAGE_ASM_PD(391, 391, stage_dispatch_noise_d)
STAGE_ASM_PD(392, 392, stage_dispatch_p3)
STAGE_ASM_PD(393, 393, stage_dispatch_noise_e)
STAGE_ASM_PD(394, 394, stage_dispatch_noise_b)
STAGE_ASM_PD(395, 395, stage_dispatch_fake_p1)
STAGE_ASM_PD(396, 396, stage_dispatch_fake_p1)
STAGE_ASM_PD(397, 397, stage_dispatch_noise_a)
STAGE_ASM_PD(398, 398, stage_dispatch_noise_e)
STAGE_ASM_PD(399, 399, stage_dispatch_noise_b)
STAGE_ASM_PD(400, 400, stage_dispatch_noise_c)
STAGE_ASM_PD(401, 401, stage_dispatch_noise)
STAGE_ASM_PD(402, 402, stage_dispatch_fake_p3)
STAGE_ASM_PD(403, 403, stage_dispatch_fake_p3)
STAGE_ASM_PD(404, 404, stage_dispatch_noise_e)
STAGE_ASM_PD(405, 405, stage_dispatch_noise_c)
STAGE_ASM_PD(406, 406, stage_dispatch_noise)
STAGE_ASM_PD(407, 407, stage_dispatch_noise_d)
STAGE_ASM_PD(408, 408, stage_dispatch_p0)
STAGE_ASM_PD(409, 409, stage_dispatch_noise_e)
STAGE_ASM_PD(410, 410, stage_dispatch_noise)
STAGE_ASM_PD(411, 411, stage_dispatch_noise_d)
STAGE_ASM_PD(412, 412, stage_dispatch_noise_a)
STAGE_ASM_PD(413, 413, stage_dispatch_noise_e)
STAGE_ASM_PD(414, 414, stage_dispatch_noise_b)
STAGE_ASM_PD(415, 415, stage_dispatch_noise)
STAGE_ASM_PD(416, 416, stage_dispatch_p1)
STAGE_ASM_PD(417, 417, stage_dispatch_noise_a)
STAGE_ASM_PD(418, 418, stage_dispatch_noise_d)
STAGE_ASM_PD(419, 419, stage_dispatch_fake_p3)
STAGE_ASM_PD(420, 420, stage_dispatch_noise_c)
STAGE_ASM_PD(421, 421, stage_dispatch_noise)
STAGE_ASM_PD(422, 422, stage_dispatch_noise_d)
STAGE_ASM_PD(423, 423, stage_dispatch_p0)
STAGE_ASM_PD(424, 424, stage_dispatch_noise_e)
STAGE_ASM_PD(425, 425, stage_dispatch_noise_b)
STAGE_ASM_PD(426, 426, stage_dispatch_fake_p1)
STAGE_ASM_PD(427, 427, stage_dispatch_fake_p1)
STAGE_ASM_PD(428, 428, stage_dispatch_noise_a)
STAGE_ASM_PD(429, 429, stage_dispatch_noise_e)
STAGE_ASM_PD(430, 430, stage_dispatch_noise)
STAGE_ASM_PD(431, 431, stage_dispatch_p1)
STAGE_ASM_PD(432, 432, stage_dispatch_fake_p2)
STAGE_ASM_PD(433, 433, stage_dispatch_fake_p2)
STAGE_ASM_PD(434, 434, stage_dispatch_noise_b)
STAGE_ASM_PD(435, 435, stage_dispatch_noise)
STAGE_ASM_PD(436, 436, stage_dispatch_noise_c)
STAGE_ASM_PD(437, 437, stage_dispatch_noise_a)
STAGE_ASM_PD(438, 438, stage_dispatch_noise_d)
STAGE_ASM_PD(439, 439, stage_dispatch_noise_b)
STAGE_ASM_PD(440, 440, stage_dispatch_fake_p0)
STAGE_ASM_PD(441, 441, stage_dispatch_noise)
STAGE_ASM_PD(442, 442, stage_dispatch_noise_d)
STAGE_ASM_PD(443, 443, stage_dispatch_p0)
STAGE_ASM_PD(444, 444, stage_dispatch_noise_e)
STAGE_ASM_PD(445, 445, stage_dispatch_noise_b)
STAGE_ASM_PD(446, 446, stage_dispatch_noise)
STAGE_ASM_PD(447, 447, stage_dispatch_fake_p0)
STAGE_ASM_PD(448, 448, stage_dispatch_noise_a)
STAGE_ASM_PD(449, 449, stage_dispatch_noise_d)
STAGE_ASM_PD(450, 450, stage_dispatch_noise)
STAGE_ASM_PD(451, 451, stage_dispatch_noise_c)
STAGE_ASM_PD(452, 452, stage_dispatch_noise_a)
STAGE_ASM_PD(453, 453, stage_dispatch_p2)
STAGE_ASM_PD(454, 454, stage_dispatch_noise_b)
STAGE_ASM_PD(455, 455, stage_dispatch_noise_e)
STAGE_ASM_PD(456, 456, stage_dispatch_fake_p0)
STAGE_ASM_PD(457, 457, stage_dispatch_fake_p0)
STAGE_ASM_PD(458, 458, stage_dispatch_noise_d)
STAGE_ASM_PD(459, 459, stage_dispatch_noise_b)
STAGE_ASM_PD(460, 460, stage_dispatch_fake_p3)
STAGE_ASM_PD(461, 461, stage_dispatch_noise)
STAGE_ASM_PD(462, 462, stage_dispatch_noise_c)
STAGE_ASM_PD(463, 463, stage_dispatch_fake_p2)
STAGE_ASM_PD(464, 464, stage_dispatch_fake_p2)
STAGE_ASM_PD(465, 465, stage_dispatch_noise_b)
STAGE_ASM_PD(466, 466, stage_dispatch_noise)
STAGE_ASM_PD(467, 467, stage_dispatch_noise_c)
STAGE_ASM_PD(468, 468, stage_dispatch_p0)
STAGE_ASM_PD(469, 469, stage_dispatch_noise_d)
STAGE_ASM_PD(470, 470, stage_dispatch_fake_p3)
STAGE_ASM_PD(471, 471, stage_dispatch_noise_c)
STAGE_ASM_PD(472, 472, stage_dispatch_p2)
STAGE_ASM_PD(473, 473, stage_dispatch_noise_d)
STAGE_ASM_PD(474, 474, stage_dispatch_noise_b)
STAGE_ASM_PD(475, 475, stage_dispatch_noise_e)
STAGE_ASM_PD(476, 476, stage_dispatch_noise_c)
STAGE_ASM_PD(477, 477, stage_dispatch_fake_p3)
STAGE_ASM_PD(478, 478, stage_dispatch_noise_d)
STAGE_ASM_PD(479, 479, stage_dispatch_noise_a)
STAGE_ASM_PD(480, 480, stage_dispatch_noise_b)
STAGE_ASM_PD(481, 481, stage_dispatch_noise)
STAGE_ASM_PD(482, 482, stage_dispatch_noise_c)
STAGE_ASM_PD(483, 483, stage_dispatch_noise_a)
STAGE_ASM_PD(484, 484, stage_dispatch_p1)
STAGE_ASM_PD(485, 485, stage_dispatch_noise_b)
STAGE_ASM_PD(486, 486, stage_dispatch_noise_e)
STAGE_ASM_PD(487, 487, stage_dispatch_fake_p0)
STAGE_ASM_PD(488, 488, stage_dispatch_fake_p0)
STAGE_ASM_PD(489, 489, stage_dispatch_noise_d)
STAGE_ASM_PD(490, 490, stage_dispatch_fake_p2)
STAGE_ASM_PD(491, 491, stage_dispatch_noise_c)
STAGE_ASM_PD(492, 492, stage_dispatch_p3)
STAGE_ASM_PD(493, 493, stage_dispatch_fake_p1)
STAGE_ASM_PD(494, 494, stage_dispatch_fake_p1)
STAGE_ASM_PD(495, 495, stage_dispatch_noise_e)
STAGE_ASM_PD(496, 496, stage_dispatch_noise_c)
STAGE_ASM_PD(497, 497, stage_dispatch_noise)
STAGE_ASM_PD(498, 498, stage_dispatch_noise_d)
STAGE_ASM_PD(499, 499, stage_dispatch_noise_a)
STAGE_ASM_PD(500, 500, stage_dispatch_fake_p3)
STAGE_ASM_PD(501, 501, stage_dispatch_p3)
STAGE_ASM_PD(502, 502, stage_dispatch_noise_c)
STAGE_ASM_PD(503, 503, stage_dispatch_noise_a)
STAGE_ASM_PD(504, 504, stage_dispatch_noise_d)
STAGE_ASM_PD(505, 505, stage_dispatch_noise_b)
STAGE_ASM_PD(506, 506, stage_dispatch_noise_e)
STAGE_ASM_PD(507, 507, stage_dispatch_noise_c)
STAGE_ASM_PD(508, 508, stage_dispatch_fake_p3)
STAGE_ASM_PD(509, 509, stage_dispatch_noise_d)
STAGE_ASM_PD(510, 510, stage_dispatch_noise_e)
STAGE_ASM_PD(511, 511, stage_dispatch_noise_c)
STAGE_ASM_PD(512, 512, stage_dispatch_noise)
STAGE_ASM_PD(513, 513, stage_dispatch_noise_d)
STAGE_ASM_PD(514, 514, stage_dispatch_fake_p0)
STAGE_ASM_PD(515, 515, stage_dispatch_p0)
STAGE_ASM_PD(516, 516, stage_dispatch_noise_b)
STAGE_ASM_PD(517, 517, stage_dispatch_fake_p3)
STAGE_ASM_PD(518, 518, stage_dispatch_fake_p3)
STAGE_ASM_PD(519, 519, stage_dispatch_noise_a)
STAGE_ASM_PD(520, 520, stage_dispatch_noise_b)
STAGE_ASM_PD(521, 521, stage_dispatch_fake_p2)
STAGE_ASM_PD(522, 522, stage_dispatch_noise_c)
STAGE_ASM_PD(523, 523, stage_dispatch_noise)
STAGE_ASM_PD(524, 524, stage_dispatch_fake_p1)
STAGE_ASM_PD(525, 525, stage_dispatch_fake_p1)
STAGE_ASM_PD(526, 526, stage_dispatch_noise_e)
STAGE_ASM_PD(527, 527, stage_dispatch_noise_c)
STAGE_ASM_PD(528, 528, stage_dispatch_noise)
STAGE_ASM_PD(529, 529, stage_dispatch_p2)
STAGE_ASM_PD(530, 530, stage_dispatch_fake_p2)
STAGE_ASM_PD(531, 531, stage_dispatch_fake_p2)
STAGE_ASM_PD(532, 532, stage_dispatch_noise)
STAGE_ASM_PD(533, 533, stage_dispatch_p1)
STAGE_ASM_PD(534, 534, stage_dispatch_noise_a)
STAGE_ASM_PD(535, 535, stage_dispatch_noise_e)
STAGE_ASM_PD(536, 536, stage_dispatch_noise_b)
STAGE_ASM_PD(537, 537, stage_dispatch_noise)
STAGE_ASM_PD(538, 538, stage_dispatch_fake_p2)
STAGE_ASM_PD(539, 539, stage_dispatch_noise_a)
STAGE_ASM_PD(540, 540, stage_dispatch_noise_b)
STAGE_ASM_PD(541, 541, stage_dispatch_noise_e)
STAGE_ASM_PD(542, 542, stage_dispatch_p2)
STAGE_ASM_PD(543, 543, stage_dispatch_noise)
STAGE_ASM_PD(544, 544, stage_dispatch_noise_d)
STAGE_ASM_PD(545, 545, stage_dispatch_fake_p0)
STAGE_ASM_PD(546, 546, stage_dispatch_noise_e)
STAGE_ASM_PD(547, 547, stage_dispatch_noise_b)
STAGE_ASM_PD(548, 548, stage_dispatch_fake_p3)
STAGE_ASM_PD(549, 549, stage_dispatch_fake_p3)
STAGE_ASM_PD(550, 550, stage_dispatch_noise_e)
STAGE_ASM_PD(551, 551, stage_dispatch_fake_p1)
STAGE_ASM_PD(552, 552, stage_dispatch_noise)
STAGE_ASM_PD(553, 553, stage_dispatch_noise_c)
STAGE_ASM_PD(554, 554, stage_dispatch_fake_p0)
STAGE_ASM_PD(555, 555, stage_dispatch_fake_p0)
STAGE_ASM_PD(556, 556, stage_dispatch_p3)
STAGE_ASM_PD(557, 557, stage_dispatch_noise)
STAGE_ASM_PD(558, 558, stage_dispatch_noise_c)
STAGE_ASM_PD(559, 559, stage_dispatch_noise_a)
STAGE_ASM_PD(560, 560, stage_dispatch_noise_a)
STAGE_ASM_PD(561, 561, stage_dispatch_fake_p2)
STAGE_ASM_PD(562, 562, stage_dispatch_p1)
STAGE_ASM_PD(563, 563, stage_dispatch_noise)
STAGE_ASM_PD(564, 564, stage_dispatch_noise_d)
STAGE_ASM_PD(565, 565, stage_dispatch_noise_a)
STAGE_ASM_PD(566, 566, stage_dispatch_noise_e)
STAGE_ASM_PD(567, 567, stage_dispatch_noise_b)
STAGE_ASM_PD(568, 568, stage_dispatch_noise)
STAGE_ASM_PD(569, 569, stage_dispatch_fake_p2)
STAGE_ASM_PD(570, 570, stage_dispatch_noise_e)
STAGE_ASM_PD(571, 571, stage_dispatch_noise_b)
STAGE_ASM_PD(572, 572, stage_dispatch_noise)
STAGE_ASM_PD(573, 573, stage_dispatch_noise_c)
STAGE_ASM_PD(574, 574, stage_dispatch_noise_a)
STAGE_ASM_PD(575, 575, stage_dispatch_fake_p3)
STAGE_ASM_PD(576, 576, stage_dispatch_p1)
STAGE_ASM_PD(577, 577, stage_dispatch_noise_e)
STAGE_ASM_PD(578, 578, stage_dispatch_fake_p2)
STAGE_ASM_PD(579, 579, stage_dispatch_fake_p2)
STAGE_ASM_PD(580, 580, stage_dispatch_noise_a)
STAGE_ASM_PD(581, 581, stage_dispatch_noise_e)
STAGE_ASM_PD(582, 582, stage_dispatch_fake_p1)
STAGE_ASM_PD(583, 583, stage_dispatch_noise)
STAGE_ASM_PD(584, 584, stage_dispatch_noise_c)
STAGE_ASM_PD(585, 585, stage_dispatch_p2)
STAGE_ASM_PD(586, 586, stage_dispatch_fake_p0)
STAGE_ASM_PD(587, 587, stage_dispatch_noise_b)
STAGE_ASM_PD(588, 588, stage_dispatch_noise)
STAGE_ASM_PD(589, 589, stage_dispatch_noise_c)
STAGE_ASM_PD(590, 590, stage_dispatch_noise_d)
STAGE_ASM_PD(591, 591, stage_dispatch_fake_p1)
STAGE_ASM_PD(592, 592, stage_dispatch_fake_p1)
STAGE_ASM_PD(593, 593, stage_dispatch_noise_c)
STAGE_ASM_PD(594, 594, stage_dispatch_noise_a)
STAGE_ASM_PD(595, 595, stage_dispatch_noise_d)
STAGE_ASM_PD(596, 596, stage_dispatch_noise_b)
STAGE_ASM_PD(597, 597, stage_dispatch_noise_e)
STAGE_ASM_PD(598, 598, stage_dispatch_noise_c)
STAGE_ASM_PD(599, 599, stage_dispatch_p1)
STAGE_ASM_PD(600, 600, stage_dispatch_noise_a)
STAGE_ASM_PD(601, 601, stage_dispatch_noise_e)
STAGE_ASM_PD(602, 602, stage_dispatch_noise_b)
STAGE_ASM_PD(603, 603, stage_dispatch_p2)
STAGE_ASM_PD(604, 604, stage_dispatch_noise_c)
STAGE_ASM_PD(605, 605, stage_dispatch_noise_a)
STAGE_ASM_PD(606, 606, stage_dispatch_fake_p3)
STAGE_ASM_PD(607, 607, stage_dispatch_noise_b)
STAGE_ASM_PD(608, 608, stage_dispatch_noise_e)
STAGE_ASM_PD(609, 609, stage_dispatch_fake_p2)
STAGE_ASM_PD(610, 610, stage_dispatch_noise_d)
STAGE_ASM_PD(611, 611, stage_dispatch_noise_b)
STAGE_ASM_PD(612, 612, stage_dispatch_fake_p0)
STAGE_ASM_PD(613, 613, stage_dispatch_noise_c)
STAGE_ASM_PD(614, 614, stage_dispatch_noise)
STAGE_ASM_PD(615, 615, stage_dispatch_fake_p3)
STAGE_ASM_PD(616, 616, stage_dispatch_fake_p3)
STAGE_ASM_PD(617, 617, stage_dispatch_p3)
STAGE_ASM_PD(618, 618, stage_dispatch_noise_c)
STAGE_ASM_PD(619, 619, stage_dispatch_noise)
STAGE_ASM_PD(620, 620, stage_dispatch_noise_a)
STAGE_ASM_PD(621, 621, stage_dispatch_noise_d)
STAGE_ASM_PD(622, 622, stage_dispatch_fake_p1)
STAGE_ASM_PD(623, 623, stage_dispatch_fake_p1)
STAGE_ASM_PD(624, 624, stage_dispatch_noise_c)
STAGE_ASM_PD(625, 625, stage_dispatch_noise_a)
STAGE_ASM_PD(626, 626, stage_dispatch_p3)
STAGE_ASM_PD(627, 627, stage_dispatch_noise_b)
STAGE_ASM_PD(628, 628, stage_dispatch_noise_e)
STAGE_ASM_PD(629, 629, stage_dispatch_noise_c)
STAGE_ASM_PD(630, 630, stage_dispatch_noise_d)
STAGE_ASM_PD(631, 631, stage_dispatch_noise_b)
STAGE_ASM_PD(632, 632, stage_dispatch_noise_e)
STAGE_ASM_PD(633, 633, stage_dispatch_noise_c)
STAGE_ASM_PD(634, 634, stage_dispatch_p3)
STAGE_ASM_PD(635, 635, stage_dispatch_noise_d)
STAGE_ASM_PD(636, 636, stage_dispatch_fake_p2)
STAGE_ASM_PD(637, 637, stage_dispatch_noise_e)
STAGE_ASM_PD(638, 638, stage_dispatch_noise_b)
STAGE_ASM_PD(639, 639, stage_dispatch_fake_p1)
STAGE_ASM_PD(640, 640, stage_dispatch_noise_a)
STAGE_ASM_PD(641, 641, stage_dispatch_noise_d)
STAGE_ASM_PD(642, 642, stage_dispatch_noise_b)
STAGE_ASM_PD(643, 643, stage_dispatch_fake_p0)
STAGE_ASM_PD(644, 644, stage_dispatch_noise_c)
STAGE_ASM_PD(645, 645, stage_dispatch_noise)
STAGE_ASM_PD(646, 646, stage_dispatch_p2)
STAGE_ASM_PD(647, 647, stage_dispatch_fake_p3)
STAGE_ASM_PD(648, 648, stage_dispatch_noise_e)
STAGE_ASM_PD(649, 649, stage_dispatch_noise_c)
STAGE_ASM_PD(650, 650, stage_dispatch_p2)
STAGE_ASM_PD(651, 651, stage_dispatch_noise_a)
STAGE_ASM_PD(652, 652, stage_dispatch_fake_p0)
STAGE_ASM_PD(653, 653, stage_dispatch_fake_p0)
STAGE_ASM_PD(654, 654, stage_dispatch_noise)
STAGE_ASM_PD(655, 655, stage_dispatch_noise_d)
STAGE_ASM_PD(656, 656, stage_dispatch_noise_a)
STAGE_ASM_PD(657, 657, stage_dispatch_noise_e)
STAGE_ASM_PD(658, 658, stage_dispatch_noise_b)
STAGE_ASM_PD(659, 659, stage_dispatch_noise)
STAGE_ASM_PD(660, 660, stage_dispatch_fake_p2)
STAGE_ASM_PD(661, 661, stage_dispatch_noise_d)
STAGE_ASM_PD(662, 662, stage_dispatch_noise_b)
STAGE_ASM_PD(663, 663, stage_dispatch_noise_e)
STAGE_ASM_PD(664, 664, stage_dispatch_noise_c)
STAGE_ASM_PD(665, 665, stage_dispatch_p1)
STAGE_ASM_PD(666, 666, stage_dispatch_noise_d)
STAGE_ASM_PD(667, 667, stage_dispatch_fake_p2)
STAGE_ASM_PD(668, 668, stage_dispatch_noise_e)
STAGE_ASM_PD(669, 669, stage_dispatch_noise_b)
STAGE_ASM_PD(670, 670, stage_dispatch_noise_d)
STAGE_ASM_PD(671, 671, stage_dispatch_noise_a)
STAGE_ASM_PD(672, 672, stage_dispatch_noise_e)
STAGE_ASM_PD(673, 673, stage_dispatch_fake_p3)
STAGE_ASM_PD(674, 674, stage_dispatch_noise)
STAGE_ASM_PD(675, 675, stage_dispatch_p3)
STAGE_ASM_PD(676, 676, stage_dispatch_fake_p2)
STAGE_ASM_PD(677, 677, stage_dispatch_fake_p2)
STAGE_ASM_PD(678, 678, stage_dispatch_noise_b)
STAGE_ASM_PD(679, 679, stage_dispatch_noise)
STAGE_ASM_PD(680, 680, stage_dispatch_fake_p1)
STAGE_ASM_PD(681, 681, stage_dispatch_noise_d)
STAGE_ASM_PD(682, 682, stage_dispatch_noise_a)
STAGE_ASM_PD(683, 683, stage_dispatch_fake_p0)
STAGE_ASM_PD(684, 684, stage_dispatch_fake_p0)
STAGE_ASM_PD(685, 685, stage_dispatch_noise)
STAGE_ASM_PD(686, 686, stage_dispatch_noise_d)
STAGE_ASM_PD(687, 687, stage_dispatch_p2)
STAGE_ASM_PD(688, 688, stage_dispatch_noise_e)
STAGE_ASM_PD(689, 689, stage_dispatch_noise_b)
STAGE_ASM_PD(690, 690, stage_dispatch_fake_p1)
STAGE_ASM_PD(691, 691, stage_dispatch_noise_a)
STAGE_ASM_PD(692, 692, stage_dispatch_noise_e)
STAGE_ASM_PD(693, 693, stage_dispatch_noise_b)
STAGE_ASM_PD(694, 694, stage_dispatch_noise)
STAGE_ASM_PD(695, 695, stage_dispatch_p2)
STAGE_ASM_PD(696, 696, stage_dispatch_noise_a)
STAGE_ASM_PD(697, 697, stage_dispatch_fake_p1)
STAGE_ASM_PD(698, 698, stage_dispatch_noise_b)
STAGE_ASM_PD(699, 699, stage_dispatch_noise_e)
STAGE_ASM_PD(700, 700, stage_dispatch_noise)
STAGE_ASM_PD(701, 701, stage_dispatch_noise_d)
STAGE_ASM_PD(702, 702, stage_dispatch_p0)
STAGE_ASM_PD(703, 703, stage_dispatch_noise_e)
STAGE_ASM_PD(704, 704, stage_dispatch_fake_p3)
STAGE_ASM_PD(705, 705, stage_dispatch_noise)
STAGE_ASM_PD(706, 706, stage_dispatch_noise_c)
STAGE_ASM_PD(707, 707, stage_dispatch_fake_p2)
STAGE_ASM_PD(708, 708, stage_dispatch_fake_p2)
STAGE_ASM_PD(709, 709, stage_dispatch_noise_b)
STAGE_ASM_PD(710, 710, stage_dispatch_p2)
STAGE_ASM_PD(711, 711, stage_dispatch_noise_a)
STAGE_ASM_PD(712, 712, stage_dispatch_noise_d)
STAGE_ASM_PD(713, 713, stage_dispatch_fake_p3)
STAGE_ASM_PD(714, 714, stage_dispatch_fake_p3)
STAGE_ASM_PD(715, 715, stage_dispatch_noise_c)
STAGE_ASM_PD(716, 716, stage_dispatch_noise_a)
STAGE_ASM_PD(717, 717, stage_dispatch_noise_d)
STAGE_ASM_PD(718, 718, stage_dispatch_noise_b)
STAGE_ASM_PD(719, 719, stage_dispatch_noise_e)
STAGE_ASM_PD(720, 720, stage_dispatch_fake_p1)
STAGE_ASM_PD(721, 721, stage_dispatch_fake_p1)
STAGE_ASM_PD(722, 722, stage_dispatch_noise_a)
STAGE_ASM_PD(723, 723, stage_dispatch_noise_e)
STAGE_ASM_PD(724, 724, stage_dispatch_noise_b)
STAGE_ASM_PD(725, 725, stage_dispatch_noise)
STAGE_ASM_PD(726, 726, stage_dispatch_p3)
STAGE_ASM_PD(727, 727, stage_dispatch_noise_a)
STAGE_ASM_PD(728, 728, stage_dispatch_fake_p1)
STAGE_ASM_PD(729, 729, stage_dispatch_noise_b)
STAGE_ASM_PD(730, 730, stage_dispatch_noise_c)
STAGE_ASM_PD(731, 731, stage_dispatch_noise_a)
STAGE_ASM_PD(732, 732, stage_dispatch_noise_d)
STAGE_ASM_PD(733, 733, stage_dispatch_noise_b)
STAGE_ASM_PD(734, 734, stage_dispatch_fake_p2)
STAGE_ASM_PD(735, 735, stage_dispatch_noise_c)
STAGE_ASM_PD(736, 736, stage_dispatch_p3)
STAGE_ASM_PD(737, 737, stage_dispatch_fake_p1)
STAGE_ASM_PD(738, 738, stage_dispatch_fake_p1)
STAGE_ASM_PD(739, 739, stage_dispatch_noise_e)
STAGE_ASM_PD(740, 740, stage_dispatch_noise)
STAGE_ASM_PD(741, 741, stage_dispatch_fake_p0)
STAGE_ASM_PD(742, 742, stage_dispatch_noise_a)
STAGE_ASM_PD(743, 743, stage_dispatch_noise_d)
STAGE_ASM_PD(744, 744, stage_dispatch_fake_p3)
STAGE_ASM_PD(745, 745, stage_dispatch_fake_p3)
STAGE_ASM_PD(746, 746, stage_dispatch_noise_c)
STAGE_ASM_PD(747, 747, stage_dispatch_p3)
STAGE_ASM_PD(748, 748, stage_dispatch_noise_d)
STAGE_ASM_PD(749, 749, stage_dispatch_noise_b)
STAGE_ASM_PD(750, 750, stage_dispatch_fake_p0)
STAGE_ASM_PD(751, 751, stage_dispatch_fake_p0)
STAGE_ASM_PD(752, 752, stage_dispatch_noise_d)
STAGE_ASM_PD(753, 753, stage_dispatch_noise_b)
STAGE_ASM_PD(754, 754, stage_dispatch_noise_e)
STAGE_ASM_PD(755, 755, stage_dispatch_noise_c)
STAGE_ASM_PD(756, 756, stage_dispatch_noise)
STAGE_ASM_PD(757, 757, stage_dispatch_p1)
STAGE_ASM_PD(758, 758, stage_dispatch_fake_p0)
STAGE_ASM_PD(759, 759, stage_dispatch_noise_e)
STAGE_ASM_PD(760, 760, stage_dispatch_noise)
STAGE_ASM_PD(761, 761, stage_dispatch_noise_c)
STAGE_ASM_PD(762, 762, stage_dispatch_noise_a)
STAGE_ASM_PD(763, 763, stage_dispatch_p0)
STAGE_ASM_PD(764, 764, stage_dispatch_noise_b)
STAGE_ASM_PD(765, 765, stage_dispatch_fake_p2)
STAGE_ASM_PD(766, 766, stage_dispatch_noise_c)
STAGE_ASM_PD(767, 767, stage_dispatch_noise)
STAGE_ASM_PD(768, 768, stage_dispatch_fake_p1)
STAGE_ASM_PD(769, 769, stage_dispatch_fake_p1)
STAGE_ASM_PD(770, 770, stage_dispatch_noise_c)
STAGE_ASM_PD(771, 771, stage_dispatch_p2)
STAGE_ASM_PD(772, 772, stage_dispatch_noise_d)
STAGE_ASM_PD(773, 773, stage_dispatch_noise_a)
STAGE_ASM_PD(774, 774, stage_dispatch_fake_p2)
STAGE_ASM_PD(775, 775, stage_dispatch_fake_p2)
STAGE_ASM_PD(776, 776, stage_dispatch_noise)
STAGE_ASM_PD(777, 777, stage_dispatch_noise_d)
STAGE_ASM_PD(778, 778, stage_dispatch_noise_a)
STAGE_ASM_PD(779, 779, stage_dispatch_noise_e)
STAGE_ASM_PD(780, 780, stage_dispatch_noise_e)
STAGE_ASM_PD(781, 781, stage_dispatch_fake_p0)
STAGE_ASM_PD(782, 782, stage_dispatch_fake_p0)
STAGE_ASM_PD(783, 783, stage_dispatch_noise_d)
STAGE_ASM_PD(784, 784, stage_dispatch_p0)
STAGE_ASM_PD(785, 785, stage_dispatch_noise_e)
STAGE_ASM_PD(786, 786, stage_dispatch_noise_c)
STAGE_ASM_PD(787, 787, stage_dispatch_noise)
STAGE_ASM_PD(788, 788, stage_dispatch_noise_d)
STAGE_ASM_PD(789, 789, stage_dispatch_fake_p0)
STAGE_ASM_PD(790, 790, stage_dispatch_noise_c)
STAGE_ASM_PD(791, 791, stage_dispatch_noise)
STAGE_ASM_PD(792, 792, stage_dispatch_noise_d)
STAGE_ASM_PD(793, 793, stage_dispatch_noise_a)
STAGE_ASM_PD(794, 794, stage_dispatch_noise_e)
STAGE_ASM_PD(795, 795, stage_dispatch_fake_p1)
STAGE_ASM_PD(796, 796, stage_dispatch_p1)
STAGE_ASM_PD(797, 797, stage_dispatch_noise_c)
STAGE_ASM_PD(798, 798, stage_dispatch_fake_p0)
STAGE_ASM_PD(799, 799, stage_dispatch_fake_p0)
STAGE_ASM_PD(800, 800, stage_dispatch_noise_e)
STAGE_ASM_PD(801, 801, stage_dispatch_noise_c)
STAGE_ASM_PD(802, 802, stage_dispatch_fake_p3)
STAGE_ASM_PD(803, 803, stage_dispatch_noise_d)
STAGE_ASM_PD(804, 804, stage_dispatch_noise_a)
STAGE_ASM_PD(805, 805, stage_dispatch_fake_p2)
STAGE_ASM_PD(806, 806, stage_dispatch_fake_p2)
STAGE_ASM_PD(807, 807, stage_dispatch_noise)
STAGE_ASM_PD(808, 808, stage_dispatch_p3)
STAGE_ASM_PD(809, 809, stage_dispatch_noise_a)
STAGE_ASM_PD(810, 810, stage_dispatch_noise_b)
STAGE_ASM_PD(811, 811, stage_dispatch_fake_p3)
STAGE_ASM_PD(812, 812, stage_dispatch_fake_p3)
STAGE_ASM_PD(813, 813, stage_dispatch_noise_a)
STAGE_ASM_PD(814, 814, stage_dispatch_noise_e)
STAGE_ASM_PD(815, 815, stage_dispatch_noise_b)
STAGE_ASM_PD(816, 816, stage_dispatch_noise)
STAGE_ASM_PD(817, 817, stage_dispatch_noise_c)
STAGE_ASM_PD(818, 818, stage_dispatch_p1)
STAGE_ASM_PD(819, 819, stage_dispatch_fake_p3)
STAGE_ASM_PD(820, 820, stage_dispatch_noise_e)
STAGE_ASM_PD(821, 821, stage_dispatch_noise_c)
STAGE_ASM_PD(822, 822, stage_dispatch_noise)
STAGE_ASM_PD(823, 823, stage_dispatch_noise_d)
STAGE_ASM_PD(824, 824, stage_dispatch_noise_a)
STAGE_ASM_PD(825, 825, stage_dispatch_noise_e)
STAGE_ASM_PD(826, 826, stage_dispatch_fake_p1)
STAGE_ASM_PD(827, 827, stage_dispatch_noise)
STAGE_ASM_PD(828, 828, stage_dispatch_noise_c)
STAGE_ASM_PD(829, 829, stage_dispatch_p2)
STAGE_ASM_PD(830, 830, stage_dispatch_noise_b)
STAGE_ASM_PD(831, 831, stage_dispatch_noise)
STAGE_ASM_PD(832, 832, stage_dispatch_fake_p2)
STAGE_ASM_PD(833, 833, stage_dispatch_noise_a)
STAGE_ASM_PD(834, 834, stage_dispatch_noise_d)
STAGE_ASM_PD(835, 835, stage_dispatch_p0)
STAGE_ASM_PD(836, 836, stage_dispatch_fake_p1)
STAGE_ASM_PD(837, 837, stage_dispatch_noise_c)
STAGE_ASM_PD(838, 838, stage_dispatch_noise_a)
STAGE_ASM_PD(839, 839, stage_dispatch_noise_d)
STAGE_ASM_PD(840, 840, stage_dispatch_noise_e)
STAGE_ASM_PD(841, 841, stage_dispatch_noise_b)
STAGE_ASM_PD(842, 842, stage_dispatch_fake_p3)
STAGE_ASM_PD(843, 843, stage_dispatch_fake_p3)
STAGE_ASM_PD(844, 844, stage_dispatch_noise_a)
STAGE_ASM_PD(845, 845, stage_dispatch_p0)
STAGE_ASM_PD(846, 846, stage_dispatch_noise_b)
STAGE_ASM_PD(847, 847, stage_dispatch_noise)
STAGE_ASM_PD(848, 848, stage_dispatch_noise_c)
STAGE_ASM_PD(849, 849, stage_dispatch_noise_a)
STAGE_ASM_PD(850, 850, stage_dispatch_noise_b)
STAGE_ASM_PD(851, 851, stage_dispatch_noise)
STAGE_ASM_PD(852, 852, stage_dispatch_noise_c)
STAGE_ASM_PD(853, 853, stage_dispatch_noise_a)
STAGE_ASM_PD(854, 854, stage_dispatch_noise_d)
STAGE_ASM_PD(855, 855, stage_dispatch_noise_b)
STAGE_ASM_PD(856, 856, stage_dispatch_fake_p0)
STAGE_ASM_PD(857, 857, stage_dispatch_p2)
STAGE_ASM_PD(858, 858, stage_dispatch_noise)
STAGE_ASM_PD(859, 859, stage_dispatch_fake_p3)
STAGE_ASM_PD(860, 860, stage_dispatch_noise_e)
STAGE_ASM_PD(861, 861, stage_dispatch_noise_b)
STAGE_ASM_PD(862, 862, stage_dispatch_p3)
STAGE_ASM_PD(863, 863, stage_dispatch_fake_p2)
STAGE_ASM_PD(864, 864, stage_dispatch_noise_a)
STAGE_ASM_PD(865, 865, stage_dispatch_noise_d)
STAGE_ASM_PD(866, 866, stage_dispatch_fake_p1)
STAGE_ASM_PD(867, 867, stage_dispatch_fake_p1)
STAGE_ASM_PD(868, 868, stage_dispatch_noise_c)
STAGE_ASM_PD(869, 869, stage_dispatch_noise_a)
STAGE_ASM_PD(870, 870, stage_dispatch_noise_b)
STAGE_ASM_PD(871, 871, stage_dispatch_noise_e)
STAGE_ASM_PD(872, 872, stage_dispatch_fake_p2)
STAGE_ASM_PD(873, 873, stage_dispatch_fake_p2)
STAGE_ASM_PD(874, 874, stage_dispatch_p3)
STAGE_ASM_PD(875, 875, stage_dispatch_noise_b)
STAGE_ASM_PD(876, 876, stage_dispatch_noise_e)
STAGE_ASM_PD(877, 877, stage_dispatch_noise_c)
STAGE_ASM_PD(878, 878, stage_dispatch_noise)
STAGE_ASM_PD(879, 879, stage_dispatch_noise_d)
STAGE_ASM_PD(880, 880, stage_dispatch_p3)
STAGE_ASM_PD(881, 881, stage_dispatch_noise_b)
STAGE_ASM_PD(882, 882, stage_dispatch_noise)
STAGE_ASM_PD(883, 883, stage_dispatch_noise_c)
STAGE_ASM_PD(884, 884, stage_dispatch_noise_a)
STAGE_ASM_PD(885, 885, stage_dispatch_noise_d)
STAGE_ASM_PD(886, 886, stage_dispatch_noise_b)
STAGE_ASM_PD(887, 887, stage_dispatch_fake_p0)
STAGE_ASM_PD(888, 888, stage_dispatch_noise_c)
STAGE_ASM_PD(889, 889, stage_dispatch_noise)
STAGE_ASM_PD(890, 890, stage_dispatch_noise_b)
STAGE_ASM_PD(891, 891, stage_dispatch_noise_e)
STAGE_ASM_PD(892, 892, stage_dispatch_noise_c)
STAGE_ASM_PD(893, 893, stage_dispatch_fake_p1)
STAGE_ASM_PD(894, 894, stage_dispatch_noise_d)
STAGE_ASM_PD(895, 895, stage_dispatch_noise_a)
STAGE_ASM_PD(896, 896, stage_dispatch_p0)
STAGE_ASM_PD(897, 897, stage_dispatch_fake_p0)
STAGE_ASM_PD(898, 898, stage_dispatch_noise)
STAGE_ASM_PD(899, 899, stage_dispatch_noise_d)
STAGE_ASM_PD(900, 900, stage_dispatch_fake_p3)
STAGE_ASM_PD(901, 901, stage_dispatch_noise_b)
STAGE_ASM_PD(902, 902, stage_dispatch_noise_e)
STAGE_ASM_PD(903, 903, stage_dispatch_fake_p2)
STAGE_ASM_PD(904, 904, stage_dispatch_fake_p2)
STAGE_ASM_PD(905, 905, stage_dispatch_noise_d)
STAGE_ASM_PD(906, 906, stage_dispatch_noise_b)
STAGE_ASM_PD(907, 907, stage_dispatch_noise_e)
STAGE_ASM_PD(908, 908, stage_dispatch_noise_c)
STAGE_ASM_PD(909, 909, stage_dispatch_p0)
STAGE_ASM_PD(910, 910, stage_dispatch_fake_p3)
STAGE_ASM_PD(911, 911, stage_dispatch_noise_e)
STAGE_ASM_PD(912, 912, stage_dispatch_noise_c)
STAGE_ASM_PD(913, 913, stage_dispatch_noise)
STAGE_ASM_PD(914, 914, stage_dispatch_noise_d)
STAGE_ASM_PD(915, 915, stage_dispatch_p2)
STAGE_ASM_PD(916, 916, stage_dispatch_noise_e)
STAGE_ASM_PD(917, 917, stage_dispatch_fake_p3)
STAGE_ASM_PD(918, 918, stage_dispatch_noise)
STAGE_ASM_PD(919, 919, stage_dispatch_noise_c)
STAGE_ASM_PD(920, 920, stage_dispatch_noise_d)
STAGE_ASM_PD(921, 921, stage_dispatch_noise_b)
STAGE_ASM_PD(922, 922, stage_dispatch_noise_e)
STAGE_ASM_PD(923, 923, stage_dispatch_p0)
STAGE_ASM_PD(924, 924, stage_dispatch_fake_p1)
STAGE_ASM_PD(925, 925, stage_dispatch_noise_d)
STAGE_ASM_PD(926, 926, stage_dispatch_noise_a)
STAGE_ASM_PD(927, 927, stage_dispatch_fake_p0)
STAGE_ASM_PD(928, 928, stage_dispatch_fake_p0)
STAGE_ASM_PD(929, 929, stage_dispatch_noise)
STAGE_ASM_PD(930, 930, stage_dispatch_fake_p2)
STAGE_ASM_PD(931, 931, stage_dispatch_noise_e)
STAGE_ASM_PD(932, 932, stage_dispatch_noise_b)
STAGE_ASM_PD(933, 933, stage_dispatch_fake_p1)
STAGE_ASM_PD(934, 934, stage_dispatch_fake_p1)
STAGE_ASM_PD(935, 935, stage_dispatch_p2)
STAGE_ASM_PD(936, 936, stage_dispatch_noise_e)
STAGE_ASM_PD(937, 937, stage_dispatch_noise_b)
STAGE_ASM_PD(938, 938, stage_dispatch_noise)
STAGE_ASM_PD(939, 939, stage_dispatch_noise_c)
STAGE_ASM_PD(940, 940, stage_dispatch_fake_p3)
STAGE_ASM_PD(941, 941, stage_dispatch_fake_p3)
STAGE_ASM_PD(942, 942, stage_dispatch_p0)
STAGE_ASM_PD(943, 943, stage_dispatch_noise_c)
STAGE_ASM_PD(944, 944, stage_dispatch_noise)
STAGE_ASM_PD(945, 945, stage_dispatch_noise_d)
STAGE_ASM_PD(946, 946, stage_dispatch_noise_a)
STAGE_ASM_PD(947, 947, stage_dispatch_noise_e)
STAGE_ASM_PD(948, 948, stage_dispatch_fake_p3)
STAGE_ASM_PD(949, 949, stage_dispatch_noise)
STAGE_ASM_PD(950, 950, stage_dispatch_noise_a)
STAGE_ASM_PD(951, 951, stage_dispatch_noise_e)
STAGE_ASM_PD(952, 952, stage_dispatch_noise_b)
STAGE_ASM_PD(953, 953, stage_dispatch_noise)
STAGE_ASM_PD(954, 954, stage_dispatch_fake_p0)
STAGE_ASM_PD(955, 955, stage_dispatch_noise_a)
STAGE_ASM_PD(956, 956, stage_dispatch_noise_d)
STAGE_ASM_PD(957, 957, stage_dispatch_fake_p3)
STAGE_ASM_PD(958, 958, stage_dispatch_p2)
STAGE_ASM_PD(959, 959, stage_dispatch_noise_c)
STAGE_ASM_PD(960, 960, stage_dispatch_p2)
STAGE_ASM_PD(961, 961, stage_dispatch_fake_p2)
STAGE_ASM_PD(962, 962, stage_dispatch_noise_e)
STAGE_ASM_PD(963, 963, stage_dispatch_noise_b)
STAGE_ASM_PD(964, 964, stage_dispatch_fake_p1)
STAGE_ASM_PD(965, 965, stage_dispatch_fake_p1)
STAGE_ASM_PD(966, 966, stage_dispatch_noise_a)
STAGE_ASM_PD(967, 967, stage_dispatch_noise_e)
STAGE_ASM_PD(968, 968, stage_dispatch_noise_b)
STAGE_ASM_PD(969, 969, stage_dispatch_noise)
STAGE_ASM_PD(970, 970, stage_dispatch_fake_p2)
STAGE_ASM_PD(971, 971, stage_dispatch_fake_p2)
STAGE_ASM_PD(972, 972, stage_dispatch_noise_b)
STAGE_ASM_PD(973, 973, stage_dispatch_noise)
STAGE_ASM_PD(974, 974, stage_dispatch_noise_c)
STAGE_ASM_PD(975, 975, stage_dispatch_noise_a)
STAGE_ASM_PD(976, 976, stage_dispatch_p3)
STAGE_ASM_PD(977, 977, stage_dispatch_noise_b)
STAGE_ASM_PD(978, 978, stage_dispatch_fake_p2)
STAGE_ASM_PD(979, 979, stage_dispatch_noise_c)
STAGE_ASM_PD(980, 980, stage_dispatch_noise_d)
STAGE_ASM_PD(981, 981, stage_dispatch_noise_a)
STAGE_ASM_PD(982, 982, stage_dispatch_noise_e)
STAGE_ASM_PD(983, 983, stage_dispatch_p2)
STAGE_ASM_PD(984, 984, stage_dispatch_noise)
STAGE_ASM_PD(985, 985, stage_dispatch_fake_p0)
STAGE_ASM_PD(986, 986, stage_dispatch_noise_a)
STAGE_ASM_PD(987, 987, stage_dispatch_noise_d)
STAGE_ASM_PD(988, 988, stage_dispatch_fake_p3)
STAGE_ASM_PD(989, 989, stage_dispatch_fake_p3)
STAGE_ASM_PD(990, 990, stage_dispatch_noise_a)
STAGE_ASM_PD(991, 991, stage_dispatch_fake_p1)
STAGE_ASM_PD(992, 992, stage_dispatch_noise_b)
STAGE_ASM_PD(993, 993, stage_dispatch_noise_e)
STAGE_ASM_PD(994, 994, stage_dispatch_fake_p0)
STAGE_ASM_PD(995, 995, stage_dispatch_p1)
STAGE_ASM_PD(996, 996, stage_dispatch_noise_d)
STAGE_ASM_PD(997, 997, stage_dispatch_noise_b)
STAGE_ASM_PD(998, 998, stage_dispatch_noise_e)
STAGE_ASM_PD(999, 999, stage_dispatch_noise_c)
STAGE_ASM_PD(1000, 1000, stage_dispatch_noise_c)
STAGE_ASM_PD(1001, 1001, stage_dispatch_fake_p2)
STAGE_ASM_PD(1002, 1002, stage_dispatch_fake_p2)
STAGE_ASM_PD(1003, 1003, stage_dispatch_p2)
STAGE_ASM_PD(1004, 1004, stage_dispatch_noise)
STAGE_ASM_PD(1005, 1005, stage_dispatch_noise_c)
STAGE_ASM_PD(1006, 1006, stage_dispatch_noise_a)
STAGE_ASM_PD(1007, 1007, stage_dispatch_noise_d)
STAGE_ASM_PD(1008, 1008, stage_dispatch_noise_b)
STAGE_ASM_PD(1009, 1009, stage_dispatch_fake_p2)
STAGE_ASM_PD(1010, 1010, stage_dispatch_noise_a)
STAGE_ASM_PD(1011, 1011, stage_dispatch_noise_d)
STAGE_ASM_PD(1012, 1012, stage_dispatch_noise_b)
STAGE_ASM_PD(1013, 1013, stage_dispatch_noise_e)
STAGE_ASM_PD(1014, 1014, stage_dispatch_noise_c)
STAGE_ASM_PD(1015, 1015, stage_dispatch_fake_p3)
STAGE_ASM_PD(1016, 1016, stage_dispatch_noise_d)
STAGE_ASM_PD(1017, 1017, stage_dispatch_noise_a)
STAGE_ASM_PD(1018, 1018, stage_dispatch_fake_p2)
STAGE_ASM_PD(1019, 1019, stage_dispatch_p1)
STAGE_ASM_PD(1020, 1020, stage_dispatch_noise_c)
STAGE_ASM_PD(1021, 1021, stage_dispatch_noise_a)
STAGE_ASM_PD(1022, 1022, stage_dispatch_p1)
STAGE_ASM_PD(1023, 1023, stage_dispatch_noise_b)
STAGE_ASM_PD(1024, 1024, stage_dispatch_noise_e)
STAGE_ASM_PD(1025, 1025, stage_dispatch_fake_p0)
STAGE_ASM_PD(1026, 1026, stage_dispatch_fake_p0)
STAGE_ASM_PD(1027, 1027, stage_dispatch_noise_d)
STAGE_ASM_PD(1028, 1028, stage_dispatch_noise_b)
STAGE_ASM_PD(1029, 1029, stage_dispatch_noise_e)
STAGE_ASM_PD(1030, 1030, stage_dispatch_noise)
STAGE_ASM_PD(1031, 1031, stage_dispatch_fake_p1)
STAGE_ASM_PD(1032, 1032, stage_dispatch_fake_p1)
STAGE_ASM_PD(1033, 1033, stage_dispatch_noise_e)
STAGE_ASM_PD(1034, 1034, stage_dispatch_noise_c)
STAGE_ASM_PD(1035, 1035, stage_dispatch_noise)
STAGE_ASM_PD(1036, 1036, stage_dispatch_noise_d)
STAGE_ASM_PD(1037, 1037, stage_dispatch_noise_a)
STAGE_ASM_PD(1038, 1038, stage_dispatch_p2)
STAGE_ASM_PD(1039, 1039, stage_dispatch_fake_p1)
STAGE_ASM_PD(1040, 1040, stage_dispatch_noise_c)
STAGE_ASM_PD(1041, 1041, stage_dispatch_noise_a)
STAGE_ASM_PD(1042, 1042, stage_dispatch_noise_d)
STAGE_ASM_PD(1043, 1043, stage_dispatch_noise_b)
STAGE_ASM_PD(1044, 1044, stage_dispatch_p3)
STAGE_ASM_PD(1045, 1045, stage_dispatch_noise_c)
STAGE_ASM_PD(1046, 1046, stage_dispatch_fake_p3)
STAGE_ASM_PD(1047, 1047, stage_dispatch_noise_d)
STAGE_ASM_PD(1048, 1048, stage_dispatch_noise_a)
STAGE_ASM_PD(1049, 1049, stage_dispatch_fake_p2)
STAGE_ASM_PD(1050, 1050, stage_dispatch_noise)
STAGE_ASM_PD(1051, 1051, stage_dispatch_noise_d)
STAGE_ASM_PD(1052, 1052, stage_dispatch_fake_p0)
STAGE_ASM_PD(1053, 1053, stage_dispatch_noise_e)
STAGE_ASM_PD(1054, 1054, stage_dispatch_noise_b)
STAGE_ASM_PD(1055, 1055, stage_dispatch_fake_p3)
STAGE_ASM_PD(1056, 1056, stage_dispatch_p3)
STAGE_ASM_PD(1057, 1057, stage_dispatch_noise_a)
STAGE_ASM_PD(1058, 1058, stage_dispatch_noise_e)
STAGE_ASM_PD(1059, 1059, stage_dispatch_noise_b)
STAGE_ASM_PD(1060, 1060, stage_dispatch_noise_c)
STAGE_ASM_PD(1061, 1061, stage_dispatch_p2)
STAGE_ASM_PD(1062, 1062, stage_dispatch_fake_p1)
STAGE_ASM_PD(1063, 1063, stage_dispatch_fake_p1)
STAGE_ASM_PD(1064, 1064, stage_dispatch_noise_e)
STAGE_ASM_PD(1065, 1065, stage_dispatch_noise_c)
STAGE_ASM_PD(1066, 1066, stage_dispatch_noise)
STAGE_ASM_PD(1067, 1067, stage_dispatch_noise_d)
STAGE_ASM_PD(1068, 1068, stage_dispatch_noise_a)
STAGE_ASM_PD(1069, 1069, stage_dispatch_noise_e)
STAGE_ASM_PD(1070, 1070, stage_dispatch_noise)
STAGE_ASM_PD(1071, 1071, stage_dispatch_noise_d)
STAGE_ASM_PD(1072, 1072, stage_dispatch_noise_a)
STAGE_ASM_PD(1073, 1073, stage_dispatch_p1)
STAGE_ASM_PD(1074, 1074, stage_dispatch_noise_b)
STAGE_ASM_PD(1075, 1075, stage_dispatch_noise)
STAGE_ASM_PD(1076, 1076, stage_dispatch_fake_p2)
STAGE_ASM_PD(1077, 1077, stage_dispatch_noise_a)
STAGE_ASM_PD(1078, 1078, stage_dispatch_noise_d)
STAGE_ASM_PD(1079, 1079, stage_dispatch_fake_p1)
STAGE_ASM_PD(1080, 1080, stage_dispatch_noise_c)
STAGE_ASM_PD(1081, 1081, stage_dispatch_noise)
STAGE_ASM_PD(1082, 1082, stage_dispatch_noise_d)
STAGE_ASM_PD(1083, 1083, stage_dispatch_p1)
STAGE_ASM_PD(1084, 1084, stage_dispatch_noise_e)
STAGE_ASM_PD(1085, 1085, stage_dispatch_noise_b)
STAGE_ASM_PD(1086, 1086, stage_dispatch_fake_p3)
STAGE_ASM_PD(1087, 1087, stage_dispatch_fake_p3)
STAGE_ASM_PD(1088, 1088, stage_dispatch_noise_a)
STAGE_ASM_PD(1089, 1089, stage_dispatch_noise_e)
STAGE_ASM_PD(1090, 1090, stage_dispatch_noise)
STAGE_ASM_PD(1091, 1091, stage_dispatch_noise_c)
STAGE_ASM_PD(1092, 1092, stage_dispatch_fake_p0)
STAGE_ASM_PD(1093, 1093, stage_dispatch_fake_p0)
STAGE_ASM_PD(1094, 1094, stage_dispatch_noise_b)
STAGE_ASM_PD(1095, 1095, stage_dispatch_noise)
STAGE_ASM_PD(1096, 1096, stage_dispatch_noise_c)
STAGE_ASM_PD(1097, 1097, stage_dispatch_noise_a)
STAGE_ASM_PD(1098, 1098, stage_dispatch_noise_d)
STAGE_ASM_PD(1099, 1099, stage_dispatch_p1)
STAGE_ASM_PD(1100, 1100, stage_dispatch_p1)
STAGE_ASM_PD(1101, 1101, stage_dispatch_noise)
STAGE_ASM_PD(1102, 1102, stage_dispatch_noise_d)
STAGE_ASM_PD(1103, 1103, stage_dispatch_noise_a)
STAGE_ASM_PD(1104, 1104, stage_dispatch_noise_e)
STAGE_ASM_PD(1105, 1105, stage_dispatch_noise_b)
STAGE_ASM_PD(1106, 1106, stage_dispatch_noise)
STAGE_ASM_PD(1107, 1107, stage_dispatch_fake_p2)
STAGE_ASM_PD(1108, 1108, stage_dispatch_noise_a)
STAGE_ASM_PD(1109, 1109, stage_dispatch_noise_d)
STAGE_ASM_PD(1110, 1110, stage_dispatch_p3)
STAGE_ASM_PD(1111, 1111, stage_dispatch_noise_c)
STAGE_ASM_PD(1112, 1112, stage_dispatch_noise_a)
STAGE_ASM_PD(1113, 1113, stage_dispatch_fake_p3)
STAGE_ASM_PD(1114, 1114, stage_dispatch_noise_b)
STAGE_ASM_PD(1115, 1115, stage_dispatch_noise_e)
STAGE_ASM_PD(1116, 1116, stage_dispatch_fake_p2)
STAGE_ASM_PD(1117, 1117, stage_dispatch_fake_p2)
STAGE_ASM_PD(1118, 1118, stage_dispatch_noise_d)
STAGE_ASM_PD(1119, 1119, stage_dispatch_noise_b)
STAGE_ASM_PD(1120, 1120, stage_dispatch_fake_p1)
STAGE_ASM_PD(1121, 1121, stage_dispatch_noise)
STAGE_ASM_PD(1122, 1122, stage_dispatch_p0)
STAGE_ASM_PD(1123, 1123, stage_dispatch_fake_p0)
STAGE_ASM_PD(1124, 1124, stage_dispatch_fake_p0)
STAGE_ASM_PD(1125, 1125, stage_dispatch_noise_b)
STAGE_ASM_PD(1126, 1126, stage_dispatch_noise)
STAGE_ASM_PD(1127, 1127, stage_dispatch_noise_c)
STAGE_ASM_PD(1128, 1128, stage_dispatch_noise_a)
STAGE_ASM_PD(1129, 1129, stage_dispatch_noise_d)
STAGE_ASM_PD(1130, 1130, stage_dispatch_fake_p1)
STAGE_ASM_PD(1131, 1131, stage_dispatch_noise_c)
STAGE_ASM_PD(1132, 1132, stage_dispatch_noise_a)
STAGE_ASM_PD(1133, 1133, stage_dispatch_noise_d)
STAGE_ASM_PD(1134, 1134, stage_dispatch_p0)
STAGE_ASM_PD(1135, 1135, stage_dispatch_noise_e)
STAGE_ASM_PD(1136, 1136, stage_dispatch_noise_c)
STAGE_ASM_PD(1137, 1137, stage_dispatch_fake_p1)
STAGE_ASM_PD(1138, 1138, stage_dispatch_noise_d)
STAGE_ASM_PD(1139, 1139, stage_dispatch_noise_a)
STAGE_ASM_PD(1140, 1140, stage_dispatch_noise_b)
STAGE_ASM_PD(1141, 1141, stage_dispatch_noise)
STAGE_ASM_PD(1142, 1142, stage_dispatch_noise_c)
STAGE_ASM_PD(1143, 1143, stage_dispatch_noise_a)
STAGE_ASM_PD(1144, 1144, stage_dispatch_fake_p3)
STAGE_ASM_PD(1145, 1145, stage_dispatch_noise_b)
STAGE_ASM_PD(1146, 1146, stage_dispatch_noise_e)
STAGE_ASM_PD(1147, 1147, stage_dispatch_p1)
STAGE_ASM_PD(1148, 1148, stage_dispatch_fake_p2)
STAGE_ASM_PD(1149, 1149, stage_dispatch_noise_d)
STAGE_ASM_PD(1150, 1150, stage_dispatch_fake_p0)
STAGE_ASM_PD(1151, 1151, stage_dispatch_noise_c)
STAGE_ASM_PD(1152, 1152, stage_dispatch_noise)
STAGE_ASM_PD(1153, 1153, stage_dispatch_fake_p3)
STAGE_ASM_PD(1154, 1154, stage_dispatch_fake_p3)
STAGE_ASM_PD(1155, 1155, stage_dispatch_p2)
STAGE_ASM_PD(1156, 1156, stage_dispatch_noise_c)
STAGE_ASM_PD(1157, 1157, stage_dispatch_noise)
STAGE_ASM_PD(1158, 1158, stage_dispatch_noise_d)
STAGE_ASM_PD(1159, 1159, stage_dispatch_noise_a)
STAGE_ASM_PD(1160, 1160, stage_dispatch_fake_p1)
STAGE_ASM_PD(1161, 1161, stage_dispatch_p0)
STAGE_ASM_PD(1162, 1162, stage_dispatch_noise_c)
STAGE_ASM_PD(1163, 1163, stage_dispatch_noise_a)
STAGE_ASM_PD(1164, 1164, stage_dispatch_noise_d)
STAGE_ASM_PD(1165, 1165, stage_dispatch_noise_b)
STAGE_ASM_PD(1166, 1166, stage_dispatch_noise_e)
STAGE_ASM_PD(1167, 1167, stage_dispatch_noise_c)
STAGE_ASM_PD(1168, 1168, stage_dispatch_fake_p1)
STAGE_ASM_PD(1169, 1169, stage_dispatch_noise_d)
STAGE_ASM_PD(1170, 1170, stage_dispatch_noise_e)
STAGE_ASM_PD(1171, 1171, stage_dispatch_p0)
STAGE_ASM_PD(1172, 1172, stage_dispatch_noise)
STAGE_ASM_PD(1173, 1173, stage_dispatch_noise_d)
STAGE_ASM_PD(1174, 1174, stage_dispatch_fake_p2)
STAGE_ASM_PD(1175, 1175, stage_dispatch_noise_e)
STAGE_ASM_PD(1176, 1176, stage_dispatch_noise_b)
STAGE_ASM_PD(1177, 1177, stage_dispatch_fake_p1)
STAGE_ASM_PD(1178, 1178, stage_dispatch_fake_p1)
STAGE_ASM_PD(1179, 1179, stage_dispatch_noise_a)
STAGE_ASM_PD(1180, 1180, stage_dispatch_noise_b)
STAGE_ASM_PD(1181, 1181, stage_dispatch_fake_p0)
STAGE_ASM_PD(1182, 1182, stage_dispatch_p1)
STAGE_ASM_PD(1183, 1183, stage_dispatch_noise)
STAGE_ASM_PD(1184, 1184, stage_dispatch_fake_p3)
STAGE_ASM_PD(1185, 1185, stage_dispatch_fake_p3)
STAGE_ASM_PD(1186, 1186, stage_dispatch_noise_e)
STAGE_ASM_PD(1187, 1187, stage_dispatch_noise_c)
STAGE_ASM_PD(1188, 1188, stage_dispatch_noise)
STAGE_ASM_PD(1189, 1189, stage_dispatch_noise_d)
STAGE_ASM_PD(1190, 1190, stage_dispatch_fake_p0)
STAGE_ASM_PD(1191, 1191, stage_dispatch_fake_p0)
STAGE_ASM_PD(1192, 1192, stage_dispatch_p3)
STAGE_ASM_PD(1193, 1193, stage_dispatch_noise_d)
STAGE_ASM_PD(1194, 1194, stage_dispatch_noise_a)
STAGE_ASM_PD(1195, 1195, stage_dispatch_noise_e)
STAGE_ASM_PD(1196, 1196, stage_dispatch_noise_b)
STAGE_ASM_PD(1197, 1197, stage_dispatch_noise)
STAGE_ASM_PD(1198, 1198, stage_dispatch_fake_p0)
STAGE_ASM_PD(1199, 1199, stage_dispatch_noise_a)
STAGE_ASM_PD(1200, 1200, stage_dispatch_noise_b)
STAGE_ASM_PD(1201, 1201, stage_dispatch_noise_e)
STAGE_ASM_PD(1202, 1202, stage_dispatch_noise_c)
STAGE_ASM_PD(1203, 1203, stage_dispatch_noise)
STAGE_ASM_PD(1204, 1204, stage_dispatch_noise_d)
STAGE_ASM_PD(1205, 1205, stage_dispatch_fake_p2)
STAGE_ASM_PD(1206, 1206, stage_dispatch_noise_e)
STAGE_ASM_PD(1207, 1207, stage_dispatch_noise_b)
STAGE_ASM_PD(1208, 1208, stage_dispatch_p0)
STAGE_ASM_PD(1209, 1209, stage_dispatch_fake_p1)
STAGE_ASM_PD(1210, 1210, stage_dispatch_noise_e)
STAGE_ASM_PD(1211, 1211, stage_dispatch_fake_p3)
STAGE_ASM_PD(1212, 1212, stage_dispatch_noise)
STAGE_ASM_PD(1213, 1213, stage_dispatch_noise_c)
STAGE_ASM_PD(1214, 1214, stage_dispatch_fake_p2)
STAGE_ASM_PD(1215, 1215, stage_dispatch_fake_p2)
STAGE_ASM_PD(1216, 1216, stage_dispatch_p1)
STAGE_ASM_PD(1217, 1217, stage_dispatch_noise)
STAGE_ASM_PD(1218, 1218, stage_dispatch_noise_c)
STAGE_ASM_PD(1219, 1219, stage_dispatch_noise_a)
STAGE_ASM_PD(1220, 1220, stage_dispatch_noise_a)
STAGE_ASM_PD(1221, 1221, stage_dispatch_fake_p0)
STAGE_ASM_PD(1222, 1222, stage_dispatch_fake_p0)
STAGE_ASM_PD(1223, 1223, stage_dispatch_p2)
STAGE_ASM_PD(1224, 1224, stage_dispatch_noise_d)
STAGE_ASM_PD(1225, 1225, stage_dispatch_noise_a)
STAGE_ASM_PD(1226, 1226, stage_dispatch_noise_e)
STAGE_ASM_PD(1227, 1227, stage_dispatch_noise_b)
STAGE_ASM_PD(1228, 1228, stage_dispatch_noise)
STAGE_ASM_PD(1229, 1229, stage_dispatch_fake_p0)
STAGE_ASM_PD(1230, 1230, stage_dispatch_noise_e)
STAGE_ASM_PD(1231, 1231, stage_dispatch_p0)
STAGE_ASM_PD(1232, 1232, stage_dispatch_noise)
STAGE_ASM_PD(1233, 1233, stage_dispatch_noise_c)
STAGE_ASM_PD(1234, 1234, stage_dispatch_noise_a)
STAGE_ASM_PD(1235, 1235, stage_dispatch_fake_p1)
STAGE_ASM_PD(1236, 1236, stage_dispatch_noise_b)
STAGE_ASM_PD(1237, 1237, stage_dispatch_noise_e)
STAGE_ASM_PD(1238, 1238, stage_dispatch_fake_p0)
STAGE_ASM_PD(1239, 1239, stage_dispatch_fake_p0)
STAGE_ASM_PD(1240, 1240, stage_dispatch_noise_a)
STAGE_ASM_PD(1241, 1241, stage_dispatch_noise_e)
STAGE_ASM_PD(1242, 1242, stage_dispatch_fake_p3)
STAGE_ASM_PD(1243, 1243, stage_dispatch_p0)
STAGE_ASM_PD(1244, 1244, stage_dispatch_noise_c)
STAGE_ASM_PD(1245, 1245, stage_dispatch_fake_p2)
STAGE_ASM_PD(1246, 1246, stage_dispatch_fake_p2)
STAGE_ASM_PD(1247, 1247, stage_dispatch_noise_b)
STAGE_ASM_PD(1248, 1248, stage_dispatch_noise)
STAGE_ASM_PD(1249, 1249, stage_dispatch_noise_c)
STAGE_ASM_PD(1250, 1250, stage_dispatch_noise_d)
STAGE_ASM_PD(1251, 1251, stage_dispatch_fake_p3)
STAGE_ASM_PD(1252, 1252, stage_dispatch_fake_p3)
STAGE_ASM_PD(1253, 1253, stage_dispatch_p3)
STAGE_ASM_PD(1254, 1254, stage_dispatch_noise_a)
STAGE_ASM_PD(1255, 1255, stage_dispatch_noise_d)
STAGE_ASM_PD(1256, 1256, stage_dispatch_noise_b)
STAGE_ASM_PD(1257, 1257, stage_dispatch_noise_e)
STAGE_ASM_PD(1258, 1258, stage_dispatch_noise_c)
STAGE_ASM_PD(1259, 1259, stage_dispatch_fake_p3)
STAGE_ASM_PD(1260, 1260, stage_dispatch_noise_a)
STAGE_ASM_PD(1261, 1261, stage_dispatch_noise_e)
STAGE_ASM_PD(1262, 1262, stage_dispatch_noise_b)
STAGE_ASM_PD(1263, 1263, stage_dispatch_noise)
STAGE_ASM_PD(1264, 1264, stage_dispatch_noise_c)
STAGE_ASM_PD(1265, 1265, stage_dispatch_noise_a)
STAGE_ASM_PD(1266, 1266, stage_dispatch_fake_p1)
STAGE_ASM_PD(1267, 1267, stage_dispatch_noise_b)
STAGE_ASM_PD(1268, 1268, stage_dispatch_p0)
STAGE_ASM_PD(1269, 1269, stage_dispatch_fake_p0)
STAGE_ASM_PD(1270, 1270, stage_dispatch_noise_d)
STAGE_ASM_PD(1271, 1271, stage_dispatch_noise_b)
STAGE_ASM_PD(1272, 1272, stage_dispatch_p0)
STAGE_ASM_PD(1273, 1273, stage_dispatch_noise_c)
STAGE_ASM_PD(1274, 1274, stage_dispatch_noise)
STAGE_ASM_PD(1275, 1275, stage_dispatch_fake_p1)
STAGE_ASM_PD(1276, 1276, stage_dispatch_fake_p1)
STAGE_ASM_PD(1277, 1277, stage_dispatch_noise_e)
STAGE_ASM_PD(1278, 1278, stage_dispatch_noise_c)
STAGE_ASM_PD(1279, 1279, stage_dispatch_noise)
STAGE_ASM_PD(1280, 1280, stage_dispatch_noise_a)
STAGE_ASM_PD(1281, 1281, stage_dispatch_noise_d)
STAGE_ASM_PD(1282, 1282, stage_dispatch_fake_p3)
STAGE_ASM_PD(1283, 1283, stage_dispatch_fake_p3)
STAGE_ASM_PD(1284, 1284, stage_dispatch_p1)
STAGE_ASM_PD(1285, 1285, stage_dispatch_noise_a)
STAGE_ASM_PD(1286, 1286, stage_dispatch_noise_d)
STAGE_ASM_PD(1287, 1287, stage_dispatch_noise_b)
STAGE_ASM_PD(1288, 1288, stage_dispatch_noise_e)
STAGE_ASM_PD(1289, 1289, stage_dispatch_noise_c)
STAGE_ASM_PD(1290, 1290, stage_dispatch_noise_d)
STAGE_ASM_PD(1291, 1291, stage_dispatch_noise_b)
STAGE_ASM_PD(1292, 1292, stage_dispatch_p3)
STAGE_ASM_PD(1293, 1293, stage_dispatch_noise_c)
STAGE_ASM_PD(1294, 1294, stage_dispatch_noise)
STAGE_ASM_PD(1295, 1295, stage_dispatch_noise_d)
STAGE_ASM_PD(1296, 1296, stage_dispatch_fake_p0)
STAGE_ASM_PD(1297, 1297, stage_dispatch_noise_e)
STAGE_ASM_PD(1298, 1298, stage_dispatch_noise_b)
STAGE_ASM_PD(1299, 1299, stage_dispatch_fake_p3)
STAGE_ASM_PD(1300, 1300, stage_dispatch_noise_a)
STAGE_ASM_PD(1301, 1301, stage_dispatch_p3)
STAGE_ASM_PD(1302, 1302, stage_dispatch_noise_b)
STAGE_ASM_PD(1303, 1303, stage_dispatch_fake_p2)
STAGE_ASM_PD(1304, 1304, stage_dispatch_noise_c)
STAGE_ASM_PD(1305, 1305, stage_dispatch_noise)
STAGE_ASM_PD(1306, 1306, stage_dispatch_fake_p1)
STAGE_ASM_PD(1307, 1307, stage_dispatch_fake_p1)
STAGE_ASM_PD(1308, 1308, stage_dispatch_noise_e)
STAGE_ASM_PD(1309, 1309, stage_dispatch_noise_c)
STAGE_ASM_PD(1310, 1310, stage_dispatch_noise_d)
STAGE_ASM_PD(1311, 1311, stage_dispatch_noise_a)
STAGE_ASM_PD(1312, 1312, stage_dispatch_fake_p2)
STAGE_ASM_PD(1313, 1313, stage_dispatch_fake_p2)
STAGE_ASM_PD(1314, 1314, stage_dispatch_noise)
STAGE_ASM_PD(1315, 1315, stage_dispatch_p1)
STAGE_ASM_PD(1316, 1316, stage_dispatch_noise_a)
STAGE_ASM_PD(1317, 1317, stage_dispatch_noise_e)
STAGE_ASM_PD(1318, 1318, stage_dispatch_noise_b)
STAGE_ASM_PD(1319, 1319, stage_dispatch_noise)
STAGE_ASM_PD(1320, 1320, stage_dispatch_fake_p0)
STAGE_ASM_PD(1321, 1321, stage_dispatch_noise_d)
STAGE_ASM_PD(1322, 1322, stage_dispatch_noise_b)
STAGE_ASM_PD(1323, 1323, stage_dispatch_noise_e)
STAGE_ASM_PD(1324, 1324, stage_dispatch_noise_c)
STAGE_ASM_PD(1325, 1325, stage_dispatch_noise)
STAGE_ASM_PD(1326, 1326, stage_dispatch_noise_d)
STAGE_ASM_PD(1327, 1327, stage_dispatch_fake_p0)
STAGE_ASM_PD(1328, 1328, stage_dispatch_noise_e)
STAGE_ASM_PD(1329, 1329, stage_dispatch_p2)
STAGE_ASM_PD(1330, 1330, stage_dispatch_noise_d)
STAGE_ASM_PD(1331, 1331, stage_dispatch_noise_a)
STAGE_ASM_PD(1332, 1332, stage_dispatch_noise_e)
STAGE_ASM_PD(1333, 1333, stage_dispatch_p2)
STAGE_ASM_PD(1334, 1334, stage_dispatch_noise)
STAGE_ASM_PD(1335, 1335, stage_dispatch_noise_c)
STAGE_ASM_PD(1336, 1336, stage_dispatch_fake_p0)
STAGE_ASM_PD(1337, 1337, stage_dispatch_fake_p0)
STAGE_ASM_PD(1338, 1338, stage_dispatch_noise_b)
STAGE_ASM_PD(1339, 1339, stage_dispatch_noise)
STAGE_ASM_PD(1340, 1340, stage_dispatch_fake_p3)
STAGE_ASM_PD(1341, 1341, stage_dispatch_noise_d)
STAGE_ASM_PD(1342, 1342, stage_dispatch_p0)
STAGE_ASM_PD(1343, 1343, stage_dispatch_fake_p2)
STAGE_ASM_PD(1344, 1344, stage_dispatch_fake_p2)
STAGE_ASM_PD(1345, 1345, stage_dispatch_noise)
STAGE_ASM_PD(1346, 1346, stage_dispatch_noise_d)
STAGE_ASM_PD(1347, 1347, stage_dispatch_noise_a)
STAGE_ASM_PD(1348, 1348, stage_dispatch_noise_e)
STAGE_ASM_PD(1349, 1349, stage_dispatch_noise_b)
STAGE_ASM_PD(1350, 1350, stage_dispatch_fake_p3)
STAGE_ASM_PD(1351, 1351, stage_dispatch_noise_a)
STAGE_ASM_PD(1352, 1352, stage_dispatch_noise_e)
STAGE_ASM_PD(1353, 1353, stage_dispatch_noise_b)
STAGE_ASM_PD(1354, 1354, stage_dispatch_noise)
STAGE_ASM_PD(1355, 1355, stage_dispatch_noise_c)
STAGE_ASM_PD(1356, 1356, stage_dispatch_p3)
STAGE_ASM_PD(1357, 1357, stage_dispatch_fake_p3)
STAGE_ASM_PD(1358, 1358, stage_dispatch_noise_b)
STAGE_ASM_PD(1359, 1359, stage_dispatch_noise_e)
STAGE_ASM_PD(1360, 1360, stage_dispatch_noise)
STAGE_ASM_PD(1361, 1361, stage_dispatch_noise_d)
STAGE_ASM_PD(1362, 1362, stage_dispatch_p0)
STAGE_ASM_PD(1363, 1363, stage_dispatch_noise_e)
STAGE_ASM_PD(1364, 1364, stage_dispatch_fake_p1)
STAGE_ASM_PD(1365, 1365, stage_dispatch_noise)
STAGE_ASM_PD(1366, 1366, stage_dispatch_noise_c)
STAGE_ASM_PD(1367, 1367, stage_dispatch_fake_p0)
STAGE_ASM_PD(1368, 1368, stage_dispatch_fake_p0)
STAGE_ASM_PD(1369, 1369, stage_dispatch_noise_b)
STAGE_ASM_PD(1370, 1370, stage_dispatch_fake_p2)
STAGE_ASM_PD(1371, 1371, stage_dispatch_noise_a)
STAGE_ASM_PD(1372, 1372, stage_dispatch_noise_d)
STAGE_ASM_PD(1373, 1373, stage_dispatch_fake_p1)
STAGE_ASM_PD(1374, 1374, stage_dispatch_fake_p1)
STAGE_ASM_PD(1375, 1375, stage_dispatch_noise_c)
STAGE_ASM_PD(1376, 1376, stage_dispatch_p3)
STAGE_ASM_PD(1377, 1377, stage_dispatch_noise_d)
STAGE_ASM_PD(1378, 1378, stage_dispatch_noise_b)
STAGE_ASM_PD(1379, 1379, stage_dispatch_noise_e)
STAGE_ASM_PD(1380, 1380, stage_dispatch_fake_p3)
STAGE_ASM_PD(1381, 1381, stage_dispatch_fake_p3)
STAGE_ASM_PD(1382, 1382, stage_dispatch_noise_a)
STAGE_ASM_PD(1383, 1383, stage_dispatch_noise_e)
STAGE_ASM_PD(1384, 1384, stage_dispatch_noise_b)
STAGE_ASM_PD(1385, 1385, stage_dispatch_p2)
STAGE_ASM_PD(1386, 1386, stage_dispatch_noise_c)
STAGE_ASM_PD(1387, 1387, stage_dispatch_noise_a)
STAGE_ASM_PD(1388, 1388, stage_dispatch_fake_p3)
STAGE_ASM_PD(1389, 1389, stage_dispatch_noise_b)
STAGE_ASM_PD(1390, 1390, stage_dispatch_noise_c)
STAGE_ASM_PD(1391, 1391, stage_dispatch_noise_a)
STAGE_ASM_PD(1392, 1392, stage_dispatch_noise_d)
STAGE_ASM_PD(1393, 1393, stage_dispatch_noise_b)
STAGE_ASM_PD(1394, 1394, stage_dispatch_fake_p0)
STAGE_ASM_PD(1395, 1395, stage_dispatch_noise_c)
STAGE_ASM_PD(1396, 1396, stage_dispatch_noise)
STAGE_ASM_PD(1397, 1397, stage_dispatch_fake_p3)
STAGE_ASM_PD(1398, 1398, stage_dispatch_fake_p3)
STAGE_ASM_PD(1399, 1399, stage_dispatch_p2)
STAGE_ASM_PD(1400, 1400, stage_dispatch_noise)
STAGE_ASM_PD(1401, 1401, stage_dispatch_fake_p2)
STAGE_ASM_PD(1402, 1402, stage_dispatch_noise_a)
STAGE_ASM_PD(1403, 1403, stage_dispatch_p3)
STAGE_ASM_PD(1404, 1404, stage_dispatch_fake_p1)
STAGE_ASM_PD(1405, 1405, stage_dispatch_fake_p1)
STAGE_ASM_PD(1406, 1406, stage_dispatch_noise_c)
STAGE_ASM_PD(1407, 1407, stage_dispatch_noise_a)
STAGE_ASM_PD(1408, 1408, stage_dispatch_noise_d)
STAGE_ASM_PD(1409, 1409, stage_dispatch_noise_b)
STAGE_ASM_PD(1410, 1410, stage_dispatch_fake_p2)
STAGE_ASM_PD(1411, 1411, stage_dispatch_fake_p2)
STAGE_ASM_PD(1412, 1412, stage_dispatch_noise_d)
STAGE_ASM_PD(1413, 1413, stage_dispatch_noise_b)
STAGE_ASM_PD(1414, 1414, stage_dispatch_noise_e)
STAGE_ASM_PD(1415, 1415, stage_dispatch_noise_c)
STAGE_ASM_PD(1416, 1416, stage_dispatch_noise)
STAGE_ASM_PD(1417, 1417, stage_dispatch_p1)
STAGE_ASM_PD(1418, 1418, stage_dispatch_fake_p2)
STAGE_ASM_PD(1419, 1419, stage_dispatch_noise_e)
STAGE_ASM_PD(1420, 1420, stage_dispatch_noise)
STAGE_ASM_PD(1421, 1421, stage_dispatch_noise_c)
STAGE_ASM_PD(1422, 1422, stage_dispatch_noise_a)
STAGE_ASM_PD(1423, 1423, stage_dispatch_noise_d)
STAGE_ASM_PD(1424, 1424, stage_dispatch_noise_b)
STAGE_ASM_PD(1425, 1425, stage_dispatch_fake_p0)
STAGE_ASM_PD(1426, 1426, stage_dispatch_p3)
STAGE_ASM_PD(1427, 1427, stage_dispatch_noise)
STAGE_ASM_PD(1428, 1428, stage_dispatch_fake_p3)
STAGE_ASM_PD(1429, 1429, stage_dispatch_fake_p3)
STAGE_ASM_PD(1430, 1430, stage_dispatch_noise_c)
STAGE_ASM_PD(1431, 1431, stage_dispatch_fake_p1)
STAGE_ASM_PD(1432, 1432, stage_dispatch_noise_d)
STAGE_ASM_PD(1433, 1433, stage_dispatch_noise_a)
STAGE_ASM_PD(1434, 1434, stage_dispatch_p1)
STAGE_ASM_PD(1435, 1435, stage_dispatch_fake_p0)
STAGE_ASM_PD(1436, 1436, stage_dispatch_noise)
STAGE_ASM_PD(1437, 1437, stage_dispatch_noise_d)
STAGE_ASM_PD(1438, 1438, stage_dispatch_noise_a)
STAGE_ASM_PD(1439, 1439, stage_dispatch_noise_e)
STAGE_ASM_PD(1440, 1440, stage_dispatch_noise_e)
STAGE_ASM_PD(1441, 1441, stage_dispatch_fake_p2)
STAGE_ASM_PD(1442, 1442, stage_dispatch_fake_p2)
STAGE_ASM_PD(1443, 1443, stage_dispatch_noise_d)
STAGE_ASM_PD(1444, 1444, stage_dispatch_noise_b)
STAGE_ASM_PD(1445, 1445, stage_dispatch_noise_e)
STAGE_ASM_PD(1446, 1446, stage_dispatch_p3)
STAGE_ASM_PD(1447, 1447, stage_dispatch_noise)
STAGE_ASM_PD(1448, 1448, stage_dispatch_noise_d)
STAGE_ASM_PD(1449, 1449, stage_dispatch_fake_p2)
STAGE_ASM_PD(1450, 1450, stage_dispatch_p0)
STAGE_ASM_PD(1451, 1451, stage_dispatch_noise)
STAGE_ASM_PD(1452, 1452, stage_dispatch_noise_d)
STAGE_ASM_PD(1453, 1453, stage_dispatch_noise_a)
STAGE_ASM_PD(1454, 1454, stage_dispatch_noise_e)
STAGE_ASM_PD(1455, 1455, stage_dispatch_fake_p3)
STAGE_ASM_PD(1456, 1456, stage_dispatch_noise)
STAGE_ASM_PD(1457, 1457, stage_dispatch_noise_c)
STAGE_ASM_PD(1458, 1458, stage_dispatch_fake_p2)
STAGE_ASM_PD(1459, 1459, stage_dispatch_fake_p2)
STAGE_ASM_PD(1460, 1460, stage_dispatch_noise_e)
STAGE_ASM_PD(1461, 1461, stage_dispatch_noise_c)
STAGE_ASM_PD(1462, 1462, stage_dispatch_fake_p1)
STAGE_ASM_PD(1463, 1463, stage_dispatch_noise_d)
STAGE_ASM_PD(1464, 1464, stage_dispatch_noise_a)
STAGE_ASM_PD(1465, 1465, stage_dispatch_p2)
STAGE_ASM_PD(1466, 1466, stage_dispatch_fake_p0)
STAGE_ASM_PD(1467, 1467, stage_dispatch_noise)
STAGE_ASM_PD(1468, 1468, stage_dispatch_noise_d)
STAGE_ASM_PD(1469, 1469, stage_dispatch_noise_a)
STAGE_ASM_PD(1470, 1470, stage_dispatch_noise_b)
STAGE_ASM_PD(1471, 1471, stage_dispatch_fake_p1)
STAGE_ASM_PD(1472, 1472, stage_dispatch_fake_p1)
STAGE_ASM_PD(1473, 1473, stage_dispatch_noise_a)
STAGE_ASM_PD(1474, 1474, stage_dispatch_noise_e)
STAGE_ASM_PD(1475, 1475, stage_dispatch_p0)
STAGE_ASM_PD(1476, 1476, stage_dispatch_noise)
STAGE_ASM_PD(1477, 1477, stage_dispatch_noise_c)
STAGE_ASM_PD(1478, 1478, stage_dispatch_noise_a)
STAGE_ASM_PD(1479, 1479, stage_dispatch_fake_p1)
STAGE_ASM_PD(1480, 1480, stage_dispatch_noise_e)
STAGE_ASM_PD(1481, 1481, stage_dispatch_noise_c)
STAGE_ASM_PD(1482, 1482, stage_dispatch_noise)
STAGE_ASM_PD(1483, 1483, stage_dispatch_noise_d)
STAGE_ASM_PD(1484, 1484, stage_dispatch_noise_a)
STAGE_ASM_PD(1485, 1485, stage_dispatch_noise_e)
STAGE_ASM_PD(1486, 1486, stage_dispatch_fake_p3)
STAGE_ASM_PD(1487, 1487, stage_dispatch_p0)
STAGE_ASM_PD(1488, 1488, stage_dispatch_noise_c)
STAGE_ASM_PD(1489, 1489, stage_dispatch_fake_p2)
STAGE_ASM_PD(1490, 1490, stage_dispatch_noise_b)
STAGE_ASM_PD(1491, 1491, stage_dispatch_noise)
STAGE_ASM_PD(1492, 1492, stage_dispatch_fake_p0)
STAGE_ASM_PD(1493, 1493, stage_dispatch_noise_a)
STAGE_ASM_PD(1494, 1494, stage_dispatch_noise_d)
STAGE_ASM_PD(1495, 1495, stage_dispatch_p2)
STAGE_ASM_PD(1496, 1496, stage_dispatch_fake_p3)
STAGE_ASM_PD(1497, 1497, stage_dispatch_noise_c)
STAGE_ASM_PD(1498, 1498, stage_dispatch_noise_a)
STAGE_ASM_PD(1499, 1499, stage_dispatch_noise_d)
STAGE_ASM_PD(1500, 1500, stage_dispatch_noise_e)
STAGE_ASM_PD(1501, 1501, stage_dispatch_noise_b)
STAGE_ASM_PD(1502, 1502, stage_dispatch_p1)
STAGE_ASM_PD(1503, 1503, stage_dispatch_fake_p1)
STAGE_ASM_PD(1504, 1504, stage_dispatch_noise_a)
STAGE_ASM_PD(1505, 1505, stage_dispatch_noise_e)
STAGE_ASM_PD(1506, 1506, stage_dispatch_noise_b)
STAGE_ASM_PD(1507, 1507, stage_dispatch_noise)
STAGE_ASM_PD(1508, 1508, stage_dispatch_noise_c)
STAGE_ASM_PD(1509, 1509, stage_dispatch_noise_a)
STAGE_ASM_PD(1510, 1510, stage_dispatch_p1)
STAGE_ASM_PD(1511, 1511, stage_dispatch_noise)
STAGE_ASM_PD(1512, 1512, stage_dispatch_noise_c)
STAGE_ASM_PD(1513, 1513, stage_dispatch_noise_a)
STAGE_ASM_PD(1514, 1514, stage_dispatch_noise_d)
STAGE_ASM_PD(1515, 1515, stage_dispatch_noise_b)
STAGE_ASM_PD(1516, 1516, stage_dispatch_fake_p2)
STAGE_ASM_PD(1517, 1517, stage_dispatch_noise_c)
STAGE_ASM_PD(1518, 1518, stage_dispatch_noise)
STAGE_ASM_PD(1519, 1519, stage_dispatch_fake_p1)
STAGE_ASM_PD(1520, 1520, stage_dispatch_noise_e)
STAGE_ASM_PD(1521, 1521, stage_dispatch_noise_b)
STAGE_ASM_PD(1522, 1522, stage_dispatch_noise)
STAGE_ASM_PD(1523, 1523, stage_dispatch_fake_p0)
STAGE_ASM_PD(1524, 1524, stage_dispatch_noise_a)
STAGE_ASM_PD(1525, 1525, stage_dispatch_noise_d)
STAGE_ASM_PD(1526, 1526, stage_dispatch_p2)
STAGE_ASM_PD(1527, 1527, stage_dispatch_fake_p3)
STAGE_ASM_PD(1528, 1528, stage_dispatch_noise_c)
STAGE_ASM_PD(1529, 1529, stage_dispatch_noise_a)
STAGE_ASM_PD(1530, 1530, stage_dispatch_noise_b)
STAGE_ASM_PD(1531, 1531, stage_dispatch_noise_e)
STAGE_ASM_PD(1532, 1532, stage_dispatch_fake_p0)
STAGE_ASM_PD(1533, 1533, stage_dispatch_fake_p0)
STAGE_ASM_PD(1534, 1534, stage_dispatch_noise_d)
STAGE_ASM_PD(1535, 1535, stage_dispatch_noise_b)
STAGE_ASM_PD(1536, 1536, stage_dispatch_p1)
STAGE_ASM_PD(1537, 1537, stage_dispatch_noise_c)
STAGE_ASM_PD(1538, 1538, stage_dispatch_noise)
STAGE_ASM_PD(1539, 1539, stage_dispatch_noise_d)
STAGE_ASM_PD(1540, 1540, stage_dispatch_fake_p2)
STAGE_ASM_PD(1541, 1541, stage_dispatch_noise_b)
STAGE_ASM_PD(1542, 1542, stage_dispatch_noise)
STAGE_ASM_PD(1543, 1543, stage_dispatch_noise_c)
STAGE_ASM_PD(1544, 1544, stage_dispatch_noise_a)
STAGE_ASM_PD(1545, 1545, stage_dispatch_noise_d)
STAGE_ASM_PD(1546, 1546, stage_dispatch_noise_b)
STAGE_ASM_PD(1547, 1547, stage_dispatch_p0)
STAGE_ASM_PD(1548, 1548, stage_dispatch_noise_c)
STAGE_ASM_PD(1549, 1549, stage_dispatch_noise)
STAGE_ASM_PD(1550, 1550, stage_dispatch_noise_b)
STAGE_ASM_PD(1551, 1551, stage_dispatch_noise_e)
STAGE_ASM_PD(1552, 1552, stage_dispatch_noise_c)
STAGE_ASM_PD(1553, 1553, stage_dispatch_fake_p3)
STAGE_ASM_PD(1554, 1554, stage_dispatch_noise_d)
STAGE_ASM_PD(1555, 1555, stage_dispatch_noise_a)
STAGE_ASM_PD(1556, 1556, stage_dispatch_fake_p2)
STAGE_ASM_PD(1557, 1557, stage_dispatch_p3)
STAGE_ASM_PD(1558, 1558, stage_dispatch_noise)
STAGE_ASM_PD(1559, 1559, stage_dispatch_noise_d)
STAGE_ASM_PD(1560, 1560, stage_dispatch_fake_p1)
STAGE_ASM_PD(1561, 1561, stage_dispatch_noise_b)
STAGE_ASM_PD(1562, 1562, stage_dispatch_noise_e)
STAGE_ASM_PD(1563, 1563, stage_dispatch_p0)
STAGE_ASM_PD(1564, 1564, stage_dispatch_fake_p0)
STAGE_ASM_PD(1565, 1565, stage_dispatch_noise_d)
STAGE_ASM_PD(1566, 1566, stage_dispatch_noise_b)
STAGE_ASM_PD(1567, 1567, stage_dispatch_noise_e)
STAGE_ASM_PD(1568, 1568, stage_dispatch_noise_c)
STAGE_ASM_PD(1569, 1569, stage_dispatch_noise)
STAGE_ASM_PD(1570, 1570, stage_dispatch_fake_p1)
STAGE_ASM_PD(1571, 1571, stage_dispatch_p2)
STAGE_ASM_PD(1572, 1572, stage_dispatch_noise_c)
STAGE_ASM_PD(1573, 1573, stage_dispatch_noise)
STAGE_ASM_PD(1574, 1574, stage_dispatch_noise_d)
STAGE_ASM_PD(1575, 1575, stage_dispatch_noise_a)
STAGE_ASM_PD(1576, 1576, stage_dispatch_noise_e)
STAGE_ASM_PD(1577, 1577, stage_dispatch_fake_p1)
STAGE_ASM_PD(1578, 1578, stage_dispatch_noise)
STAGE_ASM_PD(1579, 1579, stage_dispatch_noise_c)
STAGE_ASM_PD(1580, 1580, stage_dispatch_noise_d)
STAGE_ASM_PD(1581, 1581, stage_dispatch_noise_b)
STAGE_ASM_PD(1582, 1582, stage_dispatch_noise_e)
STAGE_ASM_PD(1583, 1583, stage_dispatch_noise_c)
STAGE_ASM_PD(1584, 1584, stage_dispatch_p3)
STAGE_ASM_PD(1585, 1585, stage_dispatch_noise_d)
STAGE_ASM_PD(1586, 1586, stage_dispatch_noise_a)
STAGE_ASM_PD(1587, 1587, stage_dispatch_fake_p2)
STAGE_ASM_PD(1588, 1588, stage_dispatch_fake_p2)
STAGE_ASM_PD(1589, 1589, stage_dispatch_noise)
STAGE_ASM_PD(1590, 1590, stage_dispatch_fake_p0)
STAGE_ASM_PD(1591, 1591, stage_dispatch_noise_e)
STAGE_ASM_PD(1592, 1592, stage_dispatch_noise_b)
STAGE_ASM_PD(1593, 1593, stage_dispatch_fake_p3)
STAGE_ASM_PD(1594, 1594, stage_dispatch_fake_p3)
STAGE_ASM_PD(1595, 1595, stage_dispatch_noise_a)
STAGE_ASM_PD(1596, 1596, stage_dispatch_p0)
STAGE_ASM_PD(1597, 1597, stage_dispatch_noise_b)
STAGE_ASM_PD(1598, 1598, stage_dispatch_noise)
STAGE_ASM_PD(1599, 1599, stage_dispatch_noise_c)
STAGE_ASM_PD(1600, 1600, stage_dispatch_fake_p1)
STAGE_ASM_PD(1601, 1601, stage_dispatch_fake_p1)
STAGE_ASM_PD(1602, 1602, stage_dispatch_noise_e)
STAGE_ASM_PD(1603, 1603, stage_dispatch_noise_c)
STAGE_ASM_PD(1604, 1604, stage_dispatch_noise)
STAGE_ASM_PD(1605, 1605, stage_dispatch_noise_d)
STAGE_ASM_PD(1606, 1606, stage_dispatch_noise_a)
STAGE_ASM_PD(1607, 1607, stage_dispatch_noise_e)
STAGE_ASM_PD(1608, 1608, stage_dispatch_p1)
STAGE_ASM_PD(1609, 1609, stage_dispatch_noise)
STAGE_ASM_PD(1610, 1610, stage_dispatch_noise_a)
STAGE_ASM_PD(1611, 1611, stage_dispatch_noise_e)
STAGE_ASM_PD(1612, 1612, stage_dispatch_noise_b)
STAGE_ASM_PD(1613, 1613, stage_dispatch_noise)
STAGE_ASM_PD(1614, 1614, stage_dispatch_fake_p2)
STAGE_ASM_PD(1615, 1615, stage_dispatch_noise_a)
STAGE_ASM_PD(1616, 1616, stage_dispatch_noise_d)
STAGE_ASM_PD(1617, 1617, stage_dispatch_fake_p1)
STAGE_ASM_PD(1618, 1618, stage_dispatch_p1)
STAGE_ASM_PD(1619, 1619, stage_dispatch_noise_c)
STAGE_ASM_PD(1620, 1620, stage_dispatch_noise_d)
STAGE_ASM_PD(1621, 1621, stage_dispatch_fake_p0)
STAGE_ASM_PD(1622, 1622, stage_dispatch_noise_e)
STAGE_ASM_PD(1623, 1623, stage_dispatch_noise_b)
STAGE_ASM_PD(1624, 1624, stage_dispatch_fake_p3)
STAGE_ASM_PD(1625, 1625, stage_dispatch_fake_p3)
STAGE_ASM_PD(1626, 1626, stage_dispatch_noise_a)
STAGE_ASM_PD(1627, 1627, stage_dispatch_noise_e)
STAGE_ASM_PD(1628, 1628, stage_dispatch_noise_b)
STAGE_ASM_PD(1629, 1629, stage_dispatch_p0)
STAGE_ASM_PD(1630, 1630, stage_dispatch_fake_p0)
STAGE_ASM_PD(1631, 1631, stage_dispatch_fake_p0)
STAGE_ASM_PD(1632, 1632, stage_dispatch_noise_b)
STAGE_ASM_PD(1633, 1633, stage_dispatch_noise)
STAGE_ASM_PD(1634, 1634, stage_dispatch_noise_c)
STAGE_ASM_PD(1635, 1635, stage_dispatch_p2)
STAGE_ASM_PD(1636, 1636, stage_dispatch_noise_d)
STAGE_ASM_PD(1637, 1637, stage_dispatch_noise_b)
STAGE_ASM_PD(1638, 1638, stage_dispatch_fake_p0)
STAGE_ASM_PD(1639, 1639, stage_dispatch_noise_c)
STAGE_ASM_PD(1640, 1640, stage_dispatch_noise_d)
STAGE_ASM_PD(1641, 1641, stage_dispatch_noise_a)
STAGE_ASM_PD(1642, 1642, stage_dispatch_noise_e)
STAGE_ASM_PD(1643, 1643, stage_dispatch_noise_b)
STAGE_ASM_PD(1644, 1644, stage_dispatch_noise)
STAGE_ASM_PD(1645, 1645, stage_dispatch_p1)
STAGE_ASM_PD(1646, 1646, stage_dispatch_noise_a)
STAGE_ASM_PD(1647, 1647, stage_dispatch_noise_d)
STAGE_ASM_PD(1648, 1648, stage_dispatch_fake_p1)
STAGE_ASM_PD(1649, 1649, stage_dispatch_fake_p1)
STAGE_ASM_PD(1650, 1650, stage_dispatch_noise_a)
STAGE_ASM_PD(1651, 1651, stage_dispatch_fake_p3)
STAGE_ASM_PD(1652, 1652, stage_dispatch_noise_b)
STAGE_ASM_PD(1653, 1653, stage_dispatch_noise_e)
STAGE_ASM_PD(1654, 1654, stage_dispatch_fake_p2)
STAGE_ASM_PD(1655, 1655, stage_dispatch_fake_p2)
STAGE_ASM_PD(1656, 1656, stage_dispatch_noise_d)
STAGE_ASM_PD(1657, 1657, stage_dispatch_p3)
STAGE_ASM_PD(1658, 1658, stage_dispatch_noise_e)
STAGE_ASM_PD(1659, 1659, stage_dispatch_noise_c)
STAGE_ASM_PD(1660, 1660, stage_dispatch_noise_c)
STAGE_ASM_PD(1661, 1661, stage_dispatch_fake_p0)
STAGE_ASM_PD(1662, 1662, stage_dispatch_p3)
STAGE_ASM_PD(1663, 1663, stage_dispatch_noise_b)
STAGE_ASM_PD(1664, 1664, stage_dispatch_noise)
STAGE_ASM_PD(1665, 1665, stage_dispatch_noise_c)
STAGE_ASM_PD(1666, 1666, stage_dispatch_noise_a)
STAGE_ASM_PD(1667, 1667, stage_dispatch_noise_d)
STAGE_ASM_PD(1668, 1668, stage_dispatch_noise_b)
STAGE_ASM_PD(1669, 1669, stage_dispatch_fake_p0)
STAGE_ASM_PD(1670, 1670, stage_dispatch_noise_a)
STAGE_ASM_PD(1671, 1671, stage_dispatch_noise_d)
STAGE_ASM_PD(1672, 1672, stage_dispatch_noise_b)
STAGE_ASM_PD(1673, 1673, stage_dispatch_noise_e)
STAGE_ASM_PD(1674, 1674, stage_dispatch_p3)
STAGE_ASM_PD(1675, 1675, stage_dispatch_fake_p1)
STAGE_ASM_PD(1676, 1676, stage_dispatch_noise_d)
STAGE_ASM_PD(1677, 1677, stage_dispatch_noise_a)
STAGE_ASM_PD(1678, 1678, stage_dispatch_fake_p0)
STAGE_ASM_PD(1679, 1679, stage_dispatch_fake_p0)
STAGE_ASM_PD(1680, 1680, stage_dispatch_p3)
STAGE_ASM_PD(1681, 1681, stage_dispatch_noise_a)
STAGE_ASM_PD(1682, 1682, stage_dispatch_fake_p3)
STAGE_ASM_PD(1683, 1683, stage_dispatch_noise_b)
STAGE_ASM_PD(1684, 1684, stage_dispatch_noise_e)
STAGE_ASM_PD(1685, 1685, stage_dispatch_fake_p2)
STAGE_ASM_PD(1686, 1686, stage_dispatch_fake_p2)
STAGE_ASM_PD(1687, 1687, stage_dispatch_noise_d)
STAGE_ASM_PD(1688, 1688, stage_dispatch_noise_b)
STAGE_ASM_PD(1689, 1689, stage_dispatch_noise_e)
STAGE_ASM_PD(1690, 1690, stage_dispatch_noise)
STAGE_ASM_PD(1691, 1691, stage_dispatch_fake_p3)
STAGE_ASM_PD(1692, 1692, stage_dispatch_fake_p3)
STAGE_ASM_PD(1693, 1693, stage_dispatch_noise_e)
STAGE_ASM_PD(1694, 1694, stage_dispatch_noise_c)
STAGE_ASM_PD(1695, 1695, stage_dispatch_noise)
STAGE_ASM_PD(1696, 1696, stage_dispatch_p1)
STAGE_ASM_PD(1697, 1697, stage_dispatch_noise_a)
STAGE_ASM_PD(1698, 1698, stage_dispatch_noise_e)
STAGE_ASM_PD(1699, 1699, stage_dispatch_fake_p3)
STAGE_ASM_PD(1700, 1700, stage_dispatch_noise_c)
STAGE_ASM_PD(1701, 1701, stage_dispatch_noise_a)
STAGE_ASM_PD(1702, 1702, stage_dispatch_noise_d)
STAGE_ASM_PD(1703, 1703, stage_dispatch_noise_b)
STAGE_ASM_PD(1704, 1704, stage_dispatch_noise_e)
STAGE_ASM_PD(1705, 1705, stage_dispatch_noise_c)
STAGE_ASM_PD(1706, 1706, stage_dispatch_fake_p1)
STAGE_ASM_PD(1707, 1707, stage_dispatch_noise_d)
STAGE_ASM_PD(1708, 1708, stage_dispatch_noise_a)
STAGE_ASM_PD(1709, 1709, stage_dispatch_p2)
STAGE_ASM_PD(1710, 1710, stage_dispatch_noise)
STAGE_ASM_PD(1711, 1711, stage_dispatch_noise_d)
STAGE_ASM_PD(1712, 1712, stage_dispatch_fake_p2)
STAGE_ASM_PD(1713, 1713, stage_dispatch_noise_e)
STAGE_ASM_PD(1714, 1714, stage_dispatch_noise_b)
STAGE_ASM_PD(1715, 1715, stage_dispatch_p3)
STAGE_ASM_PD(1716, 1716, stage_dispatch_fake_p1)
STAGE_ASM_PD(1717, 1717, stage_dispatch_noise_a)
STAGE_ASM_PD(1718, 1718, stage_dispatch_noise_e)
STAGE_ASM_PD(1719, 1719, stage_dispatch_noise_b)

void print_decoded(unsigned char *enc, unsigned long len) {
    char out[64];
    unsigned long key = U64(0x936B12D4E5F60718);
    for (unsigned long i = 0; i < len; i++) {
        unsigned char k = (unsigned char)(key >> ((i & 7) * 8));
        k ^= (unsigned char)(i * 29 + 0x31);
        out[i] = (char)(enc[i] ^ k);
    }
    sys_write(1, out, len);
    burn_stack_bytes((volatile unsigned char *)out, sizeof(out));
}

static inline __attribute__((always_inline)) unsigned long final_output_seed(unsigned long poison) {
    unsigned long k = U64(0x6D1F2A79C4B5E307);
    k ^= g.real_state;
    k ^= rol64(g.input_digest, 17);
    k ^= rol64(g.split_counter + U64(0xA5A5A5A55A5A5A5A), 31);
    k ^= poison * U64(0x9E3779B97F4A7C15);
    k ^= helper_output_key_guard_word() * U64(0xD1B54A32D192ED03);
    k ^= helper_sealed_target_guard_word() * U64(0x94D049BB133111EB);
    k ^= code_island_guard_word() * U64(0xA24BAED4963EE407);
    k ^= rol64(g.xchar_mix, 7);
    k ^= rol64(g.xchar_mirror, 19);
    k ^= rol64(g.xchar_last, 29);
    k ^= rol64(generated_layout_guard_word(), 13);
    k ^= rol64(generated_stage_order_guard_word(), 23);
    k ^= fake_check_guard_word() * U64(0xFA1E39C0DEC0FFEE);
    k ^= route_roll_guard_word() * U64(0xA11CE5A17E202640);
    k ^= rol64(g.route_roll_mix, 5) ^ rol64(g.route_roll_mirror, 17) ^ rol64(g.route_roll_last, 29);
    k = xorshift64(k + U64(0xD6E8FEB86659FD93));
    return k;
}

void print_final_state_output(unsigned long poison) {
    char out[40];
    unsigned long k = final_output_seed(poison);
    for (unsigned long i = 0; i < sizeof(out); i++) {
        k = xorshift64(k + U64(0x9E3779B97F4A7C15) + i * 0x51UL);
        unsigned char ks = (unsigned char)(k >> ((i & 7) * 8));
        ks ^= (unsigned char)(i * 0x29 + 0x71);
        out[i] = (char)(enc_final_state_output_v5[i] ^ ks);
    }
    sys_write(1, out, sizeof(out));
    burn_stack_bytes((volatile unsigned char *)out, sizeof(out));
}

static inline __attribute__((always_inline)) void FINAL_POISON_IF(unsigned long *poison, int cond, unsigned long tag) {
    if (cond) {
        unsigned long x = xorshift64(tag ^ g.real_state ^ g.input_digest ^ *poison);
        *poison ^= x | 1UL;
    }
}

void final_stage() {
    unsigned long final_poison = 0;

    deep_noise_generator(U64(0xCAFED00D));

    SILENT_SAMPLE64(g.rx_helper_active_mix);
    SILENT_SAMPLE64(g.rx_helper_active_guard);
    SILENT_SAMPLE64(g.memfd_stage2_active_mix);
    SILENT_SAMPLE64(g.memfd_stage2_active_guard);
    SILENT_SAMPLE64(g.memfd_stage2_active_seen);
    SILENT_SAMPLE64(g.memfd_stage2_commit_mix);
    SILENT_SAMPLE64(g.memfd_stage2_commit_mirror);
    SILENT_SAMPLE64(g.memfd_stage2_target_root);
    SILENT_SAMPLE64(g.memfd_stage2_target_shadow);
    SILENT_SAMPLE64(g.memfd_stage2_target_uses);
    SILENT_SAMPLE64(g.rx_helper_target_root);
    SILENT_SAMPLE64(g.rx_helper_target_shadow);
    SILENT_SAMPLE64(g.helper_output_key_mix);
    SILENT_SAMPLE64(g.memfd_stage2_output_key_mix);
    SILENT_SAMPLE64(helper_output_key_guard_word());
    SILENT_SAMPLE64(helper_sealed_target_guard_word());
    SILENT_SAMPLE64(g.pvm_mailbox);
    SILENT_SAMPLE64(g.pvm_mirror);
    SILENT_SAMPLE64(g.pvm_epoch);
    SILENT_SAMPLE64(g.pvm_mix);
    SILENT_SAMPLE64(g.pvm_writes);
    SILENT_SAMPLE64(g.pvm_stage_mix);
    SILENT_SAMPLE64(g.handler_table_ready);
    SILENT_SAMPLE64(g.handler_table_faults);
    SILENT_SAMPLE64(g.handler_table_reads);
    SILENT_SAMPLE64(g.handler_table_stage_mix);
    SILENT_SAMPLE64(g.handler_table_stage_mirror);
    SILENT_SAMPLE64(g.code_island_calls);
    SILENT_SAMPLE64(g.code_island_active_mix);
    SILENT_SAMPLE64(g.code_island_active_guard);
    SILENT_SAMPLE64(g.code_island_active_seen);
    SILENT_SAMPLE64(g.code_island_wipes);
    SILENT_SAMPLE64(code_island_guard_word());
    SILENT_SAMPLE64(g.phase_dispatch_count);
    SILENT_SAMPLE64(g.phase_dispatch_shadow);
    SILENT_SAMPLE64(g.phase_lane_mix[0]);
    SILENT_SAMPLE64(g.phase_lane_mix[1]);
    SILENT_SAMPLE64(g.phase_lane_mix[2]);
    SILENT_SAMPLE64(g.phase_lane_mix[3]);
    SILENT_SAMPLE64(g.virtual_dispatch_count);
    SILENT_SAMPLE64(g.virtual_dispatch_shadow);
    SILENT_SAMPLE64(g.virtual_lane_last);
    SILENT_SAMPLE64(g.virtual_lane_bad);
    SILENT_SAMPLE64(virtual_lane_guard_word());
    SILENT_SAMPLE64(g.forty_round_shadow);
    SILENT_SAMPLE64(g.forty_round_mirror);
    SILENT_SAMPLE64(g.forty_round_counter);
    SILENT_SAMPLE64(g.forty_round_gate);
    SILENT_SAMPLE64(forty_round_guard_word());
    SILENT_SAMPLE64(g.target_vm_shadow);
    SILENT_SAMPLE64(g.target_vm_mirror);
    SILENT_SAMPLE64(g.target_vm_counter);
    SILENT_SAMPLE64(g.target_vm_gate);
    SILENT_SAMPLE64(target_vm_guard_word());
    SILENT_SAMPLE64(g.target_decode_dispatch_shadow);
    SILENT_SAMPLE64(g.target_decode_dispatch_mirror);
    SILENT_SAMPLE64(g.target_decode_dispatch_counter);
    SILENT_SAMPLE64(g.target_decode_dispatch_gate);
    SILENT_SAMPLE64(g.target_decode_decoy_scratch[0]);
    SILENT_SAMPLE64(g.target_decode_decoy_scratch[5]);
    SILENT_SAMPLE64(target_decode_dispatch_guard_word());
    SILENT_SAMPLE64(g.mix_vm_shadow);
    SILENT_SAMPLE64(g.mix_vm_mirror);
    SILENT_SAMPLE64(g.mix_vm_counter);
    SILENT_SAMPLE64(g.mix_vm_gate);
    SILENT_SAMPLE64(mix_vm_guard_word());
    SILENT_SAMPLE64(g.diff_dispatch_shadow);
    SILENT_SAMPLE64(g.diff_dispatch_mirror);
    SILENT_SAMPLE64(g.diff_dispatch_counter);
    SILENT_SAMPLE64(g.diff_dispatch_gate);
    SILENT_SAMPLE64(g.diff_decoy_scratch[0]);
    SILENT_SAMPLE64(g.diff_decoy_scratch[5]);
    SILENT_SAMPLE64(diff_dispatch_guard_word());
    SILENT_SAMPLE64(g.apply_dispatch_shadow);
    SILENT_SAMPLE64(g.apply_dispatch_mirror);
    SILENT_SAMPLE64(g.apply_dispatch_counter);
    SILENT_SAMPLE64(g.apply_dispatch_gate);
    SILENT_SAMPLE64(g.apply_decoy_scratch[0]);
    SILENT_SAMPLE64(g.apply_decoy_scratch[5]);
    SILENT_SAMPLE64(apply_dispatch_guard_word());
    SILENT_SAMPLE64(g.xchar_mix);
    SILENT_SAMPLE64(g.xchar_mirror);
    SILENT_SAMPLE64(g.xchar_count);
    SILENT_SAMPLE64(g.xchar_last);
    SILENT_SAMPLE64(g.fake_lane_mix);
    SILENT_SAMPLE64(g.fake_lane_mirror);
    SILENT_SAMPLE64(g.fake_lane_count);
    SILENT_SAMPLE64(g.fake_lane_last);
    SILENT_SAMPLE64(g.route_roll_mix);
    SILENT_SAMPLE64(g.route_roll_mirror);
    SILENT_SAMPLE64(g.route_roll_count);
    SILENT_SAMPLE64(g.route_roll_last);
    SILENT_SAMPLE64(route_roll_guard_word());
    SILENT_SAMPLE64(g.event_algo_key);
    SILENT_SAMPLE64(g.event_algo_mirror);
    SILENT_SAMPLE64(g.event_algo_rounds);
    SILENT_SAMPLE64(event_algo_guard_word());
    SILENT_SAMPLE64(fake_check_guard_word());
    SILENT_SAMPLE64(xchar_guard_word());
    SILENT_SAMPLE64(phase_lane_guard_word());
    SILENT_SAMPLE64(handler_table_guard_word());
    SILENT_SAMPLE64(process_vm_guard_word());
    SILENT_SAMPLE64(rx_helper_guard_word());
    SILENT_SAMPLE64(memfd_stage2_guard_word());
    SILENT_SAMPLE64(heartbeat_guard_word());
    SILENT_SAMPLE64(target_delta_guard_word());
    SILENT_SAMPLE64(uffd_guard_word());
    SILENT_SAMPLE64(g.real_state);
    SILENT_SAMPLE64(g.fail_acc);
    SILENT_SAMPLE64(g.anti_debug_alarm);
    SILENT_SAMPLE64(g.input_digest);
    SILENT_SAMPLE64(expected_input_digest());
    SILENT_SAMPLE64(g.split_counter);

    FINAL_POISON_IF(&final_poison, input_vault.input_len != FLAG_LEN, U64(0xE001000000000001));
    FINAL_POISON_IF(&final_poison, g.fail_acc != 0, U64(0xE001000000000002));
    FINAL_POISON_IF(&final_poison, g.anti_debug_alarm != 0, U64(0xE001000000000003));
    FINAL_POISON_IF(&final_poison, g.input_digest != expected_input_digest(), U64(0xE001000000000004));
    FINAL_POISON_IF(&final_poison, g.split_counter != (unsigned long)(FLAG_LEN * (PHASE_COUNT - 1)), U64(0xE001000000000005));
    FINAL_POISON_IF(&final_poison, uffd_guard_word() != 0, U64(0xE001000000000006));
    FINAL_POISON_IF(&final_poison, target_delta_guard_word() != 0, U64(0xE001000000000007));
    FINAL_POISON_IF(&final_poison, heartbeat_guard_word() != 0, U64(0xE001000000000008));
    FINAL_POISON_IF(&final_poison, rx_helper_guard_word() != 0, U64(0xE001000000000009));
    FINAL_POISON_IF(&final_poison, memfd_stage2_guard_word() != 0, U64(0xE00100000000000A));
    FINAL_POISON_IF(&final_poison, memfd_stage2_target_guard_word() != 0, U64(0xE00100000000000B));
    FINAL_POISON_IF(&final_poison, helper_output_key_guard_word() != 0, U64(0xE001000000000013));
    FINAL_POISON_IF(&final_poison, helper_sealed_target_guard_word() != 0, U64(0xE001000000000014));
    FINAL_POISON_IF(&final_poison, process_vm_guard_word() != 0, U64(0xE00100000000000C));
    FINAL_POISON_IF(&final_poison, handler_table_guard_word() != 0, U64(0xE00100000000000D));
    FINAL_POISON_IF(&final_poison, code_island_guard_word() != 0, U64(0xE001000000000015));
    FINAL_POISON_IF(&final_poison, phase_lane_guard_word() != 0, U64(0xE001000000000012));
    FINAL_POISON_IF(&final_poison, virtual_lane_guard_word() != 0, U64(0xE001000000000019));
    FINAL_POISON_IF(&final_poison, forty_round_guard_word() != 0, U64(0xE00100000000001A));
    FINAL_POISON_IF(&final_poison, target_vm_guard_word() != 0, U64(0xE00100000000001B));
    FINAL_POISON_IF(&final_poison, target_decode_dispatch_guard_word() != 0, U64(0xE00100000000001F));
    FINAL_POISON_IF(&final_poison, mix_vm_guard_word() != 0, U64(0xE00100000000001C));
    FINAL_POISON_IF(&final_poison, diff_dispatch_guard_word() != 0, U64(0xE00100000000001D));
    FINAL_POISON_IF(&final_poison, apply_dispatch_guard_word() != 0, U64(0xE00100000000001E));
    FINAL_POISON_IF(&final_poison, event_algo_guard_word() != 0, U64(0xE001000000000020));
    FINAL_POISON_IF(&final_poison, xchar_guard_word() != 0, U64(0xE001000000000016));
    FINAL_POISON_IF(&final_poison, fake_check_guard_word() != 0, U64(0xE001000000000017));
    FINAL_POISON_IF(&final_poison, route_roll_guard_word() != 0, U64(0xE001000000000018));
    FINAL_POISON_IF(&final_poison, g.handler_table_reads < FLAG_LEN, U64(0xE00100000000000E));
    FINAL_POISON_IF(&final_poison, g.heartbeat_bad != 0, U64(0xE00100000000000F));
    FINAL_POISON_IF(&final_poison, (!g.heartbeat_baseline || !heartbeat_is_valid_snapshot(g.heartbeat_epoch, g.heartbeat_mirror)), U64(0xE001000000000010));
    FINAL_POISON_IF(&final_poison, g.real_state != U64(0x778C4A416D5EEADF), U64(0xE001000000000011));

    bogus_syscall_storm();
    print_final_state_output(final_poison);
    sys_exit(0);
}

void _start() {
    g.step_counter = 1;
    g.dummy_hash = U64(0x1234567813572468);
    g.fake_lane_mix = FAKE_LANE_INIT;
    g.fake_lane_mirror = fake_lane_mirror_of(g.fake_lane_mix, 0, 0);
    g.real_state = U64(0x8BD642F9D5A34C17);
    g.fail_acc = 0;
    g.final_guard = U64(0xBADC0FFEE0DDF00D);
    g.anti_debug_alarm = 0;
    g.code_hash_base = 0;
    g.input_digest = 0;
    g.xchar_mix = U64(0x584348415243484B);
    g.xchar_mirror = 0;
    g.xchar_count = 0;
    g.xchar_last = 0;
    g.route_roll_mix = U64(0x524F5554455F494E);
    g.route_roll_mirror = route_roll_expected_mirror();
    g.route_roll_count = 0;
    g.route_roll_last = 0;
    g.route_roll_bad = 0;
    g.event_mask = 0;
    g.event_counter = 0;
    g.event_shadow = 0;
    g.key_epoch = 0;
    g.timer_epoch = 0;
    g.anti_epoch = 0;
    g.event_algo_key = 0;
    g.event_algo_mirror = 0;
    g.event_algo_rounds = 0;
    g.event_algo_ready = 0;
    g.futex_word = 1;
    g.gate_epoch = 0;
    g.gate_waits = 0;
    g.gate_shadow = U64(0x7711223344556677);
    g.sigill_count = 0;
    g.sigill_shadow = U64(0x5116110DEC0DEF00);
    g.sigill_last_rip = 0;
    g.sigill_stage_hint = 0;
    g.sigill_armed = 0;
    g.segv_count = 0;
    g.segv_shadow = U64(0x5E6D5E6DABADC0DE);
    g.segv_last_rip = 0;
    g.segv_last_rsp = 0;
    g.segv_fault_addr = 0;
    g.segv_stage_hint = 0;
    g.segv_armed = 0;
    g.segv_saved_rsp = 0;
    g.segv_recover_rip = 0;
    g.uffd_enabled = 0;
    g.uffd_faults = 0;
    g.uffd_last_addr = 0;
    g.uffd_shadow = U64(0x0FFDF00D1234ABCD);
    g.uffd_fallback = 0;
    g.td_uffd_enabled = 0;
    g.td_uffd_faults = 0;
    g.td_uffd_last_addr = 0;
    g.td_uffd_shadow = U64(0x7D9A7E5A1A2B3C4D);
    g.td_uffd_fallback = 0;
    g.td_page_mix = 0;
    g.heartbeat_epoch = 0;
    g.heartbeat_mirror = 0;
    g.heartbeat_cookie = 0;
    g.heartbeat_shadow = 0;
    g.heartbeat_baseline = 0;
    g.heartbeat_last_seen = 0;
    g.heartbeat_bad = 0;
    g.heartbeat_code_hash = 0;
    g.heartbeat_checks = 0;
    g.heartbeat_stage_mix = 0;
    g.heartbeat_key_mix = 0;
    g.heartbeat_target_shadow = 0;
    g.rx_helper_ready = 0;
    g.rx_helper_calls = 0;
    g.rx_helper_shadow = U64(0xA13A57A13A57A13A);
    g.rx_helper_code_hash = 0;
    g.rx_helper_bad = 0;
    g.rx_helper_last_stage = 0;
    g.rx_helper_active_mix = U64(0xBEEFBEEFBEEFBEEF);
    g.rx_helper_active_seen = 0;
    g.rx_helper_active_guard = U64(0x13572468ACE0BDF0);
    g.rx_helper_target_root = 0;
    g.rx_helper_target_shadow = 0;
    g.helper_output_key_mix = U64(0x48454C504F55544B);
    g.memfd_stage2_ready = 0;
    g.memfd_stage2_calls = 0;
    g.memfd_stage2_shadow = U64(0x4D454D4644535432);
    g.memfd_stage2_code_hash = 0;
    g.memfd_stage2_bad = 0;
    g.memfd_stage2_last_stage = 0;
    g.memfd_stage2_active_mix = U64(0x5A5A5A5AC3C3C3C3);
    g.memfd_stage2_active_seen = 0;
    g.memfd_stage2_active_guard = U64(0x2468ACE013579BDF);
    g.memfd_stage2_fd_tag = 0;
    g.memfd_stage2_commit_mix = U64(0xC01A17F00DFACE00);
    g.memfd_stage2_commit_mirror = U64(0xDEADC0DE4D454D32);
    g.memfd_stage2_target_root = 0;
    g.memfd_stage2_target_shadow = 0;
    g.memfd_stage2_target_uses = 0;
    g.memfd_stage2_output_key_mix = U64(0x4D46444F55544B32);
    g.pvm_mailbox = 0;
    g.pvm_mirror = 0;
    g.pvm_epoch = 0;
    g.pvm_mix = 0;
    g.pvm_writes = 0;
    g.pvm_child_pid = 0;
    g.pvm_bad = 0;
    g.pvm_fallback = 0;
    g.pvm_code_hash = 0;
    g.pvm_stage_mix = U64(0x50564D5354414745);
    g.handler_table_ready = 0;
    g.handler_table_faults = 0;
    g.handler_table_shadow = U64(0x48444C5253484457);
    g.handler_table_bad = 0;
    g.handler_table_last_addr = 0;
    g.handler_table_reads = 0;
    g.handler_table_stage_mix = U64(0x48444C5253544147);
    g.handler_table_stage_mirror = U64(0x48444C524D495252);
    g.handler_table_page_hash = 0;
    g.code_island_ready = 0;
    g.code_island_calls = 0;
    g.code_island_bad = 0;
    g.code_island_last_stage = 0;
    g.code_island_code_hash = 0;
    g.code_island_active_mix = U64(0xC0DE15A11A5E0001);
    g.code_island_active_seen = 0;
    g.code_island_active_guard = U64(0xC0DE15A11A5E0002);
    g.code_island_wipes = 0;
    g.code_island_shadow = U64(0x434F444549534C45);
    for (int i = 0; i < PHASE_COUNT; i++) {
        g.phase_lane_mix[i] = U64(0x50484C4E00000000) ^ ((unsigned long)(i + 1) * U64(0x0101010101010101));
        g.phase_lane_mirror[i] = 0;
    }
    g.phase_dispatch_count = 0;
    g.phase_dispatch_shadow = U64(0x4453505443485033);
    for (int i = 0; i < PHASE_COUNT; i++) g.phase_lane_mirror[i] = phase_lane_expected_mirror((unsigned char)i);
    for (int i = 0; i < VIRTUAL_LANE_COUNT; i++) {
        g.virtual_lane_mix[i] = U64(0x564C4E0000000000) ^
                                ((unsigned long)(i + 1) * U64(0x0101010101010101)) ^
                                rol64(U64(0x9E3779B97F4A7C15), ((i & 31) + 1));
        g.virtual_lane_mirror[i] = 0;
    }
    g.virtual_dispatch_count = 0;
    g.virtual_dispatch_shadow = U64(0x5649525444535048);
    g.virtual_lane_last = 0;
    g.virtual_lane_bad = 0;
    for (int i = 0; i < VIRTUAL_LANE_COUNT; i++) g.virtual_lane_mirror[i] = virtual_lane_expected_mirror((unsigned char)i);
    g.forty_round_shadow = U64(0x4652545953484457);
    g.forty_round_counter = 0;
    g.forty_round_gate = U64(0x4652545947415445);
    g.forty_round_mirror = forty_round_expected_mirror();
    g.target_vm_shadow = U64(0x5447525653484457);
    g.target_vm_counter = 0;
    g.target_vm_gate = U64(0x5447525647415445);
    g.target_vm_mirror = target_vm_expected_mirror();
    g.target_decode_dispatch_shadow = U64(0x5444445353484457);
    g.target_decode_dispatch_counter = 0;
    g.target_decode_dispatch_gate = U64(0x5444444741544531);
    g.target_decode_dispatch_mirror = target_decode_dispatch_expected_mirror();
    for (int i = 0; i < 8; i++) g.target_decode_decoy_scratch[i] = U64(0x7A6DEC0000000000) ^ (unsigned long)(i * 0x31U);
    g.mix_vm_shadow = U64(0x4D58564D53484457);
    g.mix_vm_counter = 0;
    g.mix_vm_gate = U64(0x4D58564D47415445);
    g.mix_vm_mirror = mix_vm_expected_mirror();
    g.diff_dispatch_shadow = U64(0x4444464453484457);
    g.diff_dispatch_counter = 0;
    g.diff_dispatch_gate = U64(0x4444464447415445);
    g.diff_dispatch_mirror = diff_dispatch_expected_mirror();
    for (int i = 0; i < 8; i++) g.diff_decoy_scratch[i] = U64(0xD1FDEC0000000000) ^ (unsigned long)i;
    g.apply_dispatch_shadow = U64(0x4150445353484457);
    g.apply_dispatch_counter = 0;
    g.apply_dispatch_gate = U64(0x4150444741544531);
    g.apply_dispatch_mirror = apply_dispatch_expected_mirror();
    for (int i = 0; i < 8; i++) g.apply_decoy_scratch[i] = U64(0xA9911ED000000000) ^ (unsigned long)(i * 0x101U);
    for (int i = 0; i < FLAG_LEN; i++) g.split_shadow[i] = 0;
    g.split_counter = 0;
    g.split_last = 0;

    init_route_projection_runtime_latch();
    bogus_syscall_storm();
    seal_targets();
    init_signal_runtime();
    init_event_runtime();
    init_eventfd_algorithm_gate();
    init_futex_gate();
    init_watchdogs();
    init_heartbeat_runtime();
    init_rx_helper_runtime();
    init_memfd_stage2_runtime();
    init_code_island_runtime();
    init_process_vm_child_runtime();
    init_handler_table_runtime();
    init_userfaultfd_runtime();
    expand_sealed_stream();

    write_encrypted_blob(1, enc_prompt_v4, sizeof(enc_prompt_v4), U64(0xA0B1C2D3E4F50617));
    long nread = sys_read(0, (char *)input_vault.raw, 80);
    materialize_input_view(nread);
    g.input_digest = compute_input_digest();

    {
        int fa = fake_check_a();
        int fb = fake_check_b();
        fake_check_lane_update(0xFEU, 0xFFU, fa, fb);
    }

    build_dynamic_ptr_pool();
    deep_noise_generator(U64(0x1122334455667788));

    {
        unsigned int entry_stage = stage_group_entry(0U);
        srop_jump_seeded(decode_target((int)entry_stage), entry_stage);
    }

    sys_exit(1);
}
