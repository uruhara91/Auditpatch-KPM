/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * zn-auditpatch-kpm
 *
 * KernelPatch Module (KPM) port of the "ZN-AuditPatch" Zygisk Next module
 * (https://github.com/aviraxp/ZN-AuditPatch, see also
 * https://android-review.googlesource.com/c/platform/system/logging/+/3725346),
 * plus an optional deeper hook (see PART 2 below) that goes further than the
 * original module ever did.
 *
 * ===========================================================================
 * PART 1: the logd/recvfrom hook (always active, works on any kernel)
 * ===========================================================================
 * The original module was injected (via Zygisk Next) into the `logd` process
 * and PLT-hooked `vasprintf()`. Whenever logd formatted an SELinux AVC audit
 * denial line whose `tcontext=` field named the `su` or `magisk` domain, it
 * rewrote that field to look like an ordinary `priv_app` context before the
 * line reached logcat.
 *
 * A KPM runs in kernel space, not injected into a specific userspace
 * process, so there is no `vasprintf()` inside our address space to hook.
 * Tracing the actual data path (system/logging/logd/libaudit.cpp +
 * LogAudit.cpp in AOSP) shows logd receives every raw kernel AVC denial
 * line -- already containing the literal text `tcontext=u:r:su:s0`, verbatim
 * -- via `recvfrom()` on a netlink socket, *before* its own vasprintf() ever
 * runs. So this module hooks `recvfrom` system-wide and, purely in the
 * "after" callback (i.e. after the real syscall already ran):
 *
 *   - Bails out unless the calling task's comm is "logd" (or a custom name
 *     supplied via KPM load args).
 *   - Bails out unless the received text contains a target `tcontext=`
 *     pattern.
 *   - Rewrites it in a scratch kernel buffer (same quote-escape heuristic as
 *     upstream, see has_quote_after()), copies the result back over the
 *     caller's own buffer via compat_copy_to_user(), and patches the
 *     syscall's return value (byte count) to match.
 *
 * This only ever touches a *userspace* buffer through the safe, documented
 * compat_copy_to_user()/compat_strncpy_from_user() primitives. It never
 * allocates a kernel object that other kernel code later frees, so it has
 * no allocator-ownership concerns and needs no kernel-version-specific
 * tuning. It is always installed, on every kernel KernelPatch itself runs
 * on.
 *
 * ===========================================================================
 * PART 2: the deep security_sid_to_context hook (version-gated, best-effort)
 * ===========================================================================
 * PART 1 only ever rewrites the `tcontext=` field inside logd's audit-log
 * text. It says nothing about `scontext=`, and it says nothing about any
 * *other* consumer of a SID->string context lookup, such as:
 *   - /proc/[pid]/attr/current and friends (what `id -Z`, getcon()-style
 *     APIs, and some root-detection SDKs read directly)
 *   - any other kernel code path that turns su/magisk's SID into a display
 *     string
 *
 * All of those ultimately go through one real kernel function:
 * `security_sid_to_context()` in security/selinux/ss/services.c. Hooking
 * *that* instead of (or alongside) recvfrom() covers all of the above at
 * once, which is what was asked for. It is a fundamentally more invasive
 * hook than PART 1, for two concrete reasons, both handled explicitly below
 * rather than glossed over:
 *
 * 1. ABI shape. security_sid_to_context()'s C signature has changed twice
 *    in kernel history:
 *      < 4.19        : security_sid_to_context(u32 sid, char **scontext, u32 *scontext_len)
 *      4.19 to 6.3    : security_sid_to_context(struct selinux_state *state, u32 sid, char **scontext, u32 *scontext_len)
 *      6.4 and newer  : back to the 3-argument form
 *    Verified directly against real kernel source for this project: mainline
 *    tags v4.4/v4.9 (3-arg), v4.19/v5.4/v5.10/v5.15/v6.1 (4-arg),
 *    v6.2..v6.3 (4-arg), v6.4/v6.6/v6.12 (3-arg again) -- and cross-checked
 *    against the actual Android common-kernel branches android-4.19-stable,
 *    android-5.4-stable, android12-5.10, android13-5.15, android14-6.1 and
 *    android15-6.6, which all matched their mainline-version expectation.
 *
 * 2. Object lifetime. The buffer `*scontext` points to is a real
 *    kmalloc()'d kernel object that the *caller* eventually kfree()s (this
 *    was verified directly in security/selinux/avc.c:avc_audit_post_callback
 *    and fs/proc/base.c:proc_pid_attr_read, both of which kfree() it after
 *    use). Swapping in a differently-sourced buffer (e.g. this KPM's own
 *    kp_malloc() allocator) would hand the kernel's real kfree() a pointer
 *    it never allocated -- silent heap corruption waiting to happen. So the
 *    replacement buffer here is allocated with the kernel's *real*
 *    kmalloc()/kfree() (exposed by KernelPatch as kfuncs), which is safe to
 *    free later by anyone.
 *
 *    kmalloc() needs a GFP flags value, and some callers of
 *    security_sid_to_context() (avc_audit_post_callback, specifically) can
 *    run under rcu_read_lock() in a non-sleepable context, so GFP_ATOMIC is
 *    required -- but GFP_ATOMIC's actual *numeric* value is not a stable
 *    ABI constant (KernelPatch's own public headers leave it unimplemented
 *    for exactly this reason) and has in fact changed across kernel
 *    history: verified directly from source, ___GFP_DIRECT_RECLAIM alone
 *    moved from 0x200000 (v4.19) to 0x400 (v5.15), a different bit
 *    position entirely. Guessing a single value to cover every kernel would
 *    silently be wrong on some of them.
 *
 *    So this module ships a small table of GFP_ATOMIC values and the ABI
 *    shape, each individually verified against real kernel source (see
 *    SID2CTX_ABI_TABLE below). On a kernel version that matches a table
 *    entry, the deep hook installs. On anything else, it does not -- it is
 *    left disabled rather than guessed at, and PART 1 (recvfrom/logd) keeps
 *    working regardless. This is deliberately conservative: extending the
 *    table to a kernel version not listed here requires checking that
 *    version's real security.h and gfp.h/gfp_types.h, the same way this
 *    table was built, not adding a plausible-looking guess.
 *
 * Unlike PART 1, the deep hook cannot distinguish "su/magisk is the target
 * of a denial" from "su/magisk is the source" (or, for that matter, from
 * plain context introspection with no denial involved at all) -- it patches
 * *every* successful resolution of the su/magisk domain SID to a string,
 * system-wide. That is strictly broader than upstream ZN-AuditPatch's scope
 * and is the whole point of this part.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <asm/atomic.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <hook.h>
#include <kputils.h>
#include <kpmalloc.h>
#include <asm/current.h>

KPM_NAME("zn-auditpatch-kpm");
KPM_VERSION("2.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("aviraxp; KP port");
KPM_DESCRIPTION("Hide su/magisk context from AVC audit logs (+ optional deep SELinux hook)");

/* ------------------------------------------------------------------------
 * Shared constants
 * ------------------------------------------------------------------------ */

/* Default target process for PART 1, overridable at `kpm load` time via
 * KPM_ARGS (see auditpatch_init). */
#define DEFAULT_TARGET_COMM "logd"

/* Raw context values we're looking for, and what we replace them with.
 * These are the values as security_sid_to_context() itself returns them
 * (no "tcontext=" prefix -- that's a PART 1/text-log-line-only concept). */
#define CTX_SU "u:r:su:s0"
#define CTX_MAGISK "u:r:magisk:s0"
#define CTX_REPLACEMENT "u:r:priv_app:s0:c512,c768"
#define CTX_REPLACEMENT_LEN (sizeof(CTX_REPLACEMENT) - 1)

/* PART 1 matches inside a formatted log line, so it needs the "tcontext="
 * prefix glued on (plain C string literal concatenation). Only tcontext=,
 * never scontext=, exactly like upstream ZN-AuditPatch. */
static const char PATTERN_SU[] = "tcontext=" CTX_SU;
static const char PATTERN_MAGISK[] = "tcontext=" CTX_MAGISK;
static const char PATTERN_REPLACEMENT[] = "tcontext=" CTX_REPLACEMENT;

#define PATTERN_SU_LEN (sizeof(PATTERN_SU) - 1)
#define PATTERN_MAGISK_LEN (sizeof(PATTERN_MAGISK) - 1)
#define PATTERN_REPLACEMENT_LEN (sizeof(PATTERN_REPLACEMENT) - 1)

/* Hard ceiling for PART 1's scratch copy (defensive upper bound only --
 * see MAX_ALLOC_HEADROOM below for what actually gets allocated per call).
 * MAX_AUDIT_MESSAGE_LENGTH in AOSP libaudit.h is 8970, so this leaves
 * ample headroom while staying a single bounded allocation. */
#define SCRATCH_MAX 16384

/* The largest a match can possibly grow by: PATTERN_REPLACEMENT_LEN minus
 * the shortest pattern we match against (PATTERN_SU). Used to right-size
 * the per-call scratch allocation instead of always grabbing SCRATCH_MAX --
 * real AVC lines are a few hundred bytes, so this keeps the common-case
 * allocation in that same ballpark rather than always 16 KiB. */
#define MAX_GROWTH (PATTERN_REPLACEMENT_LEN - PATTERN_SU_LEN)
#define ALLOC_HEADROOM (MAX_GROWTH + 16)

/* ------------------------------------------------------------------------
 * State
 * ------------------------------------------------------------------------ */

static char g_target_comm[TASK_COMM_LEN] = DEFAULT_TARGET_COMM;

/* Plain counters incremented from a hook can run on any CPU concurrently
 * (recvfrom()/security_sid_to_context() are not serialized against each
 * other across cores), so these are atomic64_t rather than a bare
 * volatile uint64_t -- purely so the stats reported by ctl0 can't lose
 * updates under concurrent access. Nothing security-relevant depends on
 * these; only the reporting does. */
static atomic64_t g_p1_scanned = ATOMIC64_INIT(0);
static atomic64_t g_p1_patched = ATOMIC64_INIT(0);
static atomic64_t g_p1_errors = ATOMIC64_INIT(0);
static int g_p1_hooked = 0;

static atomic64_t g_p2_patched = ATOMIC64_INIT(0);
static atomic64_t g_p2_errors = ATOMIC64_INIT(0);
static int g_p2_hooked = 0;
static int g_p2_has_state_arg = 0;
static uint32_t g_p2_gfp_atomic = 0;
static uint64_t g_p2_addr = 0;

/* ==========================================================================
 * PART 1: logd / recvfrom hook
 * ========================================================================== */

/*
 * Mirrors the original module's has_quote_after(): if a `"` appears
 * anywhere after the matched pattern (within the bytes we actually have),
 * treat the match as unsafe/spoofable (e.g. embedded inside a quoted
 * name="..." field) and refuse to touch it.
 */
static int has_quote_after(const char *buf, int total_len, int from)
{
    int i;
    for (i = from; i < total_len; i++) {
        if (buf[i] == '"') return 1;
    }
    return 0;
}

/*
 * Attempt a single in-place substitution of `pattern` -> PATTERN_REPLACEMENT
 * inside buf[0..*len). `cap` is the hard upper bound (the real userspace
 * buffer capacity) that the result must never exceed. Returns 1 if a
 * replacement was made (and updates *len), 0 otherwise.
 */
static int try_patch_one(char *buf, int *len, int cap, const char *pattern, int pattern_len)
{
    char *pos;
    int match_off, tail_len, new_len;

    if (*len < pattern_len) return 0;

    pos = strnstr(buf, pattern, *len);
    if (!pos) return 0;

    match_off = (int)(pos - buf);

    if (has_quote_after(buf, *len, match_off + pattern_len)) return 0;

    tail_len = *len - (match_off + pattern_len);
    new_len = match_off + (int)PATTERN_REPLACEMENT_LEN + tail_len;

    if (new_len > cap) {
        pr_warn("zn-auditpatch-kpm: [p1] replacement would exceed buffer capacity (cap=%d need=%d), skipped\n", cap,
                new_len);
        return 0;
    }

    if (tail_len > 0) {
        memmove(buf + match_off + PATTERN_REPLACEMENT_LEN, buf + match_off + pattern_len, tail_len);
    }
    memcpy(buf + match_off, PATTERN_REPLACEMENT, PATTERN_REPLACEMENT_LEN);

    *len = new_len;
    return 1;
}

/*
 * after-hook on recvfrom(int sockfd, void *buf, size_t len, int flags,
 *                        struct sockaddr *src_addr, socklen_t *addrlen)
 */
static void after_recvfrom(hook_fargs6_t *args, void *udata)
{
    long ret;
    uint64_t buf_arg, cap_arg;
    void __user *ubuf;
    int user_cap;
    int alloc_size;
    long copied;
    int len;
    int patched;
    char *scratch;
    struct task_struct *task;
    const char *comm;

    ret = (long)args->ret;
    if (ret <= 0) return;

    task = current;
    if (!task) return;
    comm = get_task_comm(task);
    if (!comm) return;
    if (strncmp(comm, g_target_comm, TASK_COMM_LEN)) return;

    buf_arg = syscall_argn(args, 1);
    if (!buf_arg) return;
    ubuf = (void __user *)buf_arg;

    cap_arg = syscall_argn(args, 2);
    if (cap_arg == 0 || cap_arg > (uint64_t)(SCRATCH_MAX - 1)) {
        user_cap = SCRATCH_MAX - 1;
    } else {
        user_cap = (int)cap_arg;
    }
    if (ret > user_cap) ret = user_cap;

    atomic64_inc(&g_p1_scanned);

    /* Right-sized, not SCRATCH_MAX: real AVC lines are a few hundred
     * bytes, so this is typically a tiny fraction of the old fixed 16 KiB
     * allocation. Still bounded by SCRATCH_MAX for safety regardless of
     * what `ret` claims. */
    alloc_size = (int)ret + ALLOC_HEADROOM;
    if (alloc_size > SCRATCH_MAX - 1) alloc_size = SCRATCH_MAX - 1;

    scratch = (char *)kp_malloc(alloc_size);
    if (!scratch) {
        atomic64_inc(&g_p1_errors);
        pr_err("zn-auditpatch-kpm: [p1] kp_malloc(%d) failed\n", alloc_size);
        return;
    }

    copied = compat_strncpy_from_user(scratch, (const char __user *)ubuf, ret);
    if (copied <= 0) {
        kp_free(scratch);
        return;
    }

    len = (int)copied;

    patched = try_patch_one(scratch, &len, user_cap, PATTERN_SU, (int)PATTERN_SU_LEN);
    if (!patched) {
        patched = try_patch_one(scratch, &len, user_cap, PATTERN_MAGISK, (int)PATTERN_MAGISK_LEN);
    }

    if (patched) {
        if (compat_copy_to_user(ubuf, scratch, len) == 0) {
            args->ret = (uint64_t)len;
            atomic64_inc(&g_p1_patched);
            pr_info("zn-auditpatch-kpm: [p1] patched avc audit tcontext in '%s' (total: %lld)\n", comm,
                    (long long)atomic64_read(&g_p1_patched));
        } else {
            atomic64_inc(&g_p1_errors);
            pr_err("zn-auditpatch-kpm: [p1] compat_copy_to_user failed\n");
        }
    }

    kp_free(scratch);
}

/* ==========================================================================
 * PART 2: deep security_sid_to_context hook (version-gated)
 * ========================================================================== */

struct sid2ctx_abi {
    uint32_t kver_min; /* inclusive */
    uint32_t kver_max; /* exclusive */
    int has_state_arg; /* security_sid_to_context(state, sid, ...) vs (sid, ...) */
    uint32_t gfp_atomic; /* verified GFP_ATOMIC bit value for this range */
    const char *note;
};

/*
 * Every row here was checked against real kernel source (both mainline
 * torvalds/linux release tags and the actual Android common-kernel
 * branches) before being added -- see the PART 2 comment above for exactly
 * which ones. Do not add a row "by pattern-matching" the ones around it;
 * verify it the same way first.
 */
static const struct sid2ctx_abi SID2CTX_ABI_TABLE[] = {
    /* android-4.19-stable and mainline v4.19 (covers e.g. 4.19.191) */
    { VERSION(4, 19, 0), VERSION(5, 0, 0), 1, 0x00480020u, "4.19.x" },
    /* android-5.4-stable, android12-5.10, android13-5.15, android14-6.1,
     * and mainline v5.4/v5.10/v5.15/v6.1 */
    { VERSION(5, 0, 0), VERSION(6, 4, 0), 1, 0x00000A20u, "5.4.x-6.3.x" },
    /* android15-6.6 and mainline v6.4/v6.6/v6.12 (state arg dropped again;
     * GFP_ATOMIC's composition also changed -- no __GFP_ATOMIC component) */
    { VERSION(6, 4, 0), VERSION(7, 0, 0), 0, 0x00000820u, "6.4.x+" },
};

#define SID2CTX_ABI_TABLE_LEN (sizeof(SID2CTX_ABI_TABLE) / sizeof(SID2CTX_ABI_TABLE[0]))

/*
 * after-hook on security_sid_to_context(), 4 argument slots captured
 * unconditionally (harmless to over-capture one unused register on the
 * 3-arg ABI -- see g_p2_has_state_arg branch below).
 */
static void after_sid_to_context(hook_fargs4_t *args, void *udata)
{
    char **scontext_ptr;
    uint32_t *scontext_len_ptr;
    char *scontext;
    char *newbuf;

    if ((int)args->ret != 0) return; /* only patch successful conversions */

    if (g_p2_has_state_arg) {
        scontext_ptr = (char **)args->arg2;
        scontext_len_ptr = (uint32_t *)args->arg3;
    } else {
        scontext_ptr = (char **)args->arg1;
        scontext_len_ptr = (uint32_t *)args->arg2;
    }

    if (!scontext_ptr || !scontext_len_ptr) return;
    scontext = *scontext_ptr;
    if (!scontext) return;

    if (strcmp(scontext, CTX_SU) && strcmp(scontext, CTX_MAGISK)) return;

    newbuf = (char *)kmalloc(CTX_REPLACEMENT_LEN + 1, (gfp_t)g_p2_gfp_atomic);
    if (!newbuf) {
        atomic64_inc(&g_p2_errors);
        pr_err("zn-auditpatch-kpm: [p2] kmalloc failed\n");
        return;
    }
    memcpy(newbuf, CTX_REPLACEMENT, CTX_REPLACEMENT_LEN + 1);

    kfree(scontext);
    *scontext_ptr = newbuf;
    *scontext_len_ptr = (uint32_t)CTX_REPLACEMENT_LEN;

    atomic64_inc(&g_p2_patched);
    pr_info("zn-auditpatch-kpm: [p2] patched sid->context result (total: %lld)\n",
            (long long)atomic64_read(&g_p2_patched));
}

/* Returns 1 and fills *out if running_kver matches a verified table entry,
 * else 0. Takes the version as a parameter (rather than reading the global
 * `kver` directly) purely so this is trivially unit-testable/reviewable in
 * isolation. */
static int sid2ctx_abi_lookup(uint32_t running_kver, const struct sid2ctx_abi **out)
{
    unsigned i;
    for (i = 0; i < SID2CTX_ABI_TABLE_LEN; i++) {
        if (running_kver >= SID2CTX_ABI_TABLE[i].kver_min && running_kver < SID2CTX_ABI_TABLE[i].kver_max) {
            *out = &SID2CTX_ABI_TABLE[i];
            return 1;
        }
    }
    return 0;
}

static void install_deep_hook(void)
{
    const struct sid2ctx_abi *abi = NULL;
    hook_err_t err;

    if (!sid2ctx_abi_lookup(kver, &abi)) {
        pr_warn(
            "zn-auditpatch-kpm: [p2] kernel version 0x%x has no verified GFP_ATOMIC/ABI "
            "table entry, deep hook left DISABLED (part 1 / logd hook still active)\n",
            kver);
        return;
    }

    g_p2_addr = kallsyms_lookup_name("security_sid_to_context");
    if (!g_p2_addr) {
        pr_warn("zn-auditpatch-kpm: [p2] security_sid_to_context not found via kallsyms, deep hook DISABLED\n");
        return;
    }

    g_p2_has_state_arg = abi->has_state_arg;
    g_p2_gfp_atomic = abi->gfp_atomic;

    err = hook_wrap((void *)g_p2_addr, 4, NULL, after_sid_to_context, NULL);
    if (err) {
        pr_err("zn-auditpatch-kpm: [p2] hook_wrap failed, err=%d, deep hook DISABLED\n", err);
        g_p2_addr = 0;
        return;
    }

    g_p2_hooked = 1;
    pr_info("zn-auditpatch-kpm: [p2] deep hook installed on security_sid_to_context (abi=%s, has_state=%d)\n",
            abi->note, g_p2_has_state_arg);
}

/* ==========================================================================
 * Lifecycle
 * ========================================================================== */

static long auditpatch_init(const char *args, const char *event, void *reserved)
{
    hook_err_t err;

    pr_info("zn-auditpatch-kpm: init, kver=0x%x, event=%s, args=%s\n", kver, event ? event : "(null)",
            args ? args : "(null)");

    if (args && args[0] != '\0') {
        strncpy(g_target_comm, args, TASK_COMM_LEN - 1);
        g_target_comm[TASK_COMM_LEN - 1] = '\0';
        pr_info("zn-auditpatch-kpm: [p1] target comm overridden to '%s'\n", g_target_comm);
    } else {
        pr_info("zn-auditpatch-kpm: [p1] target comm defaults to '%s'\n", g_target_comm);
    }

    err = hook_syscalln(__NR_recvfrom, 6, NULL, after_recvfrom, NULL);
    if (err) {
        g_p1_hooked = 0;
        pr_err("zn-auditpatch-kpm: [p1] failed to hook recvfrom, err=%d\n", err);
    } else {
        g_p1_hooked = 1;
        pr_info("zn-auditpatch-kpm: [p1] recvfrom hook installed\n");
    }

    install_deep_hook();

    /* Never fail module load outright, even if both hooks failed: keep the
     * module resident so `kpm info`/dmesg make the failure diagnosable
     * instead of the module silently vanishing. */
    return 0;
}

static long auditpatch_control0(const char *ctl_args, char *__user out_msg, int outlen)
{
    char buf[320];
    int n;

    n = snprintf(buf, sizeof(buf),
                 "p1_hooked=%d target=%s p1_scanned=%lld p1_patched=%lld p1_errors=%lld | "
                 "p2_hooked=%d p2_has_state=%d p2_gfp_atomic=0x%x p2_patched=%lld p2_errors=%lld\n",
                 g_p1_hooked, g_target_comm, (long long)atomic64_read(&g_p1_scanned),
                 (long long)atomic64_read(&g_p1_patched), (long long)atomic64_read(&g_p1_errors), g_p2_hooked,
                 g_p2_has_state_arg, g_p2_gfp_atomic, (long long)atomic64_read(&g_p2_patched),
                 (long long)atomic64_read(&g_p2_errors));
    if (n < 0) n = 0;
    if (n >= (int)sizeof(buf)) n = (int)sizeof(buf) - 1;

    if (ctl_args && !strcmp(ctl_args, "reset")) {
        atomic64_set(&g_p1_scanned, 0);
        atomic64_set(&g_p1_patched, 0);
        atomic64_set(&g_p1_errors, 0);
        atomic64_set(&g_p2_patched, 0);
        atomic64_set(&g_p2_errors, 0);
        n = snprintf(buf, sizeof(buf), "counters reset\n");
    }

    compat_copy_to_user(out_msg, buf, n < outlen ? n + 1 : outlen);
    return 0;
}

static long auditpatch_exit(void *__user reserved)
{
    if (g_p1_hooked) {
        unhook_syscalln(__NR_recvfrom, NULL, after_recvfrom);
        g_p1_hooked = 0;
    }
    if (g_p2_hooked && g_p2_addr) {
        unhook((void *)g_p2_addr);
        g_p2_hooked = 0;
    }
    pr_info("zn-auditpatch-kpm: exit, p1_patched=%lld p2_patched=%lld\n",
            (long long)atomic64_read(&g_p1_patched), (long long)atomic64_read(&g_p2_patched));
    return 0;
}

KPM_INIT(auditpatch_init);
KPM_CTL0(auditpatch_control0);
KPM_EXIT(auditpatch_exit);
