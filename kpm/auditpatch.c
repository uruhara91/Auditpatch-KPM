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
 * compat_copy_to_user()/compat_strncpy_from_user() primitives, and its own
 * scratch copy is a fixed-size buffer on the stack (see SCRATCH_BUF_SIZE) --
 * not a kernel allocator of any kind. It never allocates a kernel object
 * that other kernel code later frees, so it has no allocator-ownership
 * concerns and needs no kernel-version-specific tuning. It is always
 * installed, on every kernel KernelPatch itself runs on.
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
 * 2. Object lifetime and allocator availability. The buffer `*scontext`
 *    points to is a real kernel object that the *caller* eventually
 *    frees (verified directly in security/selinux/avc.c's
 *    avc_audit_post_callback and fs/proc/base.c's proc_pid_attr_read,
 *    both of which kfree() it after use, and in
 *    security/selinux/ss/services.c's context_struct_to_string, which
 *    allocates it with a plain kstrdup() -- exactly strlen()+1 bytes, no
 *    slack). This module used to swap in a freshly kmalloc()'d
 *    replacement buffer here, reasoning that this KPM's own kp_malloc()
 *    allocator (used in PART 1's scratch buffer at the time) would hand
 *    the kernel's real kfree() a pointer it never allocated. That
 *    reasoning about kfree() compatibility was correct, but it turned out
 *    to rest on a wrong assumption in the other direction: on the device
 *    this was actually debugged against, a bug report's boot log showed
 *    the *entire module* failing to load ("unknown symbol", rc=-2 /
 *    -ENOENT from KernelPatch's own kernel/patch/module/module.c) because
 *    kf_kmalloc, kf___kmalloc, kf_kfree, tlsf_malloc, tlsf_free, and
 *    kp_rw_mem were *all* absent from that build's exported symbol table
 *    -- not just the real kernel's kmalloc()/kfree(), but also
 *    kp_malloc()/kp_free() themselves, since kpmalloc.h's kp_malloc() and
 *    kp_free() are `static inline` wrappers around exactly
 *    tlsf_malloc()/tlsf_free()/kp_rw_mem. Neither allocator was actually
 *    reliably present; only one of the two failures was visible at first
 *    because the other was hidden behind inlining. In other words: no
 *    kernel-object allocator this module could call -- KernelPatch's own
 *    or the real kernel's -- is a safe assumption to depend on across
 *    KernelPatch builds.
 *
 *    So neither part of this module allocates kernel objects anymore.
 *    PART 2 overwrites the existing context buffer *in place*, which
 *    means the replacement text can never be longer than the shortest
 *    pattern it might replace (see CTX_REPLACEMENT_SHORT below) -- a real
 *    cosmetic downgrade from a freely-sized replacement, accepted
 *    deliberately in exchange for the module actually loading. PART 1
 *    (see after_recvfrom) switched its scratch buffer from kp_malloc() to
 *    a fixed-size buffer on the stack, which needs no allocator symbol at
 *    all since it never leaves the function or outlives the call.
 *
 * Kernel-version ABI shape is still tracked in SID2CTX_ABI_TABLE below
 * (only has_state_arg now, since there's no GFP flag to get right anymore
 * -- see git history if you want the version that needed one). On a
 * kernel version that matches a table entry, the deep hook installs. On
 * anything else, it does not -- it is left disabled rather than guessed
 * at, and PART 1 (recvfrom/logd) keeps working regardless.
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
#include <linux/kallsyms.h>
#include <asm/atomic.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <hook.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("zn-auditpatch-kpm");
KPM_VERSION("2.2.0");
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

/* PART 2 (see after_sid_to_context) can only ever overwrite the existing
 * context buffer *in place* -- see the long comment above PART 2 for why
 * it cannot allocate a replacement the way PART 1 does. That means its
 * replacement must never be longer than the shortest pattern it might
 * replace (CTX_SU, 9 bytes), since context_struct_to_string() allocates
 * exactly strlen(original)+1 bytes with zero slack (confirmed against
 * real kernel source: it's a plain kstrdup()). Deliberately short and
 * generic rather than a closer copy of CTX_REPLACEMENT above -- being
 * unable to grow the buffer is the binding constraint here, not stylistic
 * preference.
 */
#define CTX_REPLACEMENT_SHORT "u:r:na:s0"
#define CTX_REPLACEMENT_SHORT_LEN (sizeof(CTX_REPLACEMENT_SHORT) - 1)

/* PART 1 matches inside a formatted log line, so it needs the "tcontext="
 * prefix glued on (plain C string literal concatenation). Only tcontext=,
 * never scontext=, exactly like upstream ZN-AuditPatch. */
static const char PATTERN_SU[] = "tcontext=" CTX_SU;
static const char PATTERN_MAGISK[] = "tcontext=" CTX_MAGISK;
static const char PATTERN_REPLACEMENT[] = "tcontext=" CTX_REPLACEMENT;

#define PATTERN_SU_LEN (sizeof(PATTERN_SU) - 1)
#define PATTERN_MAGISK_LEN (sizeof(PATTERN_MAGISK) - 1)
#define PATTERN_REPLACEMENT_LEN (sizeof(PATTERN_REPLACEMENT) - 1)

/* sizeof() is a compiler construct, not something the preprocessor can
 * evaluate in #if, so this constraint is enforced with a real compile-time
 * assertion instead of #if/#error. */
_Static_assert(CTX_REPLACEMENT_SHORT_LEN <= (sizeof(CTX_SU) - 1),
                "CTX_REPLACEMENT_SHORT must never be longer than CTX_SU (see comment above)");

/* PART 1's scratch copy is a fixed-size buffer *on the stack*, not a
 * kp_malloc()/kp_free() allocation -- see the long comment above
 * after_recvfrom() for why kp_malloc()/kp_free() (backed by
 * tlsf_malloc()/tlsf_free()/kp_rw_mem under the hood) turned out not to be
 * a safe assumption either. 1536 bytes comfortably covers real AVC audit
 * lines (a few hundred bytes in practice; MAX_AUDIT_MESSAGE_LENGTH in AOSP
 * libaudit.h is 8970 as a theoretical ceiling, but a hook running on top
 * of an unknown, already-partially-used kernel stack has no business
 * reserving anything close to that) while staying well inside the
 * fast-check CI job's stack-usage budget for this function. A read that
 * doesn't fit is simply left unpatched rather than truncated or
 * overflowed -- see the size check in after_recvfrom(). */
#define SCRATCH_BUF_SIZE 1536

/* The largest a match can possibly grow by: PATTERN_REPLACEMENT_LEN minus
 * the shortest pattern we match against (PATTERN_SU). Used to make sure
 * there's room left in SCRATCH_BUF_SIZE for growth, not just the raw
 * bytes read. */
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
 *
 * Uses a fixed-size on-stack scratch buffer, not kp_malloc()/kp_free().
 * That switch (from an earlier version of this module that did use
 * kp_malloc()/kp_free()) exists for the same reason PART 2 no longer
 * allocates at all: kp_malloc()/kp_free() are static inline wrappers
 * around tlsf_malloc()/tlsf_free()/kp_rw_mem (see kpmalloc.h), and those
 * turned out to be exactly the symbols missing from the KernelPatch build
 * this was actually debugged against -- "unknown symbol: tlsf_malloc" /
 * "tlsf_free" / "kp_rw_mem", right alongside the kmalloc()/kfree() ones,
 * in the same failed load. A scratch buffer that's purely local to this
 * function -- never handed to any other kernel code, never outliving this
 * call -- has no reason to go through a kernel allocator of any kind in
 * the first place; a fixed-size local array sidesteps the whole class of
 * problem.
 */
static void after_recvfrom(hook_fargs6_t *args, void *udata)
{
    long ret;
    uint64_t buf_arg, cap_arg;
    void __user *ubuf;
    int user_cap;
    long copied;
    int len;
    int patched;
    char scratch[SCRATCH_BUF_SIZE];
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
    if (cap_arg == 0 || cap_arg > (uint64_t)(SCRATCH_BUF_SIZE - 1)) {
        user_cap = SCRATCH_BUF_SIZE - 1;
    } else {
        user_cap = (int)cap_arg;
    }
    if (ret > user_cap) ret = user_cap;

    /* Doesn't fit our fixed scratch buffer with room for growth -- leave
     * it unpatched rather than truncate or overflow. Real AVC lines are a
     * few hundred bytes, so this should essentially never trigger; if it
     * does, PART 1 just silently doesn't cover that one oversized read. */
    if (ret + ALLOC_HEADROOM > (int)sizeof(scratch)) return;

    atomic64_inc(&g_p1_scanned);

    copied = compat_strncpy_from_user(scratch, (const char __user *)ubuf, ret);
    if (copied <= 0) return;

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
}

/* ==========================================================================
 * PART 2: deep security_sid_to_context hook (version-gated)
 * ========================================================================== */

struct sid2ctx_abi {
    uint32_t kver_min; /* inclusive */
    uint32_t kver_max; /* exclusive */
    int has_state_arg; /* security_sid_to_context(state, sid, ...) vs (sid, ...) */
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
    { VERSION(4, 19, 0), VERSION(5, 0, 0), 1, "4.19.x" },
    /* android-5.4-stable, android12-5.10, android13-5.15, android14-6.1,
     * and mainline v5.4/v5.10/v5.15/v6.1 */
    { VERSION(5, 0, 0), VERSION(6, 4, 0), 1, "5.4.x-6.3.x" },
    /* android15-6.6 and mainline v6.4/v6.6/v6.12 (state arg dropped again) */
    { VERSION(6, 4, 0), VERSION(7, 0, 0), 0, "6.4.x+" },
};

#define SID2CTX_ABI_TABLE_LEN (sizeof(SID2CTX_ABI_TABLE) / sizeof(SID2CTX_ABI_TABLE[0]))

/*
 * after-hook on security_sid_to_context(), 4 argument slots captured
 * unconditionally (harmless to over-capture one unused register on the
 * 3-arg ABI -- see g_p2_has_state_arg branch below).
 *
 * Deliberately never allocates. Real kernel kmalloc()/kfree() are NOT a
 * safe default assumption across KernelPatch builds -- confirmed the hard
 * way: on the device this was debugged against, kmalloc()/kfree() (and
 * their underlying kf_kmalloc, kf___kmalloc, kf_kfree, tlsf_malloc,
 * tlsf_free, and kp_rw_mem symbols) were simply absent from that build's
 * exported symbol table, which made the *entire module* fail to load
 * ("unknown symbol", rc=-2 / -ENOENT from KernelPatch's own module.c)
 * even though every other symbol it needs (including kp_malloc/kp_free,
 * used by PART 1) resolved fine. So PART 2 only ever overwrites the
 * existing buffer in place -- see the CTX_REPLACEMENT_SHORT comment above
 * for why that bounds what the replacement can say.
 */
static void after_sid_to_context(hook_fargs4_t *args, void *udata)
{
    char **scontext_ptr;
    uint32_t *scontext_len_ptr;
    char *scontext;

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

    /* CTX_REPLACEMENT_SHORT_LEN <= strlen(CTX_SU) is enforced at compile
     * time above, and CTX_SU is the shorter of the two patterns we match,
     * so this write (including its NUL) always fits inside the buffer
     * context_struct_to_string() originally kstrdup()'d -- confirmed
     * against real kernel source that it allocates exactly
     * strlen(original)+1 bytes, no slack. Same pointer, same allocation,
     * untouched otherwise: whoever eventually kfree()s *scontext_ptr
     * still frees exactly what security_sid_to_context() gave them. */
    memcpy(scontext, CTX_REPLACEMENT_SHORT, CTX_REPLACEMENT_SHORT_LEN + 1);
    *scontext_len_ptr = (uint32_t)CTX_REPLACEMENT_SHORT_LEN;

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
            "zn-auditpatch-kpm: [p2] kernel version 0x%x has no verified ABI "
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
                 "p2_hooked=%d p2_has_state=%d p2_patched=%lld p2_errors=%lld\n",
                 g_p1_hooked, g_target_comm, (long long)atomic64_read(&g_p1_scanned),
                 (long long)atomic64_read(&g_p1_patched), (long long)atomic64_read(&g_p1_errors), g_p2_hooked,
                 g_p2_has_state_arg, (long long)atomic64_read(&g_p2_patched), (long long)atomic64_read(&g_p2_errors));
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
