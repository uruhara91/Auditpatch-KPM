/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * auditpatch-kpm
 *
 * KernelPatch Module (KPM) port of the "ZN-AuditPatch" Zygisk Next module
 * (https://github.com/aviraxp/ZN-AuditPatch, see also
 * https://android-review.googlesource.com/c/platform/system/logging/+/3725346).
 * Full design rationale and bug history: see README.md and DEBUGGING.md.
 *
 * PART 1 (always active): hooks recvfrom() system-wide. logd receives every
 * raw AVC denial line via recvfrom() on a netlink socket before its own
 * vasprintf() formats it -- so this hooks recvfrom()'s *after* callback,
 * filters by caller comm ("logd" by default), and rewrites a matched
 * `tcontext=su/magisk` pattern in place (same anti-spoof quote-escape
 * heuristic as upstream, see has_quote_after()). Uses a fixed-size stack
 * scratch buffer, never a kernel allocator -- see DEBUGGING.md Bug 2 for
 * why that matters.
 *
 * PART 1b (v2.4.0+): same technique applied to plain read(), since some
 * ROM/vendor logd forks read the audit socket that way. Unlike recvfrom(),
 * read() isn't inherently socket-scoped, so this can't cheaply confirm the
 * fd is really the audit socket -- see after_read() below.
 *
 * PART 1c (unreleased): same technique again, applied to syslog(2)
 * (bionic's klogctl()). AOSP's logd calls this once at startup to replay
 * any AVC denials that were logged via printk() during early boot, before
 * logd's own netlink listener (PART 1) existed -- that content never
 * touches recvfrom() or read() at all. See after_syslog() and
 * DEBUGGING.md for how this gap was found.
 *
 * PART 2 (optional, version-gated): PART 1/1b only rewrite logd's
 * formatted log line. Every other SID->string lookup (e.g.
 * /proc/[pid]/attr/current) goes through security_sid_to_context() in
 * security/selinux/ss/services.c; hooking that directly covers all of
 * them, system-wide -- strictly broader than PART 1, since it can't
 * distinguish "su/magisk is the denial target" from "su/magisk is the
 * source" or plain introspection.
 *
 * security_sid_to_context()'s C signature has changed twice in kernel
 * history (3-arg / 4-arg-with-state / 3-arg again). This hook only
 * installs when the running kernel matches a verified entry in
 * SID2CTX_ABI_TABLE (patch_logic.h) -- see DEBUGGING.md for exactly which
 * kernel branches each entry was checked against. No match -> hook stays
 * disabled, PART 1/1b unaffected.
 *
 * Neither PART 1/1b nor PART 2 allocate a kernel object: PART 1/1b use a
 * stack-local scratch buffer, and PART 2 overwrites the existing context
 * buffer in place (hence CTX_REPLACEMENT_SHORT being short/generic rather
 * than PART 1's fuller replacement). See DEBUGGING.md Bug 2 for the real
 * load failure that drove this.
 *
 * Configuring extra SELinux domains beyond the builtin su/magisk pair:
 * see parse_args() below and struct extra_domain in patch_logic.h for the
 * safety invariant it depends on (type name >= 2 chars, or PART 2's
 * in-place overwrite could overflow -- checked at parse time and again at
 * the write site in after_sid_to_context()).
 *
 * Deliberately not implemented: recvmsg() coverage (a real API
 * constraint) and a general printk()-wide hook (out of scope by design).
 * See DEBUGGING.md for the reasoning.
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

/* Pure string/ABI-table logic lives in patch_logic.h, shared verbatim with
 * tests/test_logic.c's host-side unit tests -- see that header for why.
 * Included after the kernel headers above so its VERSION()/strnstr()
 * fallback guards see those definitions already in scope. */
#include "patch_logic.h"

KPM_NAME("auditpatch-kpm");
KPM_VERSION("2.4.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("aviraxp, uruhara91");
KPM_DESCRIPTION("Hide su/magisk context from AVC audit logs (+ optional deep SELinux hook)");

/* ------------------------------------------------------------------------
 * Shared constants
 * ------------------------------------------------------------------------
 * CTX_SU/CTX_MAGISK/CTX_REPLACEMENT/CTX_REPLACEMENT_SHORT, the PATTERN_*
 * strings built from them, MAX_EXTRA_DOMAINS and struct extra_domain all
 * now live in patch_logic.h (shared verbatim with the host unit tests) --
 * see that header. Only what stays genuinely kernel/module-specific
 * remains here. */

/* Default target process for PART 1/1b, overridable at `kpm load` time via
 * KPM_ARGS (see parse_args). */
#define DEFAULT_TARGET_COMM "logd"

/* PART 1/1b's scratch copy is a fixed-size buffer *on the stack*, not a
 * kp_malloc()/kp_free() allocation -- see DEBUGGING.md Bug 2. 1536 bytes
 * comfortably covers real AVC audit lines (a few hundred bytes in
 * practice; AOSP's MAX_AUDIT_MESSAGE_LENGTH is 8970 as a theoretical
 * ceiling, but a hook running on an unknown, already-partially-used
 * kernel stack shouldn't reserve anywhere near that) while staying well
 * inside the CI stack-usage budget. A read that doesn't fit is left
 * unpatched rather than truncated -- see the size check in
 * after_recvfrom()/after_read(). */
#define SCRATCH_BUF_SIZE 1536

/* The largest a match can possibly grow by: PATTERN_REPLACEMENT_LEN minus
 * the shortest *builtin* pattern we match against (PATTERN_SU). Extra
 * domains configured via args can only ever produce a pattern >= that
 * length too (MIN_EXTRA_DOMAIN_TYPE_LEN in patch_logic.h guarantees it),
 * so PATTERN_SU remains a valid worst-case baseline for this early-return
 * headroom check even with extra domains in play. Note this check is a
 * "don't bother trying" optimization, not the actual safety net -- see
 * try_patch_one()'s own `new_len > cap` check in patch_logic.h, which is
 * what really bounds every write regardless of which pattern is used. */
#define MAX_GROWTH (PATTERN_REPLACEMENT_LEN - PATTERN_SU_LEN)
#define ALLOC_HEADROOM (MAX_GROWTH + 16)

/* ------------------------------------------------------------------------
 * State
 * ------------------------------------------------------------------------ */

static char g_target_comm[TASK_COMM_LEN] = DEFAULT_TARGET_COMM;

/* Extra SELinux domains configured via KPM args, beyond the builtin
 * su/magisk pair -- see parse_args(). Set once at init, never mutated
 * afterward, so concurrent hook callbacks on other CPUs can read it
 * lock-free (same reasoning as g_target_comm below). */
static struct extra_domain g_extra_domains[MAX_EXTRA_DOMAINS];
static int g_extra_domain_count = 0;

/* Plain counters incremented from a hook can run on any CPU concurrently
 * (recvfrom()/read()/security_sid_to_context() are not serialized against
 * each other across cores), so these are atomic64_t rather than a bare
 * volatile uint64_t -- purely so the stats reported by ctl0 can't lose
 * updates under concurrent access. Nothing security-relevant depends on
 * these; only the reporting does. */
static atomic64_t g_p1_scanned = ATOMIC64_INIT(0);
static atomic64_t g_p1_patched = ATOMIC64_INIT(0);
static atomic64_t g_p1_errors = ATOMIC64_INIT(0);
static int g_p1_hooked = 0;

/* PART 1b: same technique as PART 1, applied to plain read() as well as
 * recvfrom() -- see the comment above after_read() for what this does and
 * does not cover. */
static atomic64_t g_p1b_scanned = ATOMIC64_INIT(0);
static atomic64_t g_p1b_patched = ATOMIC64_INIT(0);
static atomic64_t g_p1b_errors = ATOMIC64_INIT(0);
static int g_p1b_hooked = 0;

/* PART 1c: same technique again, applied to syslog(2) (bionic's klogctl()).
 * logd calls this once at startup (KLOG_READ_ALL) to drain any AVC denials
 * that were logged via printk() during early boot, before its own
 * NETLINK_AUDIT listener (PART 1) was even running -- see the comment
 * above after_syslog() and DEBUGGING.md for how this was found. */
static atomic64_t g_p1c_scanned = ATOMIC64_INIT(0);
static atomic64_t g_p1c_patched = ATOMIC64_INIT(0);
static atomic64_t g_p1c_errors = ATOMIC64_INIT(0);
static int g_p1c_hooked = 0;

static atomic64_t g_p2_patched = ATOMIC64_INIT(0);
static atomic64_t g_p2_errors = ATOMIC64_INIT(0);
static int g_p2_hooked = 0;
static int g_p2_has_state_arg = 0;
static uint64_t g_p2_addr = 0;

/* ==========================================================================
 * Args parsing: target comm + extra domains
 * ========================================================================== */

/*
 * KPM args format: "<target_comm>[,<extra_type>[,<extra_type>...]]"
 *   - First segment overrides g_target_comm, exactly as before (backward
 *     compatible with every existing `kpm load ... "somecomm"` invocation --
 *     a bare comm with no comma behaves identically to the old code).
 *   - Each remaining comma-separated segment is a bare SELinux *type* name
 *     (e.g. "ksu") for a custom su implementation. This module builds
 *     "u:r:<type>:s0" from it and treats it exactly like CTX_SU/CTX_MAGISK
 *     in both PART 1/1b (text pattern) and PART 2 (direct context match).
 *     See MIN_EXTRA_DOMAIN_TYPE_LEN in patch_logic.h for why a 1-character
 *     type is rejected outright rather than merely discouraged.
 *
 * No allocation: everything here writes into the fixed g_extra_domains[]
 * array (MAX_EXTRA_DOMAINS entries), same "no kernel allocator" reasoning
 * as PART 1/2's scratch buffers -- see the long comment near the top of
 * this file.
 */
static void parse_args(const char *args)
{
    const char *p = args;
    const char *comma;
    size_t seg_len;

    if (!args || args[0] == '\0') {
        pr_info("auditpatch-kpm: [args] target comm defaults to '%s', no extra domains\n", g_target_comm);
        return;
    }

    comma = strchr(p, ',');
    seg_len = comma ? (size_t)(comma - p) : strlen(p);
    if (seg_len > 0) {
        if (seg_len > TASK_COMM_LEN - 1) seg_len = TASK_COMM_LEN - 1;
        memcpy(g_target_comm, p, seg_len);
        g_target_comm[seg_len] = '\0';
        pr_info("auditpatch-kpm: [args] target comm overridden to '%s'\n", g_target_comm);
    }

    if (!comma) return;
    p = comma + 1;

    while (*p && g_extra_domain_count < MAX_EXTRA_DOMAINS) {
        struct extra_domain *d;

        comma = strchr(p, ',');
        seg_len = comma ? (size_t)(comma - p) : strlen(p);

        if (!extra_domain_type_len_ok(seg_len)) {
            pr_warn(
                "auditpatch-kpm: [args] skipping extra domain token of invalid length "
                "(%zu, need %d..%d), '%s' unaffected\n",
                seg_len, MIN_EXTRA_DOMAIN_TYPE_LEN, MAX_EXTRA_DOMAIN_TYPE_LEN, g_target_comm);
        } else {
            d = &g_extra_domains[g_extra_domain_count];
            memcpy(d->type, p, seg_len);
            d->type[seg_len] = '\0';
            d->raw_ctx_len = snprintf(d->raw_ctx, sizeof(d->raw_ctx), "u:r:%s:s0", d->type);
            d->pattern_len = snprintf(d->pattern, sizeof(d->pattern), "tcontext=u:r:%s:s0", d->type);
            pr_info("auditpatch-kpm: [args] extra domain #%d: type='%s' raw='%s'\n", g_extra_domain_count,
                    d->type, d->raw_ctx);
            g_extra_domain_count++;
        }

        if (!comma) break;
        p = comma + 1;
    }

    if (*p && g_extra_domain_count >= MAX_EXTRA_DOMAINS) {
        pr_warn("auditpatch-kpm: [args] extra domain list truncated at %d entries (MAX_EXTRA_DOMAINS)\n",
                MAX_EXTRA_DOMAINS);
    }
}

/* ==========================================================================
 * PART 1: logd / recvfrom hook
 * ========================================================================== */

/*
 * Try every configured pattern (builtin su/magisk, then any extra domains
 * from parse_args) against one buffer, stopping at the first match. Shared
 * between after_recvfrom() and after_read() so the two hooks can never
 * drift out of sync on which patterns they look for.
 */
static int try_patch_any(char *buf, int *len, int cap)
{
    int i;

    if (try_patch_one(buf, len, cap, PATTERN_SU, (int)PATTERN_SU_LEN)) return 1;
    if (try_patch_one(buf, len, cap, PATTERN_MAGISK, (int)PATTERN_MAGISK_LEN)) return 1;

    for (i = 0; i < g_extra_domain_count; i++) {
        if (try_patch_one(buf, len, cap, g_extra_domains[i].pattern, g_extra_domains[i].pattern_len)) return 1;
    }
    return 0;
}

/*
 * after-hook on recvfrom(int sockfd, void *buf, size_t len, int flags,
 *                        struct sockaddr *src_addr, socklen_t *addrlen)
 *
 * Uses a fixed-size on-stack scratch buffer, not kp_malloc()/kp_free() --
 * a scratch buffer purely local to this function, never handed to other
 * kernel code, has no reason to go through a kernel allocator at all. See
 * DEBUGGING.md Bug 2 for the real load failure that motivated this.
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
    patched = try_patch_any(scratch, &len, user_cap);

    if (patched) {
        if (compat_copy_to_user(ubuf, scratch, len) == 0) {
            args->ret = (uint64_t)len;
            atomic64_inc(&g_p1_patched);
            pr_info("auditpatch-kpm: [p1] patched avc audit tcontext in '%s' (total: %lld)\n", comm,
                    (long long)atomic64_read(&g_p1_patched));
        } else {
            atomic64_inc(&g_p1_errors);
            pr_err("auditpatch-kpm: [p1] compat_copy_to_user failed\n");
        }
    }
}

/* ==========================================================================
 * PART 1b: read() hook -- same technique, a different (and riskier) syscall
 * ========================================================================== */

/*
 * after-hook on read(int fd, void *buf, size_t count).
 *
 * Some ROM/vendor logd forks read the netlink audit socket with plain
 * read() instead of recvfrom() (recvfrom() with a NULL src_addr is
 * functionally just read() on a connected/bound socket). Its (buf, count)
 * argument shape maps onto syscall_argn(args, {1,2}) the exact same way
 * recvfrom's does, and the payload is the same NUL-terminated AVC text, so
 * this reuses try_patch_any()/the same scratch-buffer discipline verbatim
 * -- no new allocation, no new buffer-safety story to get right.
 *
 * What IS genuinely different from PART 1, and does not have a clean
 * answer: recvfrom() is a socket-only syscall, so hooking it is inherently
 * already scoped to socket I/O. read() is not -- it's used on regular
 * files, pipes, and anything else with a file descriptor. This hook has no
 * cheap way to confirm `fd` is actually the netlink audit socket before
 * touching the buffer; it relies entirely on the existing g_target_comm
 * filter (default "logd") plus the pattern match itself (an unrelated
 * file would need to contain the literal byte sequence
 * "tcontext=u:r:su:s0" at the exact offset read() returned to be touched
 * at all) to keep the blast radius narrow. Verifying the fd is really a
 * NETLINK_AUDIT socket would need fdget()/sock_from_file()-style
 * kernel-internal calls resolved via kallsyms, with their own
 * version-specific ABI risk -- the same kind of complexity PART 2 already
 * carries for one function. Left as a known, explicitly-stated gap rather
 * than adding that complexity silently; see README.
 */
static void after_read(hook_fargs3_t *args, void *udata)
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

    if (ret + ALLOC_HEADROOM > (int)sizeof(scratch)) return;

    atomic64_inc(&g_p1b_scanned);

    copied = compat_strncpy_from_user(scratch, (const char __user *)ubuf, ret);
    if (copied <= 0) return;

    len = (int)copied;
    patched = try_patch_any(scratch, &len, user_cap);

    if (patched) {
        if (compat_copy_to_user(ubuf, scratch, len) == 0) {
            args->ret = (uint64_t)len;
            atomic64_inc(&g_p1b_patched);
            pr_info("auditpatch-kpm: [p1b] patched avc audit tcontext via read() in '%s' (total: %lld)\n", comm,
                    (long long)atomic64_read(&g_p1b_patched));
        } else {
            atomic64_inc(&g_p1b_errors);
            pr_err("auditpatch-kpm: [p1b] compat_copy_to_user failed\n");
        }
    }
}

/*
 * after-hook on syslog(int type, char *buf, int len) -- SYSCALL_DEFINE3(syslog, ...)
 * in kernel/printk/printk.c, which bionic's klogctl() wraps.
 *
 * logd's main() calls klogctl(KLOG_READ_ALL, ...) exactly once at startup,
 * before its NETLINK_AUDIT listener (PART 1) is running, specifically to
 * replay any kernel ring-buffer content -- including AVC denials that were
 * logged via printk() because nothing was listening on the audit netlink
 * multicast group yet -- into its own log buffer (see readDmesg() in
 * AOSP's logd/main.cpp). That content never touches recvfrom() or read():
 * it arrives through this syscall alone, once, at boot. Confirmed against
 * real kernel source (kernel/printk/printk.c) that syslog()'s argument
 * layout is arg0=type, arg1=buf, arg2=len, ret=bytes written to buf on
 * success -- structurally identical to read()'s (fd, buf, count), so this
 * reuses the exact same scratch-buffer/try_patch_any() technique as
 * after_read() above, not a new algorithm. See DEBUGGING.md for how this
 * gap was found and what was actually checked before adding it.
 *
 * Deliberately does not filter on `type` (e.g. requiring the
 * KLOG_READ_ALL value bionic happens to use today): a different `type`
 * still returns kernel-ring-buffer text into the same flat `buf`, and
 * gating on one specific integer would be exactly the kind of unverified,
 * pattern-matched assumption this project's own ABI-table comments argue
 * against. Same safety net as PART 1/1b instead: g_target_comm plus the
 * pattern match itself.
 */
static void after_syslog(hook_fargs3_t *args, void *udata)
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

    if (ret + ALLOC_HEADROOM > (int)sizeof(scratch)) return;

    atomic64_inc(&g_p1c_scanned);

    copied = compat_strncpy_from_user(scratch, (const char __user *)ubuf, ret);
    if (copied <= 0) return;

    len = (int)copied;
    patched = try_patch_any(scratch, &len, user_cap);

    if (patched) {
        if (compat_copy_to_user(ubuf, scratch, len) == 0) {
            args->ret = (uint64_t)len;
            atomic64_inc(&g_p1c_patched);
            pr_info("auditpatch-kpm: [p1c] patched avc audit tcontext via syslog() in '%s' (total: %lld)\n", comm,
                    (long long)atomic64_read(&g_p1c_patched));
        } else {
            atomic64_inc(&g_p1c_errors);
            pr_err("auditpatch-kpm: [p1c] compat_copy_to_user failed\n");
        }
    }
}

/* ==========================================================================
 * PART 2: deep security_sid_to_context hook (version-gated)
 * ========================================================================== */
/* struct sid2ctx_abi, SID2CTX_ABI_TABLE and sid2ctx_abi_lookup() now live in
 * patch_logic.h (shared verbatim with the host unit tests) -- see that
 * header for the table itself and the provenance note above it. */

/*
 * after-hook on security_sid_to_context(), 4 argument slots captured
 * unconditionally (harmless to over-capture one unused register on the
 * 3-arg ABI -- see g_p2_has_state_arg branch below).
 *
 * Deliberately never allocates -- real kernel kmalloc()/kfree() is not a
 * safe default assumption across KernelPatch builds, see DEBUGGING.md Bug
 * 2. So this only ever overwrites the existing buffer in place -- see the
 * CTX_REPLACEMENT_SHORT comment above for why that bounds the replacement.
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

    if (strcmp(scontext, CTX_SU) && strcmp(scontext, CTX_MAGISK)) {
        int i, matched = 0;
        for (i = 0; i < g_extra_domain_count; i++) {
            if (!strcmp(scontext, g_extra_domains[i].raw_ctx)) {
                matched = 1;
                break;
            }
        }
        if (!matched) return;
    }

    /* AUDITPATCH_TRUST_BUT_VERIFY: CTX_REPLACEMENT_SHORT_LEN <= every
     * matchable context's length is *supposed* to already be guaranteed --
     * at compile time for CTX_SU/CTX_MAGISK (_Static_assert in
     * patch_logic.h), and at parse time for extra domains
     * (extra_domain_type_len_ok() in parse_args()). But this is the one
     * place that invariant actually matters: the next line overwrites a
     * real kernel object in place, kstrdup()'d to exactly
     * strlen(original)+1 bytes with zero slack. "Should be unreachable"
     * is not good enough justification for skipping the check right next
     * to the unsafe write it protects -- verify the actual buffer we're
     * about to overwrite is long enough, not just trust that every caller
     * upheld the invariant correctly. */
    if (strlen(scontext) < CTX_REPLACEMENT_SHORT_LEN) {
        atomic64_inc(&g_p2_errors);
        pr_err(
            "auditpatch-kpm: [p2] BUG: matched context '%s' (len=%zu) shorter than "
            "replacement (len=%d), refusing to avoid buffer overflow\n",
            scontext, strlen(scontext), (int)CTX_REPLACEMENT_SHORT_LEN);
        return;
    }

    /* Same pointer, same allocation, untouched otherwise: whoever
     * eventually kfree()s *scontext_ptr still frees exactly what
     * security_sid_to_context() gave them. */
    memcpy(scontext, CTX_REPLACEMENT_SHORT, CTX_REPLACEMENT_SHORT_LEN + 1);
    *scontext_len_ptr = (uint32_t)CTX_REPLACEMENT_SHORT_LEN;

    atomic64_inc(&g_p2_patched);
    pr_info("auditpatch-kpm: [p2] patched sid->context result (total: %lld)\n",
            (long long)atomic64_read(&g_p2_patched));
}

static void install_deep_hook(void)
{
    const struct sid2ctx_abi *abi = NULL;
    hook_err_t err;

    if (!sid2ctx_abi_lookup(kver, &abi)) {
        pr_warn(
            "auditpatch-kpm: [p2] kernel version 0x%x has no verified ABI "
            "table entry, deep hook left DISABLED (part 1 / logd hook still active)\n",
            kver);
        return;
    }

    g_p2_addr = kallsyms_lookup_name("security_sid_to_context");
    if (!g_p2_addr) {
        pr_warn("auditpatch-kpm: [p2] security_sid_to_context not found via kallsyms, deep hook DISABLED\n");
        return;
    }

    g_p2_has_state_arg = abi->has_state_arg;

    err = hook_wrap((void *)g_p2_addr, 4, NULL, after_sid_to_context, NULL);
    if (err) {
        pr_err("auditpatch-kpm: [p2] hook_wrap failed, err=%d, deep hook DISABLED\n", err);
        g_p2_addr = 0;
        return;
    }

    g_p2_hooked = 1;
    pr_info("auditpatch-kpm: [p2] deep hook installed on security_sid_to_context (abi=%s, has_state=%d)\n",
            abi->note, g_p2_has_state_arg);
}

/* ==========================================================================
 * Lifecycle
 * ========================================================================== */

static long auditpatch_init(const char *args, const char *event, void *reserved)
{
    hook_err_t err;

    pr_info("auditpatch-kpm: init, kver=0x%x, event=%s, args=%s\n", kver, event ? event : "(null)",
            args ? args : "(null)");

    /* Defensive: KPM_INIT is only expected to run once per load, but
     * nothing in this file enforces that on its own, and hook_syscalln()/
     * hook_wrap() have no documented "already hooked, no-op" behavior for
     * a second registration of the same before/after pair -- worst case
     * that would silently stack a duplicate chain entry and run each hook
     * callback twice per event. Cheap to guard against outright rather
     * than rely on this never being reachable. */
    if (g_p1_hooked || g_p1b_hooked || g_p1c_hooked || g_p2_hooked) {
        pr_warn("auditpatch-kpm: init called while already hooked, ignoring (p1=%d p1b=%d p1c=%d p2=%d)\n",
                g_p1_hooked, g_p1b_hooked, g_p1c_hooked, g_p2_hooked);
        return 0;
    }

    parse_args(args);

    err = hook_syscalln(__NR_recvfrom, 6, NULL, after_recvfrom, NULL);
    if (err) {
        g_p1_hooked = 0;
        pr_err("auditpatch-kpm: [p1] failed to hook recvfrom, err=%d\n", err);
    } else {
        g_p1_hooked = 1;
        pr_info("auditpatch-kpm: [p1] recvfrom hook installed\n");
    }

    err = hook_syscalln(__NR_read, 3, NULL, after_read, NULL);
    if (err) {
        g_p1b_hooked = 0;
        pr_err("auditpatch-kpm: [p1b] failed to hook read, err=%d\n", err);
    } else {
        g_p1b_hooked = 1;
        pr_info("auditpatch-kpm: [p1b] read hook installed\n");
    }

    err = hook_syscalln(__NR_syslog, 3, NULL, after_syslog, NULL);
    if (err) {
        g_p1c_hooked = 0;
        pr_err("auditpatch-kpm: [p1c] failed to hook syslog, err=%d\n", err);
    } else {
        g_p1c_hooked = 1;
        pr_info("auditpatch-kpm: [p1c] syslog hook installed\n");
    }

    install_deep_hook();

    /* Never fail module load outright, even if both hooks failed: keep the
     * module resident so `kpm info`/dmesg make the failure diagnosable
     * instead of the module silently vanishing. */
    return 0;
}

/*
 * Exercises PART 1's actual matching/replacement logic (try_patch_one) on
 * synthetic buffers, so correctness can be checked on demand
 * (`kpm ctl0 auditpatch-kpm selftest`) without waiting for a real
 * su/magisk-domain AVC denial to happen to trigger it. Four cases:
 *   1. a realistic su-domain denial line -> must patch
 *   2. a realistic magisk-domain denial line -> must patch
 *   3. su pattern embedded inside a quoted field (spoofing attempt) ->
 *      must NOT patch (has_quote_after's whole job)
 *   4. a denial line naming a *synthetic* extra domain ("ksu"), built the
 *      same way parse_args() would build one from KPM args -> must patch.
 *      Uses a purely local struct extra_domain, not g_extra_domains, so
 *      this is safe to run regardless of what (if anything) was actually
 *      configured at load time.
 * Returns 1 if all four behaved as expected, 0 otherwise.
 */
static int run_selftest(void)
{
    char case1[256];
    char case2[256];
    char case3[256];
    int len, patched, ok = 1;

    len = snprintf(case1, sizeof(case1),
                    "avc: denied { binder_transfer } for pid=1234 comm=\"some_app\" "
                    "scontext=u:r:priv_app:s0 tcontext=u:r:su:s0 tclass=binder permissive=0");
    patched = try_patch_one(case1, &len, (int)sizeof(case1) - 1, PATTERN_SU, (int)PATTERN_SU_LEN);
    if (!patched || !strnstr(case1, CTX_REPLACEMENT, len)) {
        pr_warn("auditpatch-kpm: [selftest] case 1 (su denial) FAILED\n");
        ok = 0;
    }

    len = snprintf(case2, sizeof(case2),
                    "avc: denied { binder_transfer } for pid=1234 comm=\"some_app\" "
                    "scontext=u:r:priv_app:s0 tcontext=u:r:magisk:s0 tclass=binder permissive=0");
    patched = try_patch_one(case2, &len, (int)sizeof(case2) - 1, PATTERN_MAGISK, (int)PATTERN_MAGISK_LEN);
    if (!patched || !strnstr(case2, CTX_REPLACEMENT, len)) {
        pr_warn("auditpatch-kpm: [selftest] case 2 (magisk denial) FAILED\n");
        ok = 0;
    }

    len = snprintf(case3, sizeof(case3),
                    "avc: denied { open } for path=\"tcontext=u:r:su:s0\" dev=\"sda1\" "
                    "scontext=u:r:priv_app:s0 tcontext=u:r:sdcardfs:s0 tclass=file permissive=0");
    patched = try_patch_one(case3, &len, (int)sizeof(case3) - 1, PATTERN_SU, (int)PATTERN_SU_LEN);
    if (patched) {
        pr_warn("auditpatch-kpm: [selftest] case 3 (anti-spoof) FAILED -- patched something it should not have\n");
        ok = 0;
    }

    {
        struct extra_domain d;
        char case4[256];

        memcpy(d.type, "ksu", 4);
        d.raw_ctx_len = snprintf(d.raw_ctx, sizeof(d.raw_ctx), "u:r:%s:s0", d.type);
        d.pattern_len = snprintf(d.pattern, sizeof(d.pattern), "tcontext=u:r:%s:s0", d.type);

        len = snprintf(case4, sizeof(case4),
                        "avc: denied { binder_transfer } for pid=1234 comm=\"some_app\" "
                        "scontext=u:r:priv_app:s0 tcontext=u:r:ksu:s0 tclass=binder permissive=0");
        patched = try_patch_one(case4, &len, (int)sizeof(case4) - 1, d.pattern, d.pattern_len);
        if (!patched || !strnstr(case4, CTX_REPLACEMENT, len)) {
            pr_warn("auditpatch-kpm: [selftest] case 4 (extra domain 'ksu') FAILED\n");
            ok = 0;
        }
    }

    pr_info("auditpatch-kpm: [selftest] %s\n", ok ? "all cases passed" : "one or more cases FAILED");
    return ok;
}

/*
 * compat_copy_to_user() itself has no truncation-safety: if the caller's
 * out_msg buffer (outlen) is smaller than what we formatted (n+1 bytes
 * including the NUL), copying exactly `outlen` raw bytes can leave the
 * last byte un-terminated -- a real, if minor, footgun for any userspace
 * caller that treats the result as a C string. Centralized here (rather
 * than repeated at each of the three call sites below) so the fix can't
 * accidentally apply to only some of them.
 */
static void copy_status_to_user(char *buf, int buf_cap, int n, char __user *out_msg, int outlen)
{
    int to_copy;

    if (n < 0) n = 0;
    if (n >= buf_cap) n = buf_cap - 1; /* snprintf's own truncation of buf itself */

    if (n < outlen) {
        to_copy = n + 1; /* string + NUL, fits as-is */
    } else {
        to_copy = outlen;
        if (outlen > 0) buf[outlen - 1] = '\0'; /* force-terminate within what we're actually sending */
    }
    compat_copy_to_user(out_msg, buf, to_copy);
}

static long auditpatch_control0(const char *ctl_args, char *__user out_msg, int outlen)
{
    /* 512, not 320: with p1c's three counters added, a worst-case status
     * line (every counter at max digit width) is ~451 bytes -- was
     * already tight at 320 even before p1c (snprintf() itself can't
     * overflow buf regardless, and copy_status_to_user() clamps `n`
     * defensively either way, so this was never a memory-safety issue --
     * see the comment there), but sized here to comfortably fit the real
     * worst case rather than relying on that clamp to silently drop
     * fields from the diagnostic output. */
    char buf[512];
    int n;

    if (outlen <= 0) return -EINVAL;

    if (ctl_args && !strcmp(ctl_args, "selftest")) {
        int ok = run_selftest();
        n = snprintf(buf, sizeof(buf), "selftest: %s\n", ok ? "PASS" : "FAIL (see dmesg for which case)");
        copy_status_to_user(buf, (int)sizeof(buf), n, out_msg, outlen);
        return ok ? 0 : -EIO;
    }

    if (ctl_args && !strcmp(ctl_args, "domains")) {
        int i, off = 0;
        off += snprintf(buf + off, sizeof(buf) - off, "builtin: su, magisk\nextra (%d/%d):", g_extra_domain_count,
                         MAX_EXTRA_DOMAINS);
        for (i = 0; i < g_extra_domain_count && off < (int)sizeof(buf); i++) {
            off += snprintf(buf + off, sizeof(buf) - off, " %s", g_extra_domains[i].type);
        }
        /* snprintf() returns the length it *would* have written, which can
         * exceed the remaining space on truncation -- so `off` itself is not
         * trustworthy as a byte offset once truncation has happened. Clamp
         * before the final snprintf below: today's MAX_EXTRA_DOMAINS(4) *
         * (MAX_EXTRA_DOMAIN_TYPE_LEN(31)+1) keeps the real total at 161
         * bytes against a 320-byte buf, so this branch isn't reachable yet
         * -- but a future bump to either constant without revisiting this
         * function would otherwise turn `buf + off` into an out-of-bounds
         * pointer and `sizeof(buf) - off` into a huge, size_t-underflowed
         * length. Same "don't just trust it holds" standard as
         * AUDITPATCH_TRUST_BUT_VERIFY in after_sid_to_context() below. */
        if (off > (int)sizeof(buf)) off = (int)sizeof(buf);
        n = snprintf(buf + off, sizeof(buf) - off, "\n") + off;
        copy_status_to_user(buf, (int)sizeof(buf), n, out_msg, outlen);
        return 0;
    }

    if (ctl_args && !strcmp(ctl_args, "reset")) {
        atomic64_set(&g_p1_scanned, 0);
        atomic64_set(&g_p1_patched, 0);
        atomic64_set(&g_p1_errors, 0);
        atomic64_set(&g_p1b_scanned, 0);
        atomic64_set(&g_p1b_patched, 0);
        atomic64_set(&g_p1b_errors, 0);
        atomic64_set(&g_p1c_scanned, 0);
        atomic64_set(&g_p1c_patched, 0);
        atomic64_set(&g_p1c_errors, 0);
        atomic64_set(&g_p2_patched, 0);
        atomic64_set(&g_p2_errors, 0);
        n = snprintf(buf, sizeof(buf), "counters reset\n");
        copy_status_to_user(buf, (int)sizeof(buf), n, out_msg, outlen);
        return 0;
    }

    n = snprintf(buf, sizeof(buf),
                 "p1_hooked=%d p1b_hooked=%d p1c_hooked=%d target=%s extra_domains=%d/%d p1_scanned=%lld "
                 "p1_patched=%lld p1_errors=%lld p1b_scanned=%lld p1b_patched=%lld p1b_errors=%lld "
                 "p1c_scanned=%lld p1c_patched=%lld p1c_errors=%lld | "
                 "p2_hooked=%d p2_has_state=%d p2_patched=%lld p2_errors=%lld\n",
                 g_p1_hooked, g_p1b_hooked, g_p1c_hooked, g_target_comm, g_extra_domain_count, MAX_EXTRA_DOMAINS,
                 (long long)atomic64_read(&g_p1_scanned), (long long)atomic64_read(&g_p1_patched),
                 (long long)atomic64_read(&g_p1_errors), (long long)atomic64_read(&g_p1b_scanned),
                 (long long)atomic64_read(&g_p1b_patched), (long long)atomic64_read(&g_p1b_errors),
                 (long long)atomic64_read(&g_p1c_scanned), (long long)atomic64_read(&g_p1c_patched),
                 (long long)atomic64_read(&g_p1c_errors), g_p2_hooked, g_p2_has_state_arg,
                 (long long)atomic64_read(&g_p2_patched), (long long)atomic64_read(&g_p2_errors));

    copy_status_to_user(buf, (int)sizeof(buf), n, out_msg, outlen);
    return 0;
}

static long auditpatch_exit(void *__user reserved)
{
    if (g_p1_hooked) {
        unhook_syscalln(__NR_recvfrom, NULL, after_recvfrom);
        g_p1_hooked = 0;
    }
    if (g_p1b_hooked) {
        unhook_syscalln(__NR_read, NULL, after_read);
        g_p1b_hooked = 0;
    }
    if (g_p1c_hooked) {
        unhook_syscalln(__NR_syslog, NULL, after_syslog);
        g_p1c_hooked = 0;
    }
    if (g_p2_hooked && g_p2_addr) {
        unhook((void *)g_p2_addr);
        g_p2_hooked = 0;
    }
    pr_info("auditpatch-kpm: exit, p1_patched=%lld p1b_patched=%lld p1c_patched=%lld p2_patched=%lld\n",
            (long long)atomic64_read(&g_p1_patched), (long long)atomic64_read(&g_p1b_patched),
            (long long)atomic64_read(&g_p1c_patched), (long long)atomic64_read(&g_p2_patched));
    return 0;
}

KPM_INIT(auditpatch_init);
KPM_CTL0(auditpatch_control0);
KPM_EXIT(auditpatch_exit);
