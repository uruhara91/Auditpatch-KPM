/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * patch_logic.h -- pure, kernel-independent string/ABI-table logic for
 * auditpatch-kpm.
 *
 * Included by BOTH auditpatch.c (the real KPM, freestanding kernel build)
 * and tests/test_logic.c (a plain host userspace build, see that file).
 * Nothing in here touches task_struct, hooks, syscalls, or any KernelPatch
 * API -- only string/memory operations, integer comparisons, and a couple
 * of small fixed-size structs. That's what makes it possible to unit-test
 * this file with plain host gcc + ASan/UBSan, no cross toolchain and no
 * device required, while still testing the *literal bytes that ship in the
 * .kpm* rather than a hand-maintained lookalike that can silently drift
 * out of sync with the real logic.
 *
 * Define AUDITPATCH_HOST_TEST before including this file to get the host
 * build path (plain libc headers, a local strnstr() since glibc doesn't
 * portably provide one). Without it, this assumes it's being included from
 * inside auditpatch.c after that file's own kernel headers, so linux/kernel.h's
 * VERSION() macro and linux/string.h's strnstr()/memcpy()/memmove()/strcmp()
 * are already visible.
 */
#ifndef AUDITPATCH_PATCH_LOGIC_H
#define AUDITPATCH_PATCH_LOGIC_H

#ifdef AUDITPATCH_HOST_TEST
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#else
#include <linux/kernel.h>
#include <linux/string.h>
#endif

/* Same definition as kernel/include/common.h / preset.h in KernelPatch
 * (verified against the real header). Guarded so this is a no-op, not a
 * conflicting redefinition, when those headers already provided it -- and
 * harmless even if it *were* re-evaluated, since GCC only warns on a
 * redefinition with a genuinely different token sequence, not an identical
 * one. */
#ifndef VERSION
#define VERSION(major, minor, patch) (((major) << 16) + ((minor) << 8) + (patch))
#endif

/* ------------------------------------------------------------------------
 * Host-only shims
 * ------------------------------------------------------------------------ */
#ifdef AUDITPATCH_HOST_TEST
/* glibc does not portably export strnstr() (it's a BSD/kernel extension);
 * the kernel side gets a real one via linux/string.h, backed by
 * KernelPatch's kfunc plumbing. Same semantics here: search at most `slen`
 * bytes of `s` for the NUL-terminated `find`. */
static inline char *strnstr(const char *s, const char *find, size_t slen)
{
    size_t find_len = strlen(find);
    if (find_len == 0) return (char *)s;
    while (slen >= find_len) {
        if (memcmp(s, find, find_len) == 0) return (char *)s;
        s++;
        slen--;
    }
    return NULL;
}
#endif

/* ------------------------------------------------------------------------
 * Matched contexts and their replacement
 * ------------------------------------------------------------------------ */

#define CTX_SU "u:r:su:s0"
#define CTX_MAGISK "u:r:magisk:s0"
#define CTX_REPLACEMENT "u:r:priv_app:s0:c512,c768"
#define CTX_REPLACEMENT_LEN (sizeof(CTX_REPLACEMENT) - 1)

/* PART 2 can only overwrite the existing context buffer in place (see the
 * long comment in auditpatch.c for why), so this must never be longer than
 * the shortest *builtin* pattern it might replace (CTX_SU, 9 bytes).
 * Extra domains configured via KPM args are validated at parse time
 * (MIN_EXTRA_DOMAIN_TYPE_LEN below) to never produce anything shorter than
 * that either -- see extra_domain_type_len_ok(). */
#define CTX_REPLACEMENT_SHORT "u:r:na:s0"
#define CTX_REPLACEMENT_SHORT_LEN (sizeof(CTX_REPLACEMENT_SHORT) - 1)

static const char PATTERN_SU[] = "tcontext=" CTX_SU;
static const char PATTERN_MAGISK[] = "tcontext=" CTX_MAGISK;
static const char PATTERN_REPLACEMENT[] = "tcontext=" CTX_REPLACEMENT;

#define PATTERN_SU_LEN (sizeof(PATTERN_SU) - 1)
#define PATTERN_MAGISK_LEN (sizeof(PATTERN_MAGISK) - 1)
#define PATTERN_REPLACEMENT_LEN (sizeof(PATTERN_REPLACEMENT) - 1)

_Static_assert(CTX_REPLACEMENT_SHORT_LEN <= (sizeof(CTX_SU) - 1),
                "CTX_REPLACEMENT_SHORT must never be longer than CTX_SU");

/* ------------------------------------------------------------------------
 * Extra (user-configured) domains -- see auditpatch.c's parse_args()
 * ------------------------------------------------------------------------ */

/* A configured extra domain is a bare SELinux *type* name (e.g. "ksu");
 * this module builds "u:r:<type>:s0" from it, same :s0-sensitivity/no-MLS
 * convention as CTX_SU/CTX_MAGISK. A different sensitivity or categories
 * won't match (documented limitation, not a bug).
 *
 * MIN_EXTRA_DOMAIN_TYPE_LEN=2 is load-bearing, not cosmetic: a raw context
 * "u:r:<type>:s0" is (4 + len(type) + 3) bytes, and PART 2 overwrites that
 * many bytes in place with CTX_REPLACEMENT_SHORT (9 bytes). A 1-character
 * type would produce an 8-byte context -- shorter than the replacement --
 * and overflow the kstrdup()'d buffer security_sid_to_context() handed
 * back. len>=2 keeps every extra-domain context >= 9 bytes. Re-checked
 * defensively at the write site in after_sid_to_context() (see
 * AUDITPATCH_TRUST_BUT_VERIFY there) rather than trusted from here alone. */
#define MIN_EXTRA_DOMAIN_TYPE_LEN 2
#define MAX_EXTRA_DOMAIN_TYPE_LEN 31 /* leaves room for the NUL in a 32-byte field */

static inline int extra_domain_type_len_ok(size_t len)
{
    return len >= MIN_EXTRA_DOMAIN_TYPE_LEN && len <= MAX_EXTRA_DOMAIN_TYPE_LEN;
}

#define MAX_EXTRA_DOMAINS 4
#define EXTRA_DOMAIN_TYPE_BUF (MAX_EXTRA_DOMAIN_TYPE_LEN + 1)          /* "ksu\0" */
#define EXTRA_DOMAIN_CTX_BUF (4 + MAX_EXTRA_DOMAIN_TYPE_LEN + 3 + 1)   /* "u:r:" + type + ":s0\0" */
#define EXTRA_DOMAIN_PATTERN_BUF (9 + EXTRA_DOMAIN_CTX_BUF)            /* "tcontext=" + ctx (generous) */

struct extra_domain {
    char type[EXTRA_DOMAIN_TYPE_BUF];       /* bare type, e.g. "ksu" */
    char raw_ctx[EXTRA_DOMAIN_CTX_BUF];     /* "u:r:ksu:s0", precomputed once at parse time */
    char pattern[EXTRA_DOMAIN_PATTERN_BUF]; /* "tcontext=u:r:ksu:s0", precomputed once at parse time */
    int raw_ctx_len;
    int pattern_len;
};

/* ------------------------------------------------------------------------
 * PART 1 / PART 1b: buffer patch primitive
 * ------------------------------------------------------------------------ */

/*
 * Mirrors the original module's has_quote_after(): if a `"` appears
 * anywhere after the matched pattern (within the bytes we actually have),
 * treat the match as unsafe/spoofable (e.g. embedded inside a quoted
 * name="..." field) and refuse to touch it.
 */
static inline int has_quote_after(const char *buf, int total_len, int from)
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
 *
 * Memory-safety note (also see auditpatch.c's after_recvfrom/after_read):
 * this function's own `new_len > cap` check is what actually bounds every
 * write it performs -- as long as callers pass a `cap` that never exceeds
 * the real destination buffer's size, this cannot overflow regardless of
 * which pattern (builtin or extra-domain, any length) is passed in.
 */
static inline int try_patch_one(char *buf, int *len, int cap, const char *pattern, int pattern_len)
{
    char *pos;
    int match_off, tail_len, new_len;

    if (*len < pattern_len) return 0;

    pos = strnstr(buf, pattern, (size_t)*len);
    if (!pos) return 0;

    match_off = (int)(pos - buf);

    if (has_quote_after(buf, *len, match_off + pattern_len)) return 0;

    tail_len = *len - (match_off + pattern_len);
    new_len = match_off + (int)PATTERN_REPLACEMENT_LEN + tail_len;

    if (new_len > cap) return 0;

    if (tail_len > 0) {
        memmove(buf + match_off + PATTERN_REPLACEMENT_LEN, buf + match_off + pattern_len, (size_t)tail_len);
    }
    memcpy(buf + match_off, PATTERN_REPLACEMENT, PATTERN_REPLACEMENT_LEN);

    *len = new_len;
    return 1;
}

/* ------------------------------------------------------------------------
 * PART 2: security_sid_to_context() ABI table
 * ------------------------------------------------------------------------ */

struct sid2ctx_abi {
    uint32_t kver_min; /* inclusive */
    uint32_t kver_max; /* exclusive */
    int has_state_arg; /* security_sid_to_context(state, sid, ...) vs (sid, ...) */
    const char *note;
};

/*
 * Every row here was checked against real kernel source (both mainline
 * torvalds/linux release tags and the actual Android common-kernel
 * branches) before being added -- see the PART 2 comment in auditpatch.c
 * for exactly which ones. Do not add a row "by pattern-matching" the ones
 * around it; verify it the same way first.
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

/* Returns 1 and fills *out if running_kver matches a verified table entry,
 * else 0. Takes the version as a parameter (rather than reading the global
 * `kver` directly) purely so this is trivially unit-testable/reviewable in
 * isolation. */
static inline int sid2ctx_abi_lookup(uint32_t running_kver, const struct sid2ctx_abi **out)
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

#endif /* AUDITPATCH_PATCH_LOGIC_H */
