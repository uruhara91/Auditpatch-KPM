/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Host-side unit tests for ../patch_logic.h -- the exact header the real
 * .kpm is built from. No kernel headers, no cross toolchain, no device.
 *
 * Build & run:
 *   cc -Wall -Wextra -O2 -fsanitize=address,undefined -o test_logic test_logic.c && ./test_logic
 *
 * Covers: the same 4 cases as on-device run_selftest() in auditpatch.c;
 * buffer boundary cases it doesn't reach (exact-cap fit, cap-too-small
 * refusal, match at start/end, two occurrences, buffer shorter than
 * pattern, trailing quote); extra_domain_type_len_ok()'s boundary; and
 * SID2CTX_ABI_TABLE (no gaps/overlaps, real Android kernel versions match
 * DEBUGGING.md's provenance notes).
 */
#define AUDITPATCH_HOST_TEST
#include "../patch_logic.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;
#define CHECK(name, cond)                                          \
    do {                                                           \
        if (cond) {                                                \
            g_pass++;                                              \
        } else {                                                   \
            g_fail++;                                              \
            printf("FAIL: %s (%s:%d)\n", name, __FILE__, __LINE__); \
        }                                                           \
    } while (0)

static void test_try_patch_one(void)
{
    char buf[512];
    int len, cap, ok;

    /* --- mirrors run_selftest() cases 1-3 in auditpatch.c --- */
    len = snprintf(buf, sizeof(buf),
                    "avc: denied { binder_transfer } for pid=1234 comm=\"some_app\" "
                    "scontext=u:r:priv_app:s0 tcontext=u:r:su:s0 tclass=binder permissive=0");
    ok = try_patch_one(buf, &len, (int)sizeof(buf), PATTERN_SU, (int)PATTERN_SU_LEN);
    CHECK("case1: su denial patches", ok && strstr(buf, CTX_REPLACEMENT) && !strstr(buf, "tcontext=u:r:su:s0"));

    len = snprintf(buf, sizeof(buf),
                    "avc: denied { binder_transfer } for pid=1234 comm=\"some_app\" "
                    "scontext=u:r:priv_app:s0 tcontext=u:r:magisk:s0 tclass=binder permissive=0");
    ok = try_patch_one(buf, &len, (int)sizeof(buf), PATTERN_MAGISK, (int)PATTERN_MAGISK_LEN);
    CHECK("case2: magisk denial patches", ok && strstr(buf, CTX_REPLACEMENT));

    len = snprintf(buf, sizeof(buf),
                    "avc: denied { open } for path=\"tcontext=u:r:su:s0\" dev=\"sda1\" "
                    "scontext=u:r:priv_app:s0 tcontext=u:r:sdcardfs:s0 tclass=file permissive=0");
    ok = try_patch_one(buf, &len, (int)sizeof(buf), PATTERN_SU, (int)PATTERN_SU_LEN);
    CHECK("case3: quoted spoof attempt NOT patched", !ok && strstr(buf, "tcontext=u:r:su:s0"));

    /* --- mirrors run_selftest() case 4: synthetic extra domain --- */
    {
        struct extra_domain d;
        memcpy(d.type, "ksu", 4);
        d.raw_ctx_len = snprintf(d.raw_ctx, sizeof(d.raw_ctx), "u:r:%s:s0", d.type);
        d.pattern_len = snprintf(d.pattern, sizeof(d.pattern), "tcontext=u:r:%s:s0", d.type);

        len = snprintf(buf, sizeof(buf),
                        "avc: denied { binder_transfer } for pid=1234 comm=\"some_app\" "
                        "scontext=u:r:priv_app:s0 tcontext=u:r:ksu:s0 tclass=binder permissive=0");
        ok = try_patch_one(buf, &len, (int)sizeof(buf), d.pattern, d.pattern_len);
        CHECK("case4: extra domain 'ksu' denial patches", ok && strstr(buf, CTX_REPLACEMENT));
        CHECK("case4: raw_ctx built correctly", strcmp(d.raw_ctx, "u:r:ksu:s0") == 0);
        CHECK("case4: pattern built correctly", strcmp(d.pattern, "tcontext=u:r:ksu:s0") == 0);
    }

    /* --- boundary/edge cases beyond the on-device selftest --- */

    len = snprintf(buf, sizeof(buf), "x tcontext=u:r:su:s0");
    cap = len - (int)PATTERN_SU_LEN + (int)PATTERN_REPLACEMENT_LEN;
    ok = try_patch_one(buf, &len, cap, PATTERN_SU, (int)PATTERN_SU_LEN);
    CHECK("exact-cap boundary succeeds (new_len == cap)", ok);

    {
        char before[64];
        len = snprintf(buf, sizeof(buf), "x tcontext=u:r:su:s0");
        strcpy(before, buf);
        cap = len - (int)PATTERN_SU_LEN + (int)PATTERN_REPLACEMENT_LEN - 1; /* one short */
        ok = try_patch_one(buf, &len, cap, PATTERN_SU, (int)PATTERN_SU_LEN);
        CHECK("cap-too-small refuses cleanly", !ok);
        CHECK("cap-too-small leaves buffer byte-for-byte untouched", strcmp(buf, before) == 0);
    }

    len = snprintf(buf, sizeof(buf), "prefix tcontext=u:r:magisk:s0");
    ok = try_patch_one(buf, &len, (int)sizeof(buf), PATTERN_MAGISK, (int)PATTERN_MAGISK_LEN);
    CHECK("match at buffer end (tail_len=0) patches", ok && strstr(buf, CTX_REPLACEMENT));

    len = snprintf(buf, sizeof(buf), "tcontext=u:r:su:s0 tclass=binder");
    ok = try_patch_one(buf, &len, (int)sizeof(buf), PATTERN_SU, (int)PATTERN_SU_LEN);
    CHECK("match at buffer start patches, tail preserved",
          ok && strncmp(buf, PATTERN_REPLACEMENT, PATTERN_REPLACEMENT_LEN) == 0 && strstr(buf, "tclass=binder"));

    len = snprintf(buf, sizeof(buf), "tcontext=u:r:su:s0 middle tcontext=u:r:su:s0 end");
    ok = try_patch_one(buf, &len, (int)sizeof(buf), PATTERN_SU, (int)PATTERN_SU_LEN);
    {
        int occurrences = 0;
        char *p = buf;
        while ((p = strstr(p, "tcontext=u:r:su:s0")) != NULL) {
            occurrences++;
            p++;
        }
        CHECK("only first of two occurrences patched per call", ok && occurrences == 1);
    }

    len = 3;
    memcpy(buf, "tco", 3);
    ok = try_patch_one(buf, &len, (int)sizeof(buf), PATTERN_SU, (int)PATTERN_SU_LEN);
    CHECK("shorter-than-pattern buffer safely no-ops", !ok && len == 3);

    {
        char before2[128];
        len = snprintf(buf, sizeof(buf), "tcontext=u:r:su:s0 tclass=binder permissive=0 extra=\"z\"");
        strcpy(before2, buf);
        ok = try_patch_one(buf, &len, (int)sizeof(buf), PATTERN_SU, (int)PATTERN_SU_LEN);
        CHECK("trailing quote anywhere suppresses patch (matches upstream heuristic)",
              !ok && strcmp(buf, before2) == 0);
    }
}

static void test_extra_domain_type_len_ok(void)
{
    /* This boundary is load-bearing for PART 2 memory safety (see the
     * comment above MIN_EXTRA_DOMAIN_TYPE_LEN in patch_logic.h) -- not
     * just input validation, so it gets its own explicit boundary test. */
    CHECK("type len 0 rejected", !extra_domain_type_len_ok(0));
    CHECK("type len 1 rejected (would produce an 8-byte context, shorter than CTX_REPLACEMENT_SHORT)",
          !extra_domain_type_len_ok(1));
    CHECK("type len 2 accepted (produces exactly 9 bytes, matching CTX_REPLACEMENT_SHORT_LEN)",
          extra_domain_type_len_ok(2));
    CHECK("type len MAX accepted", extra_domain_type_len_ok(MAX_EXTRA_DOMAIN_TYPE_LEN));
    CHECK("type len MAX+1 rejected", !extra_domain_type_len_ok(MAX_EXTRA_DOMAIN_TYPE_LEN + 1));

    /* Cross-check against the actual buffer arithmetic: any accepted
     * length must yield a raw_ctx at least CTX_REPLACEMENT_SHORT_LEN
     * bytes long, which is the real invariant that matters. */
    {
        size_t len;
        for (len = 0; len <= MAX_EXTRA_DOMAIN_TYPE_LEN + 1; len++) {
            size_t raw_ctx_len = 4 + len + 3; /* "u:r:" + type + ":s0" */
            if (extra_domain_type_len_ok(len)) {
                CHECK("every accepted type len yields a long-enough raw_ctx", raw_ctx_len >= CTX_REPLACEMENT_SHORT_LEN);
            }
        }
    }
}

static void test_sid2ctx_abi_table(void)
{
    const struct sid2ctx_abi *abi;
    unsigned i;

    for (i = 0; i + 1 < SID2CTX_ABI_TABLE_LEN; i++) {
        CHECK("ABI table rows contiguous, no gap/overlap",
              SID2CTX_ABI_TABLE[i].kver_max == SID2CTX_ABI_TABLE[i + 1].kver_min);
    }

    CHECK("4.19.191 (real device from README) -> has_state=1",
          sid2ctx_abi_lookup(VERSION(4, 19, 191), &abi) && abi->has_state_arg == 1);
    CHECK("5.15.148 (android13-5.15) -> has_state=1",
          sid2ctx_abi_lookup(VERSION(5, 15, 148), &abi) && abi->has_state_arg == 1);
    CHECK("6.1.75 (android14-6.1) -> has_state=1",
          sid2ctx_abi_lookup(VERSION(6, 1, 75), &abi) && abi->has_state_arg == 1);
    CHECK("6.6.30 (android15-6.6) -> has_state=0",
          sid2ctx_abi_lookup(VERSION(6, 6, 30), &abi) && abi->has_state_arg == 0);
    CHECK("6.3.9 (just below 6.4 boundary) -> has_state=1",
          sid2ctx_abi_lookup(VERSION(6, 3, 9), &abi) && abi->has_state_arg == 1);
    CHECK("6.4.0 (exactly at boundary) -> has_state=0",
          sid2ctx_abi_lookup(VERSION(6, 4, 0), &abi) && abi->has_state_arg == 0);
    CHECK("4.14.180 (below table) -> unmatched, deep hook stays off", !sid2ctx_abi_lookup(VERSION(4, 14, 180), &abi));

    CHECK("CTX_REPLACEMENT_SHORT never longer than CTX_SU", CTX_REPLACEMENT_SHORT_LEN <= strlen(CTX_SU));
}

int main(void)
{
    test_try_patch_one();
    test_extra_domain_type_len_ok();
    test_sid2ctx_abi_table();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
