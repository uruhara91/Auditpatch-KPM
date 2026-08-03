#!/bin/sh
# Verify a built .kpm is actually loadable by KernelPatch, not just "an ELF
# file that compiled". Checks the same things kernel/patch/module/module.c
# checks before it will accept a module, plus the relocation-type
# regression test for the real bug found (and fixed) in v2.1.0/v2.1.1: see
# README.md's Troubleshooting section for the full story of how a KPM can
# embed into boot.img without error and still silently fail to load at
# boot.
#
# Usage: verify-kpm.sh <readelf-binary> <path-to.kpm>
# Exit 0 = all checks pass. Exit 1 = at least one check failed (message on
# stderr explains which, and why it matters).

set -eu

READELF="$1"
KPM="$2"

# 1. Required sections must exist and be ALLOC-flagged, matching exactly
#    what find_sec() in module.c requires. Missing/misflagged sections
#    here are rejected at boot with "no .kpm.init or .kpm.exit section" /
#    "no .kpm.info section", even though embedding into boot.img itself
#    never validates this.
for sec in .kpm.info .kpm.init .kpm.exit; do
    line=$("$READELF" -S "$KPM" | grep -A1 " $sec *PROGBITS" || true)
    if [ -z "$line" ]; then
        echo "FAIL: section $sec missing entirely" >&2
        exit 1
    fi
    if ! echo "$line" | tail -1 | grep -qE '(^| )A( |$)|WA'; then
        echo "FAIL: section $sec is missing the ALLOC flag: $line" >&2
        exit 1
    fi
done
echo "OK: .kpm.info/.kpm.init/.kpm.exit present and ALLOC-flagged"

# 2. A symbol table must be present -- module.c refuses to load a stripped
#    module ("module has no symbols (stripped?)").
if ! "$READELF" -S "$KPM" | grep -qi symtab; then
    echo "FAIL: no .symtab section (module.c refuses stripped KPMs)" >&2
    exit 1
fi
echo "OK: .symtab present"

# 3. Every relocation type used must be one relo.c actually implements.
#    This is the regression test for the real bug found in v2.1.0: without
#    -fno-pic -fno-pie, a real aarch64 GCC emits R_AARCH64_ADR_GOT_PAGE /
#    R_AARCH64_LD64_GOT_LO12_NC for nearly every external/kfunc call, which
#    KernelPatch's relocator does not handle and silently rejects the
#    module at boot.
supported='R_AARCH64_NONE|R_AARCH64_ABS64|R_AARCH64_ABS32|R_AARCH64_ABS16|R_AARCH64_PREL64|R_AARCH64_PREL32|R_AARCH64_PREL16|R_AARCH64_MOVW_UABS_G0|R_AARCH64_MOVW_UABS_G1|R_AARCH64_MOVW_UABS_G2|R_AARCH64_MOVW_UABS_G3|R_AARCH64_MOVW_SABS_G0|R_AARCH64_MOVW_SABS_G1|R_AARCH64_MOVW_SABS_G2|R_AARCH64_MOVW_PREL_G0|R_AARCH64_MOVW_PREL_G1|R_AARCH64_MOVW_PREL_G2|R_AARCH64_MOVW_PREL_G3|R_AARCH64_LD_PREL_LO19|R_AARCH64_ADR_PREL_LO21|R_AARCH64_ADR_PREL_PG_HI21|R_AARCH64_ADD_ABS_LO12_NC|R_AARCH64_LDST8_ABS_LO12_NC|R_AARCH64_LDST16_ABS_LO12_NC|R_AARCH64_LDST32_ABS_LO12_NC|R_AARCH64_LDST64_ABS_LO12_NC|R_AARCH64_LDST128_ABS_LO12_NC|R_AARCH64_TSTBR14|R_AARCH64_CONDBR19|R_AARCH64_JUMP26|R_AARCH64_CALL26'
used=$("$READELF" -r -W "$KPM" | grep -oE 'R_AARCH64_[A-Z0-9_]+' | sort -u)
bad=""
for t in $used; do
    if ! echo "$t" | grep -qE "^($supported)\$"; then
        bad="$bad $t"
    fi
done
if [ -n "$bad" ]; then
    echo "FAIL: relocation type(s) not handled by KernelPatch's relo.c:$bad" >&2
    echo "This will build and 'Embed' without error, but the KPM will silently" >&2
    echo "fail to load at boot. See README.md's Troubleshooting section." >&2
    exit 1
fi
echo "OK: all relocation types are ones relo.c handles ($(echo "$used" | wc -w) types used)"
