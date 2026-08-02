# AuditPatch (KPM)

A **KernelPatch Module (KPM)** port of [aviraxp/ZN-AuditPatch](https://github.com/aviraxp/ZN-AuditPatch),
a Zygisk Next module. Same user-visible effect, different (kernel-space)
mechanism. See [`android-review.googlesource.com/c/platform/system/logging/+/3725346`](https://android-review.googlesource.com/c/platform/system/logging/+/3725346)
for the upstream background this module works around.

**What it does:** when logd receives an SELinux AVC "denied" audit line whose
`tcontext=` field names the `su` or `magisk` domain, it is rewritten to look
like an ordinary `priv_app` context before it becomes visible in logcat /
`dmesg`-adjacent audit logs, e.g.:

```
...tcontext=u:r:su:s0 tclass=binder...           ->  (unpatched)
...tcontext=u:r:priv_app:s0:c512,c768 tclass=binder...  (patched)
```

Only `tcontext=` is ever touched, never `scontext=` — identical scope to the
original module.

This requires **[APatch](https://github.com/bmax121/APatch)** (KernelPatch).
It does **not** work with plain Magisk or KernelSU, because those don't run a
kernel patched by KernelPatch, which is what makes KPMs possible at all.

---

## Why a straight "port" isn't a straight recompile

The original module is a shared library injected by Zygisk Next into the
`logd` process, where it PLT-hooks `vasprintf()`. A KPM runs in **kernel
space** and is not injected into any particular process, so there is no
`vasprintf()` call inside our address space to intercept — the whole
interception strategy has to move.

Tracing the actual data path in AOSP
(`system/logging/logd/libaudit.cpp` + `LogAudit.cpp`) shows:

1. `logd` opens a raw netlink socket:
   `socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_AUDIT)`.
2. Its `LogAudit` thread receives every raw kernel AVC denial line —
   **already containing the literal text** `tcontext=u:r:su:s0`, verbatim,
   exactly as the kernel's SELinux AVC audit code produced it — with:
   `recvfrom(fd, rep, sizeof(*rep), flags, &nladdr, &nladdrlen)`.
3. *Only afterwards* does logd's own `vasprintf()` build the final logcat
   line out of that already-received text (this is the call the original
   module hooks).

So the exact same string exists one syscall earlier, as the data
`recvfrom()` copies back into logd's own buffer. This KPM hooks `recvfrom`
system-wide with KernelPatch's syscall-hook API and, purely in the
*after*-hook (i.e. after the real syscall already ran):

- Bails out immediately unless the calling process' `comm` is `logd` (or a
  custom name passed as KPM load args — see below).
- Bails out unless the received bytes actually contain one of the two
  target `tcontext=` patterns.
- Rewrites the pattern into a kernel-side scratch buffer (with the same
  "don't touch it if a `"` appears afterwards" anti-spoof heuristic as the
  original — see `has_quote_after()`), copies the result back over the
  caller's own buffer with `compat_copy_to_user()`, and patches the
  syscall's return value (byte count) to match the new length.

Net effect on `logd` is identical to the original module, with two
practical improvements that fall out of doing this in the kernel instead of
via userspace injection:

- **No `logd` restart needed.** The original module needed a
  `resetprop -w sys.boot_completed 0; setprop ctl.restart logd` hack in
  `service.sh` because Zygisk Next could not inject into `logd` early
  enough on its own. Since this hook is installed system-wide in the
  kernel and filters by process name at call time, an *already-running*
  `logd` is covered too, the moment the KPM loads.
- **Effectively zero overhead outside its target.** The hook is a no-op for
  every process other than the configured target, and a no-op for every
  `recvfrom()` call from that process that doesn't contain the target
  substrings — which, in `logd`'s case, is also true by construction: its
  much hotter `/dev/socket/logdw` traffic goes through `recvmsg()`, not
  `recvfrom()`, so it's never even inspected.

---

## Going deeper: the `security_sid_to_context` hook (PART 2)

The recvfrom/logd hook above only ever rewrites the `tcontext=` field inside
one specific log line. It says nothing about `scontext=`, and nothing about
any *other* consumer of a SID→string context lookup — `/proc/[pid]/attr/current`
(what `id -Z`, `getcon()`-style APIs, and some root-detection SDKs read
directly), or anywhere else in the kernel that turns su/magisk's SID into a
display string.

All of those ultimately go through one real kernel function:
`security_sid_to_context()` in `security/selinux/ss/services.c`. This module
optionally hooks *that* directly, system-wide, which is strictly broader
than upstream ZN-AuditPatch ever was — it can no longer distinguish
"su/magisk is the target of a denial" from "su/magisk is the source", or
even from plain context introspection with no denial involved at all. It
patches *every* successful resolution of the su/magisk domain SID to a
string.

**This is intentionally conservative about which kernels it runs on.** Two
things make this hook meaningfully riskier than the recvfrom one, and both
are handled explicitly rather than glossed over:

1. **ABI shape.** `security_sid_to_context()`'s C signature has changed
   twice in kernel history:
   ```
   < 4.19       : security_sid_to_context(u32 sid, char **scontext, u32 *scontext_len)
   4.19 – 6.3   : security_sid_to_context(struct selinux_state *state, u32 sid, char **scontext, u32 *scontext_len)
   6.4 +        : back to the 3-argument form
   ```
2. **Object lifetime.** The returned `*scontext` buffer is a real
   `kmalloc()`'d kernel object that the *caller* later `kfree()`s (verified
   directly against `avc_audit_post_callback()` and `proc_pid_attr_read()`
   in real kernel source). Swapping in a buffer from a different allocator
   would eventually hand the kernel's real `kfree()` a pointer it never
   allocated — silent heap corruption. So the replacement is allocated with
   the kernel's *real* `kmalloc()`, which needs a `GFP_ATOMIC` flag (some
   callers run under `rcu_read_lock()`, non-sleepable) — and that flag's
   *numeric value* is not stable ABI and has changed across kernel history
   (confirmed from source: `___GFP_DIRECT_RECLAIM` alone moved from
   `0x200000` on 4.19 to `0x400` on 5.15 — a different bit position).

So rather than guess a single value and hope, this module ships a short
table of `(kernel version range → ABI shape, GFP_ATOMIC value)`, with every
row individually checked against real kernel source — both mainline
`torvalds/linux` tags and the actual Android common-kernel branches:

| kernel version | `security_sid_to_context` shape | `GFP_ATOMIC` | verified against |
|---|---|---|---|
| `< 4.19` | 3-arg (no state) | *not verified* — hook stays off | mainline v4.4, v4.9 |
| `4.19 – 5.0` | 4-arg (`state` first) | `0x00480020` | `android-4.19-stable` (covers e.g. **4.19.191**), mainline v4.19 |
| `5.0 – 6.4` | 4-arg (`state` first) | `0x00000A20` | `android-5.4-stable`, `android12-5.10`, `android13-5.15`, `android14-6.1`, mainline v5.4/v5.10/v5.15/v6.1 |
| `6.4 +` | 3-arg (no state) | `0x00000820` | `android15-6.6`, mainline v6.4/v6.6/v6.12 |

On boot, the module checks the running kernel version (KernelPatch's `kver`)
against this table. **A match → the deep hook installs. No match → it is
left disabled, on purpose, and only the recvfrom/logd hook (PART 1) is
active.** Extending the table to a kernel version not listed here means
checking that version's real `security.h` and `gfp.h`/`gfp_types.h` first,
the same way this table was built — not adding a plausible-looking row.

If you're on a kernel this table doesn't cover and want it added, the most
useful thing you can hand over is the exact kernel version/branch (e.g.
`android13-5.15` or a specific commit/tag), so the same source-level
verification can be done for it specifically instead of guessed generically.

**What this module deliberately does *not* do:** projects like
[Admirepowered/selinux_hook](https://github.com/Admirepowered/selinux_hook)
go further still, by constructing an entirely separate, synthetic "clean"
copy of the live SELinux policy database and redirecting policy queries
(`/sys/fs/selinux/access`, `/sys/fs/selinux/context`) to it. Doing that
requires hand-defining SELinux's *private*, unexported internal structs
(`struct policydb`, `context`, `ebitmap`, `hashtab`, ...), whose layout
differs across kernel versions *and* vendor forks (Qualcomm/MediaTek/Samsung
kernels routinely add their own fields). Getting a single field offset
wrong there means treating a chunk of kernel memory as the wrong struct —
which is a real kernel-panic/bootloop risk, not a hypothetical one, and one
this project isn't willing to ship without the exact target kernel source
to verify every struct against.

---

## Layout

```
kpm/
  auditpatch.c     - the KPM itself (this is the entire deliverable)
  Makefile         - builds auditpatch.kpm with the aarch64-none-elf toolchain
.github/workflows/build.yml
```

That's it. No Magisk/KernelSU-style `module.prop`/`customize.sh` wrapper —
a KPM isn't a root module you "install"; it's a kernel object you Embed or
Load through APatch Manager directly (see **Installing** below), same as
[bmax121/KernelPatch](https://github.com/bmax121/KernelPatch)'s own `kpms/`
demos and [Admirepowered/selinux_hook](https://github.com/Admirepowered/selinux_hook).

## Building

You need the bare-metal `aarch64-none-elf-` cross toolchain (the same one
KernelPatch itself documents for building KPMs — see
[`doc/en/build.md`](https://github.com/bmax121/KernelPatch/blob/main/doc/en/build.md)),
and a checkout of [bmax121/KernelPatch](https://github.com/bmax121/KernelPatch)
for its header-only `kernel/` tree (no build of KernelPatch itself is
needed, just the headers — this KPM links against nothing else).

```bash
# 1. Get the toolchain (Linux x86_64 host shown; macOS/Windows builds also
#    exist, see https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)
curl -fL -o toolchain.tar.xz \
  https://developer.arm.com/-/media/Files/downloads/gnu/14.2.rel1/binrel/arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf.tar.xz
mkdir toolchain && tar -xJf toolchain.tar.xz -C toolchain --strip-components=1
export PATH="$PWD/toolchain/bin:$PATH"

# 2. Get KernelPatch's headers
git clone --depth 1 https://github.com/bmax121/KernelPatch.git

# 3. Build
export TARGET_COMPILE=aarch64-none-elf-
make -C kpm KP_DIR="$PWD/KernelPatch"
# -> kpm/auditpatch.kpm
```

The `.github/workflows/build.yml` action does exactly this on every push
and pull request (plus a fast host-`gcc` `-fsyntax-only` lint pass against
the real KernelPatch headers), and attaches `auditpatch.kpm` to tagged
releases (`vX.Y.Z`).

## Installing

`auditpatch.kpm` is the only artifact — take the file from a release (or
build it yourself) and, in **APatch Manager → KPM**:

- **Embed** (recommended — persists across reboots): merges it into
  `boot.img` at patch time, so it loads pre-kernel-init on every boot. This
  is the only method APatch currently guarantees persists.
- **Load** (manual, until next reboot): good for testing; you'll need to
  repeat this after every reboot.

There is currently no third, "install it like a root module and it
auto-loads forever" option — as of this writing APatch's own docs state
that KPM auto-load-on-install ("Install") is
[not yet implemented](https://apatch.dev/kpm-usage-guide.html). Embed and
Load above are the two methods APatch actually guarantees.

## Verifying it's working

```bash
dmesg | grep zn-auditpatch-kpm
# zn-auditpatch-kpm: init, kver=0x41300, event=..., args=...
# zn-auditpatch-kpm: [p1] recvfrom hook installed
# zn-auditpatch-kpm: [p2] deep hook installed on security_sid_to_context (abi=4.19.x, has_state=1)
# zn-auditpatch-kpm: [p1] patched avc audit tcontext in 'logd' (total: 1)   <- appears once something is actually caught
# zn-auditpatch-kpm: [p2] patched sid->context result (total: 1)
```

Or query the module's own status/counters directly (works from any APatch
module script or an adb shell with the SuperKey):

```bash
kpatch "$SUPERKEY" kpm ctl0 zn-auditpatch-kpm status
# p1_hooked=1 target=logd p1_scanned=<n> p1_patched=<n> p1_errors=<n> | p2_hooked=1 p2_has_state=1 p2_gfp_atomic=0x480020 p2_patched=<n> p2_errors=<n>
kpatch "$SUPERKEY" kpm ctl0 zn-auditpatch-kpm reset   # zero the counters
```

`p2_hooked=0` with no error logged simply means the running kernel didn't
match a verified table entry above — PART 1 is still fully active in that
case.

## Configuring the target process

By default the hook only ever looks at `recvfrom()` calls made by a process
named `logd`. You can target a different process (e.g. on a ROM that
renames or wraps it) by passing it as the KPM load args:

```bash
kpatch "$SUPERKEY" kpm load /path/to/auditpatch.kpm my_logd_wrapper
```

## Limitations

- **arm64 only**, same as KernelPatch/APatch itself.
- PART 1: only `recvfrom()` is hooked, matching AOSP's actual
  `libaudit.cpp` implementation. A ROM/vendor fork that reads the audit
  netlink socket via `recvmsg()`/`read()` instead would not be covered;
  extending this would need raw (non-string) `copy_from_user`, which
  KernelPatch's public KPM API doesn't currently expose (only
  NUL-terminated-string-oriented helpers are), so it's left out rather
  than half-implemented.
- PART 1 only rewrites `tcontext=`, never `scontext=` — same scope as the
  original module. PART 2 (if active on your kernel) covers both, since it
  operates below that distinction.
- PART 2 only installs on kernel versions with a verified table entry (see
  above). On anything else it silently stays off; PART 1 is unaffected
  either way.
- Neither part touches actual SELinux **enforcement** (`avc_has_perm`,
  which operates on raw SIDs against the loaded policy, not on display
  strings) — both parts only affect how su/magisk's SID is *displayed* to
  audit logs / context-introspection callers. This is not a security
  hardening tool; it does not change what the device's access-control
  policy actually allows or denies.

## Credits / license

- Original idea, module, and the exact string-replacement logic:
  [aviraxp/ZN-AuditPatch](https://github.com/aviraxp/ZN-AuditPatch).
- KPM/KernelPatch APIs used throughout: [bmax121/KernelPatch](https://github.com/bmax121/KernelPatch).
- GPL-2.0-or-later, see [`LICENSE`](LICENSE) — same as KernelPatch itself,
  whose headers/exported kernel symbols this module is built against.
