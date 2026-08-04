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

**This is intentionally conservative about which kernels it runs on**,
because of one real risk that's handled explicitly rather than glossed
over: **ABI shape.** `security_sid_to_context()`'s C signature has changed
twice in kernel history:
```
< 4.19       : security_sid_to_context(u32 sid, char **scontext, u32 *scontext_len)
4.19 – 6.3   : security_sid_to_context(struct selinux_state *state, u32 sid, char **scontext, u32 *scontext_len)
6.4 +        : back to the 3-argument form
```
Getting this wrong means reading an unrelated register as if it were a
pointer and dereferencing it — a real kernel-panic risk, not a
hypothetical one. So this module ships a short table of
`(kernel version range → ABI shape)`, with every row individually checked
against real kernel source — both mainline `torvalds/linux` tags and the
actual Android common-kernel branches:

| kernel version | `security_sid_to_context` shape | verified against |
|---|---|---|
| `< 4.19` | 3-arg (no state) — *not verified, hook stays off* | mainline v4.4, v4.9 |
| `4.19 – 5.0` | 4-arg (`state` first) | `android-4.19-stable` (covers e.g. **4.19.191**), mainline v4.19 |
| `5.0 – 6.4` | 4-arg (`state` first) | `android-5.4-stable`, `android12-5.10`, `android13-5.15`, `android14-6.1`, mainline v5.4/v5.10/v5.15/v6.1 |
| `6.4 +` | 3-arg (no state) | `android15-6.6`, mainline v6.4/v6.6/v6.12 |

On boot, the module checks the running kernel version (KernelPatch's `kver`)
against this table. **A match → the deep hook installs. No match → it is
left disabled, on purpose, and only the recvfrom/logd hook (PART 1) is
active.** Extending the table to a kernel version not listed here means
checking that version's real `security.h` first, the same way this table
was built — not adding a plausible-looking row.

If you're on a kernel this table doesn't cover and want it added, the most
useful thing you can hand over is the exact kernel version/branch (e.g.
`android13-5.15` or a specific commit/tag), so the same source-level
verification can be done for it specifically instead of guessed generically.

**Why the PART 2 replacement text is short and generic
(`u:r:na:s0`), not the fuller `u:r:priv_app:s0:c512,c768` PART 1 uses:**
the buffer `security_sid_to_context()` returns is a real kernel object
(`kstrdup()`'d, verified from source: exactly `strlen(original)+1` bytes,
zero slack) that unrelated kernel code later `kfree()`s. An earlier version
of this module allocated a fresh, freely-sized replacement buffer for this
using the real kernel's `kmalloc()`, reasoning that swapping in a buffer
from a different allocator would eventually hand the kernel's real
`kfree()` a pointer it never allocated. That reasoning about `kfree()`
compatibility held up, but the *allocator itself* turned out not to be a
safe assumption: see **Troubleshooting** below for how a real bug report
showed `kmalloc()`/`kfree()` (and even this KPM's own `kp_malloc()`) simply
weren't exported symbols on one real device, which failed the entire
module's load. So PART 2 now only ever overwrites the existing buffer *in
place*, which means its replacement can never be longer than the shortest
pattern it might replace (`u:r:su:s0`, 9 bytes) — a real cosmetic
downgrade, accepted deliberately in exchange for the module actually
loading rather than depending on an allocator kfunc that isn't universally
exported.

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

The `.github/workflows/build.yml` action builds this three ways on every
push and pull request:
1. `lint` — fast host-`gcc` `-fsyntax-only` pass against the real
   KernelPatch headers (catches type/API mistakes; cannot catch codegen or
   relocation issues, since it never invokes an assembler).
2. `fast-check` — a *real* AArch64 build using Ubuntu's apt-installable
   `gcc-aarch64-linux-gnu` (installs in seconds, unlike the full ARM
   toolchain below), then `kpm/tools/verify-kpm.sh` checks the actual
   output is something KernelPatch's loader will accept (see
   **Troubleshooting**), plus a stack-usage budget check.
3. `build` — the real release build with the official
   `aarch64-none-elf-` toolchain, running the same `verify-kpm.sh` check
   against its output before attaching `auditpatch.kpm` to tagged releases
   (`vX.Y.Z`).

You can run the same loadability check locally against your own build:
`sh kpm/tools/verify-kpm.sh <path-to-readelf> kpm/auditpatch.kpm`.

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
# p1_hooked=1 target=logd p1_scanned=<n> p1_patched=<n> p1_errors=<n> | p2_hooked=1 p2_has_state=1 p2_patched=<n> p2_errors=<n>
kpatch "$SUPERKEY" kpm ctl0 zn-auditpatch-kpm reset   # zero the counters
```

`p2_hooked=0` with no error logged simply means the running kernel didn't
match a verified table entry above — PART 1 is still fully active in that
case.

## Troubleshooting: "Embed" succeeds but the KPM never shows up as loaded

**If you're on v2.2.0+, both root causes below are already fixed — this
section is kept as a record of what they were and how they were found,
since the debugging technique (the `bootlog` trick especially) is useful
for diagnosing *any* KPM that has this symptom, not just this one.**

Symptom: APatch/FolkPatch Manager's "Embed KPM" step reports no error, but
after flashing and rebooting the module never appears in the active-KPM
list (as opposed to the "Existed/staged KPM" list, which just reflects
what's embedded in `boot.img`, not what actually loaded), and
`dmesg | grep -i kpm` shows nothing.

**That last check is misleading, and finding that out was itself the key
to diagnosing cause #2 below.** KernelPatch's own internal logging uses a
`[+] KP I` / `[-] KP E` prefix, not the substring `kpm` — so a plain
`grep -i kpm` on `dmesg` can miss the exact lines that matter. Worse, an
*embedded* KPM is loaded by `kernel/patch/patch.c` at `pre-kernel-init`,
early enough that the message may only exist in KernelPatch's own
early-boot log buffer, not the regular kernel ring buffer `dmesg` reads at
all. The reliable way to see it:

```sh
# no su needed -- this hijacks execve() of the literal `truncate` path
/system/bin/truncate "$SUPERKEY" bootlog
```
and look for a line like:
```
KP load kpm: zn-auditpatch-kpm, event: pre-kernel-init, rc: -2
```
`rc` is a plain negative errno from KernelPatch's `load_module()` —
`0` means it loaded, anything else tells you why it didn't (`-2` /
`-ENOENT` specifically means "unknown symbol", see cause #2 below).

### Cause 1: GOT-relative relocations (fixed in v2.1.1)

Confirmed by actually disassembling a real `aarch64` build of this module
(not just syntax-checking it, which is all `-fsyntax-only` can do — it
never invokes an assembler): a real `aarch64` GCC, without
`-fno-pic -fno-pie` set explicitly, emits `R_AARCH64_ADR_GOT_PAGE` /
`R_AARCH64_LD64_GOT_LO12_NC` relocations for essentially every
external/kfunc call in this file. KernelPatch's own ELF relocator
(`kernel/patch/module/relo.c`) does not implement either relocation type;
it logs `unsupported RELA relocation` and rejects the module. The Makefile
now sets `-fno-pic -fno-pie`; verified concretely (compiled with real
`aarch64-linux-gnu-gcc`, before/after: every function call using a GOT
relocation → zero of them, all 174 relocations in the small set `relo.c`
handles).

### Cause 2: `kmalloc`/`kfree`/`kp_malloc`/`kp_free` not universally exported (fixed in v2.2.0)

Fixing cause #1 was necessary but, on at least one real device, not
sufficient — a `bootlog` capture (see above) from a genuine bug report
showed the module still failing, with a *different* root cause:

```
KP E unknown symbol: kf_kfree
KP E unknown symbol: tlsf_free
KP E unknown symbol: kf___kmalloc
KP E unknown symbol: tlsf_malloc
KP E unknown symbol: kp_rw_mem
KP E unknown symbol: kf_kmalloc
KP load kpm: zn-auditpatch-kpm, event: pre-kernel-init, rc: -2
```

PART 2 used the real kernel's `kmalloc()`/`kfree()` (via KernelPatch's
kfunc mechanism) to allocate a replacement context buffer, specifically
*because* the buffer's eventual `kfree()` by unrelated kernel code
requires it to come from a real, kfree()-compatible allocator (see the
long comment above `after_sid_to_context()` in the source for the full
reasoning — that part was correct). What turned out to be wrong was
assuming that allocator path is universally present: on the device this
was debugged against, `kf_kmalloc`/`kf___kmalloc`/`kf_kfree` were absent
from that KernelPatch/FolkPatch build's exported symbol table entirely,
which fails the *whole module's* load (symbol resolution happens for
every undefined symbol before `KPM_INIT` ever runs).

Less obviously: `kp_malloc()`/`kp_free()` — KernelPatch's *own* allocator,
used by PART 1's scratch buffer at the time — turned out to depend on
exactly the same unavailable symbols. They're `static inline` wrappers
around `tlsf_malloc()`/`tlsf_free()`/`kp_rw_mem` (see KernelPatch's
`kpmalloc.h`), which is why those three names show up in the same failure
list even though nothing in this module calls them directly — the
`kp_malloc`/`kp_free` symbol names themselves never appear in a compiled
object at all, since they're inlined away, which is exactly why this
half of the problem wasn't obvious from the undefined-symbol list alone.

Both parts were rewritten to not depend on any kernel-object allocator:
- PART 1's scratch buffer is now a fixed-size buffer on the stack (1536
  bytes — comfortably covers real AVC audit lines, well inside a safe
  stack budget, verified with `-fstack-usage`), never handed to any other
  kernel code, so it needs no allocator at all.
- PART 2 now overwrites the existing context buffer *in place* instead of
  allocating a replacement, which is why its replacement text
  (`CTX_REPLACEMENT_SHORT` in the source) is short and generic rather than
  matching PART 1's fuller `u:r:priv_app:s0:c512,c768` — it's bounded by
  the original buffer's exact size (a `kstrdup()`, confirmed against real
  kernel source to have zero slack), not by a freely-sized allocation.

If you rebuild with v2.2.0+, no allocator kfunc of any kind is required by
this module anymore — only string/printk/hook-infrastructure kfuncs and
KernelPatch's own core (`kver`, `task_struct_offset`, `hook_wrap`,
`hook_syscalln`, `kallsyms_lookup_name`, ...), which is about as close to
"every KernelPatch build has these" as this module can get.

If you rebuild and it *still* doesn't show up, in order of how directly
they answer "did it load at all":
1. `/system/bin/truncate "$SUPERKEY" bootlog` right after a fresh reboot —
   most direct, and (per above) catches cases regular `dmesg` misses.
2. `kpatch "$SUPERKEY" kpm list`.
3. `dmesg | grep -iE "KP [EWI]|kpm|zn-auditpatch"` — note the `KP [EWI]`
   alternative, not just `kpm`, per the note above.
4. `file auditpatch.kpm` should say `ELF 64-bit LSB relocatable, ARM
   aarch64`; if your build pipeline downloaded something else (an HTML
   error page saved with a `.kpm` extension, for instance), that's a
   packaging/download problem rather than anything about this module.
5. If `bootlog` shows an `unknown symbol: X` line for something other than
   an allocator symbol, that's a new instance of the same class of problem
   as cause #2 — please report which symbol so this module can stop
   depending on it too.

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
- Unloading a running KPM (`kpm unload`, e.g. via APatch Manager's KPM
  screen after using "Load") is not fully synchronized against concurrent
  execution: `unload_module()` in KernelPatch's own
  `kernel/patch/module/module.c` calls the module's `exit()` and then
  immediately frees its executable memory with no wait for other CPUs to
  finish executing code from it (the function is literally preceded by a
  `// todo: lock` comment upstream). This is a framework-level gap shared
  by every KPM, not something specific to this one, and not something a
  KPM author can fix from outside KernelPatch itself. Practical effect:
  prefer **Embed** over repeated **Load**/unload cycles for anything other
  than short testing sessions, since Embed never goes through this
  runtime-unload path at all.

## Hardening / correctness notes

A few things worth stating plainly rather than leaving implicit, from
actually compiling this to real AArch64 object code (see **Troubleshooting**
above) and inspecting the result rather than just reasoning about it:

- **Stack usage is small and checked in CI.** The largest function
  (`after_recvfrom`, which holds the 1536-byte fixed scratch buffer
  described in **Troubleshooting**) uses 1616 bytes per `-fstack-usage`;
  everything else is well under 512 bytes. CI's `fast-check` job fails the
  build if any function exceeds a 2 KiB budget, as a guard against a
  future change accidentally growing that further on top of an unknown,
  already-partially-used kernel stack.
- **Neither part of this module allocates a kernel object anymore.** See
  **Troubleshooting** for why: a real bug report showed that neither the
  real kernel's `kmalloc()`/`kfree()` nor even this KPM's own
  `kp_malloc()`/`kp_free()` are safe to assume present across KernelPatch
  builds. PART 1's scratch buffer is a fixed-size stack buffer; PART 2
  overwrites its target buffer in place. No allocator kfunc of any kind is
  a load-time dependency of this module as of v2.2.0.
- **Statistics counters are genuinely atomic**, not just `volatile`:
  `g_p1_scanned`/`g_p1_patched`/`g_p1_errors`/`g_p2_patched`/`g_p2_errors`
  are `atomic64_t`, confirmed by disassembly to compile to real
  `ldxr`/`stxr` load-/store-exclusive sequences (not a plain
  load-increment-store that could lose updates if both PART 1 and PART 2
  fire on different CPUs at the same moment). Nothing security-relevant
  depends on these being exact — only the `ctl0 status` reporting does —
  but there's no reason for them to be sloppy either.
- **Every relocation type the build actually produces is one KernelPatch's
  loader implements**, enforced by `kpm/tools/verify-kpm.sh` in both CI
  jobs (see Troubleshooting) — not just "it compiled", which as v2.1.0
  demonstrated is not sufficient on its own to mean it will load. That
  script cannot, by its nature, catch a missing-*symbol* failure the way
  it catches a bad relocation *type* (it has no way to know what symbols a
  real target device's KernelPatch build does or doesn't export) — the
  `bootlog` technique in Troubleshooting is the tool for that class of
  problem instead.

## Credits / license

- Original idea, module, and the exact string-replacement logic:
  [aviraxp/ZN-AuditPatch](https://github.com/aviraxp/ZN-AuditPatch).
- KPM/KernelPatch APIs used throughout: [bmax121/KernelPatch](https://github.com/bmax121/KernelPatch).
- GPL-2.0-or-later, see [`LICENSE`](LICENSE) — same as KernelPatch itself,
  whose headers/exported kernel symbols this module is built against.
