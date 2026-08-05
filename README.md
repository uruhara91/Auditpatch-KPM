# AuditPatch (KPM)

A **KernelPatch Module (KPM)** port of [aviraxp/ZN-AuditPatch](https://github.com/aviraxp/ZN-AuditPatch),
a Zygisk Next module. Same user-visible effect, different (kernel-space)
mechanism. Background: [`android-review.googlesource.com/c/platform/system/logging/+/3725346`](https://android-review.googlesource.com/c/platform/system/logging/+/3725346).

## Credits / license

- Original idea, module, and the exact string-replacement logic:
  [aviraxp/ZN-AuditPatch](https://github.com/aviraxp/ZN-AuditPatch).
- KPM/KernelPatch APIs used throughout: [bmax121/KernelPatch](https://github.com/bmax121/KernelPatch).
- Authors: aviraxp, uruhara91.
- GPL-2.0-or-later, see [`LICENSE`](LICENSE) — same as KernelPatch itself.
