# path_hide

KernelPatch module for Linux **4.19.157-perf** (munch / MIUI OS1.0.10.0.ULMCNXM).

It contains two independent modes:

| Mode | Purpose |
|---|---|
| `probe <uid>` | Log VFS lookup/readdir events for one uid. Changes **nothing**. |
| `hide on` + `add <path>` | Hide registered paths from app processes. |

The probe exists so the hook points and the hard-coded offsets can be verified
on the real device before `hide` is turned on.

## Config directory (recommended)

Instead of feeding one `add` command per path, put the configuration in
`/data/local/tmp/path_hide/` and send a single `reload`:

```
/data/local/tmp/path_hide/
├── paths      # one absolute path per line, '#' comments
└── config     # key=value
```

`/data/local/tmp/path_hide/paths`:

```
# hide these from app processes
/sdcard/TWRP
/data/media/0/TWRP
/system/addon.d
/vendor/bin/install-recovery.sh
```

`/data/local/tmp/path_hide/config`:

```
hide=1
minuid=10000
probe=off
# probe=2000      # or trace one uid
# budget=200
```

Offset overrides are optional; the defaults are the ones verified for this
Image. Keys are hex:

```
# off_nd_mnt=0x0
# off_nd_dentry=0x8
# off_nd_flags=0x38
# off_dentry_inode=0x30
# off_inode_uid=0x4
# off_inode_sb=0x28
# off_inode_ino=0x40
# off_file_inode=0x20
# off_vma_file=0xa0
# off_seq_count=0x18
# off_cred_security=0x78
# off_tsec_sid=0x4
# off_tsec_create_sid=0xc
# off_tsec_keycreate_sid=0x10
# off_tsec_sockcreate_sid=0x14
```

Invalid values (negative, >= 0x1000, or misaligned) are rejected and the
previous value is kept. `offsets` prints the live values; `selftest` triggers
a probe lookup so the path/inode can be compared with `stat`.

Create it and load:

```sh
mkdir -p /data/local/tmp/path_hide
# ... write paths/config ...
# then send: reload
```

The module also runs `reload` automatically at load time, so loading the KPM
after writing the files is enough. After editing the files, send `reload`
(or unload/reload the KPM) to apply.

`reload` semantics:

- `paths` is the source of truth: the registry is cleared and rebuilt from it.
  Entries previously added with the `add` command are discarded.
- The new registry is built into an inactive buffer while the old one keeps
  hiding, then swapped with a single release store: there is **no window where
  hidden paths become visible during a reload**.
- The reloading uid is exempted from the hooks while it resolves the paths, so
  re-resolving a hidden path cannot drop it from the new registry.
- `hide=1` is applied last, after the swap.
- A missing `paths` file results in an empty registry (fail-open).

### SELinux and the control caller

The config lives in `/data/local/tmp` (`u:object_r:shell_data_file`) rather
than `/data/adb` (`u:object_r:adb_data_file`). On this device even the `su`
domain is denied `search` on `/data/adb`'s `adb_data_file` directory, so
`/data/adb` is not usable from an app-driven control channel.

An app-context caller (`u:r:untrusted_app_*`) may still be denied
`shell_data_file`. `reload`/`add` therefore try the caller's own context
first, and only on `EACCES`/`EPERM` retry with a root cred whose SELinux SID
was written **directly**. Each candidate scontext is tried in turn; the first
one that can actually read the files wins:

```
u:r:magisk:s0
```

On this device `u:r:magisk:s0` is the only domain that can read
`/data/local/tmp/path_hide`; `u:r:su:s0` is denied `shell_data_file`. The
`sctx=` load arg can still override the single candidate if the policy
changes.

The load args can put one candidate first:

```
sctx=u:r:su:s0
```

Do **not** use `set_security_override()`: `selinux_kernel_act_as()` checks
`KERNEL_SERVICE__USE_AS_OVERRIDE` against the caller and silently denies apps,
leaving the cred with the kernel SID. Use the `APatch_kpm/run_cmd_demo`
pattern (also used by KernelPatch's `commit_su()`):

```
prepare_kernel_cred(NULL)
  -> security_secctx_to_secid(sctx, &sid)
  -> blob = *(void **)((char *)cred + 0x78)     // cred->security
  -> *(u32 *)((char *)blob + 0x04) = sid        // tsec->sid
  -> clear create_sid/keycreate_sid/sockcreate_sid
  -> override_creds(new) ... filp_open/kernel_read/kern_path ...
  -> revert_creds(old)
  -> atomic_dec_and_test(usage); __put_cred() only at zero
```

The offsets were derived from this Image's `selinux_cred_getsecid()`
(`ldr x8,[cred,#0x78]; ldr w8,[x8,#4]`) and `selinux_kernel_act_as()`. If
`selinux_cred_getsecid` is available, the module verifies both offsets before
writing.

The reload log:

```
[path_hide] reload: sctx u:r:su:s0 cerr=-13 err=-13 denied=0 ok=0
[path_hide] reload: sctx u:r:shell:s0 cerr=0 err=0 denied=0 ok=1
[path_hide] reload: using sctx u:r:shell:s0
[path_hide] reload: cerr=0 err=0 denied=0 paths ok=1 fail=0 hide=1 minuid=10000 probe=-1
```

- `cerr` / `err` → config / paths file read errors (`-13` = `EACCES`,
  `-2` = `ENOENT`).
- `denied` → number of paths whose `kern_path()` returned `EACCES`/`EPERM`.
- A new AVC line shows which `scontext` was actually used.

## Build

```bash
export TARGET_COMPILE=/path/to/arm-gnu-toolchain-12.2.rel1-x86_64-aarch64-none-elf/bin/aarch64-none-elf-
cd path_hide
make
# -> path_hide.kpm
```

`KP_DIR` defaults to `../KernelPatch` (the submodule, 0.13.2).

> **KPMs must be compiled with `-mgeneral-regs-only`.** Without it GCC is free
> to use NEON/FP/SIMD registers (e.g. `ldr q0` / `str q0` for a 16-byte struct
> initialiser). The kernel does not save/restore kernel-mode FP state across
> preemption, so such a store can write garbage. This actually happened here:
> the `ph_cfg` defaults came out as `hide=48 minuid=0 probe=0`. The Makefile
> also passes `-mno-outline-atomics` so atomics are inlined instead of calling
> `__aarch64_*` libgcc helpers (KPMs cannot resolve those symbols).

## Load / control

```c
sc_kpm_load(key, "/data/local/tmp/path_hide.kpm", NULL, NULL);

char out[512];
sc_kpm_control(key, "path_hide", "probe 2000", out, sizeof(out));
sc_kpm_control(key, "path_hide", "add /sdcard/TWRP", out, sizeof(out));
sc_kpm_control(key, "path_hide", "hide 1", out, sizeof(out));
sc_kpm_control(key, "path_hide", "status", out, sizeof(out));

sc_kpm_unload(key, "path_hide", NULL);
```

### Control commands

```
reload            read /data/local/tmp/path_hide/{paths,config} and rebuild
offsets           print the live struct offsets
selftest          probe one lookup (check dmesg against stat)
add <path>        resolve path, store (sb, ino, uid)
clear             drop all registered paths
hide <0|1>        enable/disable actual hiding
minuid <n>        hide from uid >= n (default 10000)
probe <uid|off>   trace one uid (exact match), or disable tracing
budget <n>        reset the remaining probe log lines
status            version, hide/probe state, entries, used scontext
list              list registered paths
```

> `reload` is the normal interface. The imperative commands are kept for
> debugging; a `reload` will overwrite anything added with `add`.
>
> Hooks are installed only while `hide=1` or a probe uid is set; otherwise
> they are removed, so an idle module has no VFS overhead.

## Probe workflow

1. Load the module (probe is off by default, hide is off).
2. Pick the uid to observe:
   - adb shell = `2000`
   - `su` = `0`
   - an app = `10xxx` (`stat -c %u /data/data/<pkg>`)
3. Enable tracing, either with the control command `probe <uid>` or by putting
   `probe=2000` in `/data/local/tmp/path_hide/config` and sending `reload`.
4. Run a few operations as that uid:
   ```
   stat /system/build.prop
   ls /sdcard
   cat /system/bin/sh >/dev/null
   ```
5. Watch dmesg:
   ```
   dmesg | grep path_hide
   ```
6. `probe off` (or set `probe=off` and `reload`).

Expected lines (paths should be real, inode numbers should match `stat`):

```
[path_hide] probe walk_component uid=2000 ino=1234 iuid=0 path=/system/build.prop
[path_hide] probe lookup_fast    uid=2000 ino=1234 iuid=0 path=/system/build.prop
[path_hide] probe complete_walk  uid=2000 ino=1234 iuid=0 path=/system/build.prop
[path_hide] probe filldir64      uid=2000 ino=5678 sb=ffffff8f12345000 name=Android
```

The `sb` value is the directory's superblock, captured by `iterate_dir`; it
should be the same for every entry of one `getdents64` call. If it is 0, the
`iterate_dir` hook did not run and readdir falls back to `ilookup()`.

If the paths/ino values are garbage, the offsets in `path_hide.h` do not match
the build and **hide must not be enabled**.

## Hide workflow

Write the two files and send one `reload`:

```sh
mkdir -p /data/local/tmp/path_hide

cat > /data/local/tmp/path_hide/paths <<'EOF'
/sdcard/TWRP
/data/media/0/TWRP
/system/addon.d
EOF

cat > /data/local/tmp/path_hide/config <<'EOF'
hide=1
minuid=10000
EOF

# control channel: reload
```

For testing from an adb shell, add `minuid=2000` to `config` first.

`add` uses `kern_path(path, LOOKUP_FOLLOW)`, so symlinks are resolved. Add both
the `/sdcard/...` and `/data/media/0/...` forms when hiding FUSE paths; readdir
matches the entry's ino against the registered inode via `ilookup()`.

The imperative equivalent (debug only, erased by the next `reload`):

```
add /sdcard/TWRP
add /data/media/0/TWRP
minuid 2000
hide 1
```

## What is hooked

| Symbol | When | What it does |
|---|---|---|
| `walk_component` | after | checks `nd->path.dentry->d_inode`; returns `-ENOENT` |
| `lookup_fast` | after | fast-path dentry; releases refs and returns `-ENOENT` (returns `-ENOENT` directly under RCU) |
| `complete_walk` | after | final component of open/stat before `may_open`/`vfs_open` |
| `iterate_dir` | before/after | records `file->f_inode->i_sb` for this getdents call |
| `filldir64` / `filldir` | before | matches `(dir_sb, ino)` and skips matching entries with `skip_origin` |
| `proc_cwd_link` / `proc_root_link` / `proc_exe_link` / `proc_fd_link` | after | drops the refs and returns `-ENOENT` when the link target is hidden |
| `show_map` / `show_smap` | before/after | discards the whole maps/smaps record of a hidden file-backed vma |

readdir prefers the authoritative `(dir_sb, ino)` pair captured by
`iterate_dir`. `ilookup()` is only a fallback for the FUSE case where the
dir sb is FUSE but only the backing `/data/media/0` path was registered, and
when the ctx→sb slot table is full.

The proc hooks cover `/proc/<pid>/{cwd,root,exe}` and `/proc/<pid>/fd/N`.
For maps/smaps, `ph_after_show_map()` restores `seq_file.count` to the value
from before the call, so the entire record is dropped (including its
device/inode fields — no partial line is leaked). `getcwd(2)` is not covered;
it would need a `__arm64_sys_getcwd` hook.

These hooks match the **registered inode**, so register the exact file for
`fd`/`exe`/`maps` (e.g. the `.so` or binary path), not only its parent
directory. Registering a directory hides the directory itself and lookups
through it, but not mmaps of files inside it.

All hooks are installed with `hook_wrap` (chained), so other modules can hook
the same functions.

## Verification against the running boot

Checked against `/home/prslc/Share/boot.img` (the actual device boot):

| Item | Result |
|---|---|
| Kernel | `4.19.157-perf-g045c5942d886` (same as stock) |
| Config | byte-identical to stock (KALLSYMS_ALL=y, no BTF, no RANDSTRUCT) |
| KernelPatch | **0.13.2** (`KP1158` setup header), same version as `KernelPatch/` submodule |
| Static KP patch | only the first Image entry `b` instruction; the rest of the stock kernel is **byte-identical** |
| `complete_walk` / `walk_component` / `lookup_fast` / `filldir64` | byte-identical to stock |
| Symbol addresses | identical to stock (`walk_component=ffffff80082d8c80`, `lookup_fast=ffffff80082d94a0`, `complete_walk=ffffff82d8a20` on the non-KASLR base) |
| `invoke_syscall` | absent |
| `sys_call_table` / `compat_sys_call_table` | present (needed later for uid hide) |

So the offsets in `path_hide.h` and the hook targets below are valid for the
running kernel, not just the stock vendor Image.

## Compatibility

**Symbol addresses are never hard-coded.** Every hooked function and every
helper (`kern_path`, `path_put`, `dput`, `ilookup`, `iput`, `filp_open`,
`kernel_read`, `filp_close`, `dentry_path_raw`) is resolved at module load with
`kallsyms_lookup_name()`, so KASLR and a different link address are fine. The
load log prints each address; a missing symbol only disables that hook.

What *is* build-specific:

| Item | Portability |
|---|---|
| Symbol addresses / KASLR | dynamic, fine |
| Symbol names + ABI (`walk_component` returns `int`, `lookup_fast(nd, path, inode, seqp)` returns `int`, `complete_walk` returns `int`, `filldir64` 6 args) | 4.19 mainline only |
| `nameidata` / `dentry` / `file` / `struct path` offsets | 4.19 layout, **config-dependent** |
| `inode` offsets | depend on `CONFIG_FS_POSIX_ACL`: with ACL (this build) `i_sb=0x28`, `i_ino=0x40`; without ACL they shift by `-0x10` |
| `CONFIG_RANDSTRUCT` | breaks all offsets (this kernel has it off) |
| 5.10 / 6.x | **not supported**: `walk_component` returns `const char *`, `lookup_fast` returns `struct dentry *`, and namei was refactored |

So: on another **4.19** vendor kernel with a typical config (POSIX ACL on, no
RANDSTRUCT, no LTO inlining of the four symbols), it has a good chance of
working as-is — but **always run `probe` first** and compare the printed
paths/ino against `stat`; the offset values in `path_hide.h` are not
self-validating. If they are wrong, re-derive them from that kernel's
disassembly or add that build's values.

## Side channels / detection

Fixed in this version:

- **RCU timing oracle**: `lookup_fast()` used to return `-ECHILD` for a hidden
  dcache hit, forcing a full ref-walk retry — a hidden path was measurably
  slower than a cached negative path. It now returns `-ENOENT` directly, the
  same way the kernel handles a negative dentry under RCU.
- **Reload visibility window**: the registry is double-buffered and swapped
  atomically, so hidden paths are never visible during a `reload`.
- **Self-interference**: the reloading uid is exempted from the hooks.

Still detectable (inherent to entry-level path hiding; most also apply to
SUSFS's `sus_path`):

- **Parent `st_nlink`** counts hidden subdirectories: `2 + visible_subdirs` vs
  the real value reveals that hidden directories exist.
- **`getdents` offsets**: on filesystems that use sequential directory
  offsets (tmpfs), skipping an entry leaves a gap in `d_off`. ext4/f2fs use
  hashed offsets, so this is much less visible there.
- **Pre-existing handles**: `/proc/self/cwd`, `/proc/*/fd/N`, `/proc/*/maps`
  and `/proc/*/smaps` are now covered (proc link hooks and
  `show_map`/`show_smap`). `getcwd(2)` itself is not, and fd-based
  `fstat`/`read` on an already-open fd still allow access to the object;
  `getcwd` would need a `__arm64_sys_getcwd` hook.
- **readdir vs stat inconsistency**: fixed for the normal case — `filldir`
  matches the authoritative `(dir_sb, ino)` captured by `iterate_dir`, so it
  no longer depends on the inode cache. The `ilookup()` fallback (used for the
  FUSE `/sdcard` → `/data/media/0` bridge or when the 32 ctx→sb slots are all
  busy) can still miss if that inode was evicted.
- **Stale registry**: matching is `(sb, ino)`; after a file is deleted and its
  inode number is reused, the new file can be hidden until the next `reload`.
  Re-run `reload` after filesystem changes.
- **Other sb views**: overlayfs copies or a different superblock exposing the
  same data are not matched.
- **Latency fingerprint**: the inline hooks are always installed, even when
  `hide=0`, so path lookups carry a constant trampoline overhead. Detecting it
  from userspace requires a reliable same-build baseline and many samples.

This is a userspace-visibility layer, not a defense against a kernel-level
adversary (root with kernel read/write can read the registry or the config
files directly).

## Known limitations on this Image

- `do_last()` and `lookup_open()` are **inlined into `path_openat()`**, so they
  cannot be hooked. The O_CREAT/`atomic_open` path therefore relies on
  `complete_walk`; if a filesystem implements `atomic_open` and sets
  `FMODE_OPENED`, `complete_walk` is skipped. f2fs/FUSE do not implement
  `atomic_open`; ext4 normally does not either.
- `lookup_slow` and `fillonedir` have no symbols in this Image (inlined or
  optimized out). `__lookup_slow` exists but is not needed by this design.
- `hidden` paths are hidden only from processes with `uid >= minuid`; the inode
  owner (`i_uid == current_uid`) always sees them, matching SUSFS behaviour.
- Offsets are build-specific. They were derived from the shipped Image:
  - `nameidata.path.mnt/dentry = 0x00/0x08`
  - `nameidata.flags = 0x38`
  - `dentry.d_inode = 0x30`
  - `inode.i_uid/i_sb/i_ino = 0x04/0x28/0x40`
- Re-derive them if the vendor kernel changes (no BTF/RANDSTRUCT in this one).
