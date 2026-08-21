# Tasks

## 1. Provider skeleton

- [ ] 1.1 Scaffold the Go module and terraform-plugin-framework provider named `terrahive`
- [ ] 1.2 Provider configuration: `pin_dir` (default `/sys/fs/bpf/terrahive`), validate bpffs mount and privileges
- [ ] 1.3 Shared internal package for pin, load, read, and unpin via cilium/ebpf
- [ ] 1.4 goreleaser config, registry manifest, GPG signing

## 2. Program loading

- [ ] 2.1 `ebpf_program` schema with `object_file`, `c_source`, `go_source` and `ExactlyOneOf` validation
- [ ] 2.2 Load from object file: parse ELF, infer type from section, load, pin
- [ ] 2.3 Read: resolve pin, compare program tag and type for drift
- [ ] 2.4 Delete and import
- [ ] 2.5 `c_source` path: compile with system clang at apply
- [ ] 2.6 Force replacement on any source or type change

## 3. Maps

- [ ] 3.1 `ebpf_map` resource: type, key_size, value_size, max_entries; create, pin, read, delete
- [ ] 3.2 `ebpf_map_entry` resource: base64 key and value, lookup-based drift detection
- [ ] 3.3 Map sharing: programs reference pinned maps by path

## 4. Attachments

- [x] 4.1 `ebpf_kprobe` (kprobe, kretprobe, uprobe, uretprobe, usdt)
- [x] 4.2 `ebpf_tracepoint` (tracepoint, raw_tracepoint, perf_event)
- [x] 4.3 `ebpf_tracing` (fentry, fexit, fmod_ret, lsm, iter)
- [x] 4.4 `ebpf_xdp` (interface, mode)
- [x] 4.5 `ebpf_tcx` (interface, direction)
- [x] 4.6 `ebpf_cgroup` (cgroup path, attach_type)
- [x] 4.7 `ebpf_netfilter`
- [x] 4.8 `ebpf_struct_ops`

## 5. Flavors

- [ ] 5.1 Build tags splitting lean and bumble binaries
- [ ] 5.2 Embed pinned TinyGo toolchain via embed.FS, extract-on-first-use cache
- [ ] 5.3 `go_source` compile path in bumble; clear error in lean
- [ ] 5.4 Release both flavors from one pipeline

## 6. Verification and docs

- [ ] 6.1 Acceptance tests under privileged CI (programs, maps, entries, kprobe, xdp)
- [ ] 6.2 Example configs: hello-kprobe (object file), xdp-drop (C), go-probe (bumble)
- [ ] 6.3 Registry docs per resource, README with the beekeeper framing and the bumblebee flight joke
