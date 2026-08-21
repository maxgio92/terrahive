# Everything wrong with this idea

Read this if you are deciding whether to take terrahive seriously. It lists every Terraform and eBPF practice this provider violates, why each one matters, and why we did it anyway. By the end you will know exactly what you are signing up for.

Terrahive is a Terraform provider that manages eBPF programs, maps, and links on the Linux kernel it runs on. It is a meme built to be technically sound. Both halves of that sentence are true, and this page is the evidence for the first half.

## 1. Terraform managing the local machine

Terraform providers call remote APIs. The provider process holds credentials, the infrastructure lives somewhere else, and the state file survives whatever happens to the machine running `terraform apply`. That separation is the whole model.

Terrahive calls the `bpf()` syscall on the kernel it runs inside. The state file and the target share fate: reinstall the OS and your state describes a kernel that no longer exists. There is no "somewhere else". The API endpoint is `/proc/self`.

We do it anyway because the `bpf()` syscall is an API, it does CRUD, and nobody said the API had to be over a network. The provider is honest about the blast radius: it is exactly one machine, and you are standing on it.

## 2. terraform apply as root

Infrastructure-as-code tooling runs with scoped cloud credentials that a leaked token can revoke. Terrahive needs root or CAP_BPF, because loading BPF programs needs root or CAP_BPF. You are running a Terraform provider, its plugin protocol, and its dependency tree with kernel-level privileges.

We do it anyway because there is no other way to load a BPF program, and every eBPF tool you already run (bpftool, bcc, bpftrace) makes the same demand. Terrahive did not raise the privilege bar; it just put Terraform behind it.

## 3. Ephemeral objects forced to be durable

BPF objects die with the process that loaded them. That is a design decision by the kernel: file descriptors hold references, the last reference drops, the object unloads. It keeps the kernel clean when tools crash.

Terraform resources must outlive the process that created them, or Read returns nothing and every plan is a full rebuild. So terrahive pins every object to bpffs, and the pin path is the resource ID. Pinning exists as an escape hatch for long-lived objects. Terrahive uses it for everything, always, and calls the pin path an identity. That is a hack elevated to architecture.

We do it anyway because it works. A pinned object holds a kernel reference until you unpin it, Read resolves the pin and fetches real object info, and Delete unpins and drops the last reference. The lifecycle maps onto CRUD with no gaps. It is still a hack. It is also load-bearing.

## 4. Drift by design

`terraform refresh` assumes the world changes slowly and mostly through Terraform. An `ebpf_map_entry` resource diffs a value in a kernel hashmap that the attached BPF program may rewrite millions of times per second. The value can change between plan and apply. It can change between two reads of the same plan. You are running drift detection against the kernel's hot path.

We do it anyway because some map entries really are configuration: a feature flag, a rate limit, a config struct the program only reads. For those, `ebpf_map_entry` is correct. For counters and per-packet state it is a machine for generating diffs, and the docs say to leave those maps alone. The resource does not know which kind of map it is looking at. You do.

## 5. Verification at the wrong phase

`terraform plan` promises that if plan succeeds, apply will too, modulo the outside world changing. The eBPF verifier runs inside the kernel at load time, which for terrahive means at apply. A plan can validate cleanly and apply can fail with a verifier rejection, which is the exact failure `plan` exists to catch early.

We do it anyway because the verifier cannot run anywhere else. It checks the program against the running kernel's BTF, its version, and its configuration. No userspace simulation is authoritative. The mitigation is diagnostics: a verifier rejection surfaces in the apply error with the full verifier log, so at least the failure explains itself.

## 6. A compiler inside a provider

The `terrahive-bumble` flavor embeds a pinned TinyGo release, which statically links LLVM. The binary is roughly 150 MB. It extracts the toolchain to a cache directory on first use and compiles your Go source into BPF bytecode during apply.

The eBPF ecosystem spent years escaping exactly this. BCC compiled C at runtime on every target machine, which meant shipping LLVM and kernel headers everywhere. CO-RE (compile once, run everywhere) exists precisely so nobody has to do that again. Bumble reads that history and ships the compiler anyway.

We do it anyway because `terraform apply` compiling Go into kernel bytecode is the joke, and the joke has to work. The lean `terrahive` flavor takes precompiled object files only and carries no compiler; it is the flavor you should use. Bumble is the showcase, and the 150 MB is the punchline.

## 7. Replace-only updates

A loaded BPF program is immutable in the kernel, so every change to an `ebpf_program` forces destroy-and-create. Attachment resources reference programs by pin path, so the replacement cascades: the link detaches, the old program unloads, the new one loads, the link reattaches. Between detach and reattach, the probe is off. Events in that window are simply not observed.

We do it anyway because there is no in-place mutate to offer. Blue-green kernel probes are not a thing; you cannot run old and new side by side and cut traffic over. If your program must never miss an event, do not manage its lifecycle with a tool whose update primitive is a gap.

## 8. No remote state story

Remote state backends, locking, and workspaces exist so a team can manage shared infrastructure without racing each other. Terrahive's infrastructure is one machine's kernel. Put the state in S3 and two colleagues who apply the same configuration instrument two different kernels, each holding a lock that protects the other from nothing. The state file is only meaningful on the machine that produced it.

We do it anyway because local state on the target machine is coherent, and that is what terrahive assumes. If you want fleet-wide declarative BPF, that tool exists and it is called bpfman. See below.

## 9. The prefix mismatch

Terraform convention says resource names start with the provider name: `aws_instance`, `google_compute_network`. Terrahive's resources are `ebpf_program`, `ebpf_map`, `ebpf_link_kprobe`. The prefix says what the resources are; the provider name says what the project is; they disagree. Every configuration needs an alias in `required_providers`:

```hcl
terraform {
  required_providers {
    ebpf = {
      source = "maxgio92/terrahive"
    }
  }
}
```

We do it anyway because `terrahive_program` describes the tool and `ebpf_program` describes the object, and configurations are read more often than providers are named. The alias costs four lines once per module. Naming the resource after the meme would cost every reader on every line.

## 10. Impossible resources, acknowledged

Four attach types cannot be terrahive resources at all: `socket_filter`, `sk_msg`, `sk_skb`, and `sk_reuseport`. They bind a program to a live socket file descriptor owned by some process. There is no persistent kernel object for Terraform to own, nothing to pin, and nothing for Read to resolve after the socket's owner exits. Terrahive can load and pin those programs; it cannot own their attachment, and no amount of pinning changes that.

We do not do it anyway. This is the one place the model breaks completely, so the provider refuses rather than pretends. A tool this committed to a bad idea owes you a clear statement of where the idea stops.

## Why it works anyway

The sins above are real, and so is this: the kernel's BPF object model genuinely maps to CRUD. Programs, maps, and links each have a file descriptor, a global ID, queryable object info, and a pin path. Create loads, Read resolves the pin and fetches kernel state, Delete unpins and unloads. That is not a metaphor stretched to fit; it is the actual shape of the `bpf()` API.

Declarative BPF management is also proven ground. bpfman manages BPF program lifecycles declaratively in production, including as a Kubernetes operator. Terrahive did not invent the idea; it relocated it into a tool with a worse fit and a better meme.

And pinned links are real durability, not a trick. A pinned `bpf_link` keeps its attachment alive across process exits, reboots of the loading tool, and anything short of unpinning or rebooting the kernel. Drift detection against pinned objects compares real kernel state to declared state and reports real differences.

So the satire is informed. Every anti-pattern on this page was chosen with the alternative understood. The provider is wrong the way a well-built ship in a bottle is wrong: the objection is not that it fails, but that it exists.
