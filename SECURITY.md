# Security Policy

## Read this first

Terrahive is not a normal Terraform provider. It does not call a remote API.
It calls the `bpf()` syscall on the kernel of the machine that runs
`terraform apply`. To load programs, create maps, and attach to kernel hooks,
the provider needs root or `CAP_BPF` (plus related capabilities), and it needs
a `bpffs` mount. It loads and runs code inside your kernel.

The blast radius is the whole machine. A bad program, a bad map write, or a
bad attachment can crash the box, corrupt kernel state, or expose data that
crosses the kernel boundary. Run Terrahive only on hosts you own and can
afford to lose. Do not run it against production hosts you cannot rebuild.

## Supported versions

Security fixes land on the latest released minor version. Older versions do
not get backports. Upgrade to the latest release before you report a problem,
and confirm the issue still reproduces there.

## Reporting a vulnerability

Report privately. Do not open a public issue for a security problem.

Use GitHub private vulnerability reporting:

1. Go to the repository Security tab.
2. Click "Report a vulnerability".
3. Describe the problem, the affected version, and the steps to reproduce.

Include a proof of concept when you can. Include the kernel version and the
architecture, because BPF behavior depends on both.

## What to expect

We aim to acknowledge a report within 5 business days. We will confirm the
issue, agree on a fix, and coordinate a release. We credit reporters who want
credit. Please give us time to ship a fix before you disclose publicly.

## Out of scope

The following are known properties of the design, not vulnerabilities:

- The provider requires root or `CAP_BPF`. That is by design.
- The provider loads and runs kernel code by design. See
  [docs/ANTIPATTERNS.md](docs/ANTIPATTERNS.md).
- Running Terrahive on a host you do not control is your risk to manage.
