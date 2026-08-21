resource "ebpf_cgroup" "ingress" {
  name        = "cgroup-ingress"
  program     = ebpf_program.skb.id
  cgroup      = "/sys/fs/cgroup/my-service"
  attach_type = "cgroup_inet_ingress"
}
