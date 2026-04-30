# copy-fail-destroyer

A Kubernetes DaemonSet agent that detects and remediates [CVE-2022-27666](https://nvd.nist.gov/vuln/detail/CVE-2022-27666) — a heap buffer overflow in the Linux kernel's ESP6 (IPsec) implementation, exploitable via the `AF_ALG` socket interface and `splice`.

## What it does

On each node the agent runs a loop every 5 minutes that:

1. **Checks the kernel version** against all known patched stable branches.
2. **Probes the AF_ALG module** by attempting to create and bind an `AF_ALG` socket to `aead` / `authenc(hmac(sha256),cbc(aes))` — the exact algorithm the exploit targets. This is safe and non-destructive.
3. **Remediates** by unloading the `algif_aead` kernel module (`delete_module`) if the probe succeeds, removing the attack surface until the kernel can be patched.
4. **Exposes Prometheus metrics** so you can alert and track status across the fleet.

## Prometheus metrics

All metrics are exposed on `:9100/metrics`.

| Metric | Description |
|---|---|
| `cve_2022_27666_kernel_needs_patching` | `1` if the kernel version is not patched for CVE-2022-27666 |
| `cve_2022_27666_vulnerable` | `1` if the kernel is vulnerable **and** the module is reachable (actively exploitable) |
| `cve_2022_27666_module_reachable` | `1` if the `AF_ALG` aead algorithm can be bound |
| `cve_2022_27666_remediation_applied` | `1` if the `algif_aead` module was successfully unloaded |

## Patched kernel versions

The detector tracks fixes across these stable branches:

- `5.17.0+` (mainline)
- `5.16.15`, `5.15.29`, `5.10.106`, `5.4.185`
- `4.19.235`, `4.14.272`, `4.9.307`

## Project structure

```
cmd/destroyer/main.go          # Entry point — metrics server, check loop, remediation
pkg/detector/
  cve202227666.go              # Kernel version detection, KernelNeedsPatching()
  probe_linux.go               # AF_ALG module probe (Linux)
  probe_other.go               # Probe stub (non-Linux)
  remediate_linux.go           # Module unload via delete_module (Linux)
  remediate_other.go           # Remediation stub (non-Linux)
deploy/daemonset.yaml          # Kubernetes DaemonSet manifest
Dockerfile                     # Multi-stage build (scratch final image)
```

## Building

```bash
# Native
go build ./cmd/destroyer

# Linux cross-compile (for container image)
CGO_ENABLED=0 GOOS=linux go build -o destroyer ./cmd/destroyer
```

## Container image

```bash
docker build -t copy-fail-destroyer .
```

## Deployment

The agent must run as a **privileged** pod to unload kernel modules (`CAP_SYS_MODULE`). Deploy as a DaemonSet:

```bash
kubectl apply -f deploy/daemonset.yaml
```

The DaemonSet includes Prometheus scrape annotations (`prometheus.io/scrape: "true"`, port `9100`).