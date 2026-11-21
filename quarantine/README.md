# Quarantine Drop Zone

Place untrusted JSONL telemetry exports or log bundles here only for offline parsing via:

```bash
./scripts/sandbox-scan.sh quarantine/<file>.jsonl quarantine/<file>.candidates.json
```

**Never** execute scripts, unpack untrusted binaries, or clone offensive framework forks directly on the host — use a snapshotted KVM/QEMU VM attached to `artex-lab-isolated` (`192.168.250.0/24`) instead. See [docs/quarantine_sop.md](../docs/quarantine_sop.md).
