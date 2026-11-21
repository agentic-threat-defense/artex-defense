# Scheduled Local-GPU Watchtower (`systemd` User Timer)

Runs `artex-hunt watchtower --with-gemma4` every **6 hours** with zero cloud token spend:

- Polls **only** strictly allowlisted HTTPS public defensive RSS/Atom feeds and upstream open-source detection repositories.
- Deduplicates against `quarantine/watchtower/state.sqlite` so the local GPU stays completely idle unless genuinely new agentic/IdP/cloud threat intel arrives.
- Never auto-edits rules or touches attacker infrastructure; writes defanged, human-reviewable digests to `quarantine/watchtower/digests/`.

## Install & Enable (User-Level, No Root Required)

```bash
mkdir -p ~/.config/systemd/user
cp scripts/systemd/artex-watchtower.service ~/.config/systemd/user/
cp scripts/systemd/artex-watchtower.timer ~/.config/systemd/user/

# Edit WorkingDirectory/ExecStart if your checkout path differs from ~/Work/artex-defense
systemctl --user daemon-reload
systemctl --user enable --now artex-watchtower.timer

# Inspect schedule or run an immediate one-shot check
systemctl --user list-timers artex-watchtower.timer
systemctl --user start artex-watchtower.service
journalctl --user -u artex-watchtower.service -n 50 --no-pager
```
