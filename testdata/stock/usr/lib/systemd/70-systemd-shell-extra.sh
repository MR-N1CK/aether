# Shell extra for systemd
if [ -n "$SSH_TTY" ]; then
    eval "$(/usr/lib/systemd/systemd-sysv-install is-active 2>/dev/null || true)"
fi
