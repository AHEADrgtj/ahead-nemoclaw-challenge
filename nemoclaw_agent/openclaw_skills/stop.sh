#!/usr/bin/env bash
# Kill the running skill runner. The sandbox has no pkill/ps/lsof,
# so we scan /proc directly.
#
# Usage (inside sandbox):
#   bash stop.sh

found=0
for pid in /proc/[0-9]*/; do
  if grep -q uvicorn "$pid/cmdline" 2>/dev/null; then
    p="$(basename "$pid")"
    kill -9 "$p" 2>/dev/null && echo "Killed uvicorn (PID $p)"
    found=1
  fi
done

if [ "$found" -eq 0 ]; then
  echo "No uvicorn process found."
fi
