#!/bin/sh
# Labelled verify test: runs examples/verify once per attempt so the
# "Verify again?" prompt never gets in the way, and records which finger was
# used before each attempt. Analyse the log with verify_analysis.py.
#
# Usage (from the build directory): verify-loop.sh [FINGER_INDEX] [LOG]
#   FINGER_INDEX  menu index of the enrolled finger in examples/verify (6 = right index)
#   LOG           output log (default: ./verify-loop.log)

finger=${1:-6}
log=${2:-verify-loop.log}
: > "$log"

i=1
while [ "$i" -le 30 ]; do
  printf 'Attempt %s - lift your finger, then type e (enrolled finger), o (other finger), p (other person) or q (quit): ' "$i"
  read -r who
  [ "$who" = q ] && break
  echo "=== attempt $i finger=$who" >> "$log"
  printf '%s\nn\n' "$finger" | ./examples/verify 2>&1 | tee -a "$log" |
    grep --line-buffered -E 'Waiting for finger down|MATCH|SIGFM score|Failed to verify'
  i=$((i + 1))
done
