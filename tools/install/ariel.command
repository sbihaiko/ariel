#!/bin/sh
# Double-click wrapper for macOS: Terminal runs this, which runs the installer.
# A failure keeps the window open, so the message can be read.
here=$(cd "$(dirname "$0")" && pwd)
"$here/ariel.sh" "$@"
status=$?
if [ "$status" -ne 0 ] && [ -t 0 ]; then
  printf '\npress return to close\n'
  read -r _
fi
exit "$status"
