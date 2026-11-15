#!/system/bin/sh
# mem.sh — fast read of the game's memory (block reads when page-aligned).
# usage: sh mem.sh <DECIMAL_addr> <byte_count>
PID=$(pidof com.axlebolt.standoff2 | tr ' ' '\n' | sort -n | head -1)
OFF=$1
LEN=$2
if [ $((OFF % 4096)) -eq 0 ] && [ $((LEN % 4096)) -eq 0 ]; then
  exec dd if=/proc/$PID/mem bs=4096 skip=$((OFF / 4096)) count=$((LEN / 4096)) 2>/dev/null
else
  exec dd if=/proc/$PID/mem skip=$OFF ibs=1 count=$LEN 2>/dev/null
fi
