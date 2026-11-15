#!/system/bin/sh
# memw.sh — write bytes to the game's memory.
# usage: cat bytes | sh memw.sh <DECIMAL_addr>
PID=$(pidof com.axlebolt.standoff2 | tr ' ' '\n' | sort -n | head -1)
exec dd of=/proc/$PID/mem seek=$1 bs=1 2>/dev/null
