#!/bin/sh

TIMEOUT=240
default_file=output.txt

DEBUG_FLAGS="-DPERF_TEST"

if [ $# -gt 1 ]; then
	echo "Usage: $0 (outputfile)"
	exit 1
fi

if [ $# -eq 1 ]; then
	if [ -e $1 ] && [ ! -f $1 ]; then
		echo "$1 is not a file"
		exit 1
	fi
	file=$1
else
	file=$default_file
fi

Perf_Test () {
	echo Xvmm | make qemu-nox DEBUG_CFLAGS="$2" | while IFS= read -r line; do printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S:%3N')" "$line"; done > $1
}

Timeout () {
	sleep $TIMEOUT && killall qemu-system-x86_64
}

echo "SPT Performance Test"
Timeout & Perf_Test $file "$DEBUG_FLAGS"
echo "End of SPT Performance Test"

exit 0
