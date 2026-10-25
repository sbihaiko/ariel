#!/bin/sh
# `make test` at the repository root sends ariel-ps5.elf to a console. It must
# refuse unless ARIEL_DEPLOY=yes is given on purpose, and refuse before the
# SDK is read or anything is built, so an agent that runs it by habit touches
# nothing.
root=$(cd "$(dirname "$0")/../.." && pwd)

out=$(env -u ARIEL_DEPLOY PS5_DEPLOY=false make -s -C "$root" test 2>&1)
if [ $? -eq 0 ]; then
	echo "FAIL make test without ARIEL_DEPLOY=yes ran: $out"
	exit 1
fi
case $out in
*ARIEL_DEPLOY=yes*) ;;
*)
	echo "FAIL make test without ARIEL_DEPLOY=yes did not name the switch: $out"
	exit 1
	;;
esac
echo "PASS make test refuses to deploy without ARIEL_DEPLOY=yes"

out=$(PS5_DEPLOY=false make -s -C "$root" test ARIEL_DEPLOY=no 2>&1)
if [ $? -eq 0 ] || ! printf '%s' "$out" | grep -q 'ARIEL_DEPLOY=yes'; then
	echo "FAIL make test with ARIEL_DEPLOY=no was not refused: $out"
	exit 1
fi
echo "PASS make test refuses ARIEL_DEPLOY=no"
