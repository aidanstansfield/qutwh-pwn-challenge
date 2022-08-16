#!/bin/bash

# Start the process
cd /home/challenge && /usr/bin/socat -dd TCP4-LISTEN:9000,fork,reuseaddr,su=challenge EXEC:/home/challenge/challenge,pty,echo=0,raw,iexten=0 &
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start challenge: $status"
  exit $status
fi

sleep infinity