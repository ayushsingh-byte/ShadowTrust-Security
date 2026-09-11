# Throwaway attacker box for scripts/populate_lab.sh — drives real traffic at the
# honeynet sensors so the pipeline produces genuine telemetry, detections and
# incidents. Never exposed; only ever run on the internal honeynet_edge network.
FROM alpine:3.19
RUN apk add --no-cache openssh-client sshpass nmap nmap-ncat curl bind-tools coreutils
RUN printf 'Host *\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  ConnectTimeout 6\n  PreferredAuthentications password\n  LogLevel ERROR\n' > /etc/ssh/ssh_config
ENTRYPOINT ["/bin/sh","-c"]
