#!/bin/sh
# Catch every TCP port on this container's address with one listener.
#
# DNS here answers every query with this container's own IP, so a probe
# container reaching for `api.example.com:443` opens a connection to us on 443,
# and to us on 8080, 25, or anything else it fancies. Binding 65,535 sockets to
# record that is absurd; one REDIRECT rule is not.
#
# NET_ADMIN is required for this and is granted to the sinkhole alone. The probe
# containers — the ones running third-party code — run with every capability
# dropped and never get it.
set -eu

iptables -t nat -A PREROUTING -p tcp --syn -j REDIRECT --to-port 9999

exec python3 /opt/sinkhole/sinkhole.py
