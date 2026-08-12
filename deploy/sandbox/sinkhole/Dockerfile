# The sinkhole: the only container on the sandbox network that is ours.
#
# Trusted, unlike everything else that joins that network, so it is the one
# place NET_ADMIN is granted — it needs a single iptables REDIRECT to catch
# every TCP port on one socket.
FROM python:3.13-alpine

RUN apk add --no-cache iptables

COPY sinkhole.py /opt/sinkhole/sinkhole.py
COPY entrypoint.sh /opt/sinkhole/entrypoint.sh
RUN chmod +x /opt/sinkhole/entrypoint.sh && mkdir -p /var/log/sinkhole

ENTRYPOINT ["/opt/sinkhole/entrypoint.sh"]
