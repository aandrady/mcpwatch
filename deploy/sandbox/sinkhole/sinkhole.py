"""Catch-all DNS and TCP sinkhole for the sandbox network.

Every probe container is put on an ``--internal`` Docker network with this
container as its only DNS server. Two jobs, and the second one is the reason
this exists rather than just using ``--network none``:

1. **Answer every DNS query with this container's own address.** A server that
   tries to reach ``api.example.com`` gets pointed here instead of failing at
   resolution, so the connection attempt actually happens and can be recorded.

2. **Accept every TCP connection, on every port, and log it.** The network is
   internal, so nothing can leave the host regardless; this turns a blocked
   packet into a *recorded observation*. WP8's brief is explicit that egress
   attempted during mere tool enumeration is itself a finding, and a finding
   needs evidence, not just an absence.

The listener reads a small prefix of whatever the client sends and, when it
looks like a TLS ClientHello, extracts the SNI. That is usually enough to name
the destination the server believed it was talking to, which is what makes an
attempt reportable rather than merely countable.

Never sends anything back. This is not a MITM proxy — it does not terminate TLS
or serve content, because a server that gets a plausible-looking answer may go
further down a code path we have no interest in executing. It absorbs and
records, nothing more. (WP9's divergence harness is where interception belongs.)
"""

import asyncio
import json
import os
import socket
import struct
import sys
import time

DNS_PORT = 53
LOG_PATH = os.environ.get("SINKHOLE_LOG", "/var/log/sinkhole/attempts.jsonl")
PREFIX_BYTES = 2048
"""How much of the client's first write to read before giving up on SNI."""

READ_TIMEOUT = 2.0
"""A client that connects and says nothing is still a recorded attempt."""


def _log(event: dict[str, object]) -> None:
    """Append one event as JSON Lines, flushed immediately.

    Flushed because the probe reads this file after tearing the container down,
    and a buffered final write is exactly the record that would go missing.
    """
    event["at"] = time.time()
    line = json.dumps(event, sort_keys=True)
    with open(LOG_PATH, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()
    print(line, file=sys.stderr, flush=True)


# ------------------------------------------------------------------- TLS SNI ---


def parse_sni(data: bytes) -> str | None:
    """Extract the server name from a TLS ClientHello, or None.

    Deliberately tolerant: this parses attacker-influenced bytes, so every
    length is bounds-checked against the buffer and any malformed structure
    returns None rather than raising. A failed parse costs one unnamed
    destination; an exception here would take down the sinkhole that is
    supposed to be recording it.
    """
    try:
        # TLS record: type(1) version(2) length(2), then handshake:
        # type(1) length(3) version(2) random(32)
        if len(data) < 43 or data[0] != 0x16 or data[5] != 0x01:
            return None
        pos = 43
        session_id_len = data[pos]
        pos += 1 + session_id_len
        cipher_len = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2 + cipher_len
        compression_len = data[pos]
        pos += 1 + compression_len
        if pos + 2 > len(data):
            return None
        extensions_end = pos + 2 + struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2

        while pos + 4 <= min(extensions_end, len(data)):
            ext_type, ext_len = struct.unpack(">HH", data[pos : pos + 4])
            pos += 4
            if ext_type != 0x0000:  # server_name
                pos += ext_len
                continue
            # server_name_list: length(2), then type(1) length(2) host
            if pos + 5 > len(data):
                return None
            name_len = struct.unpack(">H", data[pos + 3 : pos + 5])[0]
            host = data[pos + 5 : pos + 5 + name_len]
            return host.decode("ascii", errors="replace") or None
    except (IndexError, struct.error, UnicodeDecodeError):
        return None
    return None


# ----------------------------------------------------------------------- TCP ---


async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Record one connection attempt, then drop it."""
    peer = writer.get_extra_info("peername") or ("?", 0)
    local = writer.get_extra_info("sockname") or ("?", 0)
    prefix = b""
    try:
        prefix = await asyncio.wait_for(reader.read(PREFIX_BYTES), timeout=READ_TIMEOUT)
    except (TimeoutError, ConnectionError, OSError):
        pass

    _log(
        {
            "kind": "tcp",
            "from_port": peer[1],
            "dest_port": local[1],
            "sni": parse_sni(prefix),
            "bytes": len(prefix),
            # A short prefix of a plaintext request names the destination when
            # there is no SNI to read — an HTTP Host header, most often.
            "prefix": prefix[:200].decode("utf-8", errors="replace") if prefix else None,
        }
    )
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass


class DnsProtocol(asyncio.DatagramProtocol):
    """Answers every A/AAAA query with this container's own address."""

    def __init__(self, address: str) -> None:
        self.address = socket.inet_aton(address)
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Store the transport for replies."""
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Log the question and answer it with our own address."""
        name = _dns_question(data)
        _log({"kind": "dns", "query": name, "from_port": addr[1]})
        reply = _dns_reply(data, self.address)
        if reply and self.transport is not None:
            self.transport.sendto(reply, addr)


def _dns_question(data: bytes) -> str | None:
    """Read the QNAME out of a DNS query, tolerantly."""
    try:
        pos = 12
        labels = []
        while pos < len(data):
            length = data[pos]
            if length == 0:
                break
            pos += 1
            labels.append(data[pos : pos + length].decode("ascii", errors="replace"))
            pos += length
        return ".".join(labels) or None
    except (IndexError, UnicodeDecodeError):
        return None


def _dns_reply(query: bytes, address: bytes) -> bytes | None:
    """Build a minimal A-record answer pointing at ``address``."""
    if len(query) < 12:
        return None
    end = 12
    while end < len(query) and query[end] != 0:
        end += 1 + query[end]
    end += 5  # null label + qtype + qclass
    if end > len(query):
        return None
    header = struct.pack(
        ">HHHHHH",
        struct.unpack(">H", query[0:2])[0],  # id
        0x8180,  # standard response, recursion available
        1,  # questions
        1,  # answers
        0,
        0,
    )
    answer = struct.pack(">HHHIH", 0xC00C, 1, 1, 30, 4) + address
    return header + query[12:end] + answer


async def main() -> None:
    """Serve DNS and a catch-all TCP listener until killed."""
    address = socket.gethostbyname(socket.gethostname())
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    _log({"kind": "start", "address": address})

    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(
        lambda: DnsProtocol(address), local_addr=("0.0.0.0", DNS_PORT)
    )

    # One listener per port would need 65,535 sockets. This container's own
    # entrypoint installs an iptables REDIRECT sending every TCP destination
    # port here, so a single socket catches everything. NET_ADMIN is granted to
    # *this* container to do that — never to a probe container, which is the one
    # running untrusted code.
    server = await asyncio.start_server(handle_tcp, "0.0.0.0", 9999)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
