"""
pi-sentinel-interface :: simulator/mock_traffic.py

Virtual Raspberry Pi sensor node. Runs forever, generating randomized
local-subnet packet metadata (TCP / UDP / ICMP / ARP) and POSTing it in
batches to the backend every 2 seconds.

Usage:
    python simulator/mock_traffic.py
    python simulator/mock_traffic.py --url http://localhost:5000/api/v1/logs --interval 2
"""

import argparse
import random
import sys
import time
from datetime import datetime, timezone

import requests

DEFAULT_URL = "http://localhost:5000/api/v1/logs"
DEFAULT_INTERVAL = 2.0
NODE_ID = "pi-sentinel-node-01"

SUBNET_PREFIX = "192.168.1."
GATEWAY_IP = SUBNET_PREFIX + "1"
BROADCAST_IP = SUBNET_PREFIX + "255"

# A handful of "known" LAN hosts so the unique-IP KPI looks realistic.
LOCAL_HOSTS = [SUBNET_PREFIX + str(octet) for octet in (10, 11, 12, 20, 25, 33, 42, 55, 67, 80, 101, 150, 200, 223)]

# A few external addresses for traffic leaving the LAN.
EXTERNAL_HOSTS = ["8.8.8.8", "1.1.1.1", "142.250.190.78", "151.101.1.69", "104.16.132.229", "13.107.42.14"]

# Weighted protocol mix (roughly typical for a home/office LAN).
PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP"]
PROTOCOL_WEIGHTS = [55, 28, 7, 10]


def utc_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def pick_local():
    return random.choice(LOCAL_HOSTS)


def pick_peer(exclude):
    """Pick a destination: mostly local/gateway, sometimes external."""
    roll = random.random()
    if roll < 0.45:
        candidates = [ip for ip in LOCAL_HOSTS + [GATEWAY_IP] if ip != exclude]
        return random.choice(candidates)
    if roll < 0.85:
        return random.choice(EXTERNAL_HOSTS)
    return GATEWAY_IP


def make_packet():
    protocol = random.choices(PROTOCOLS, weights=PROTOCOL_WEIGHTS, k=1)[0]
    source_ip = pick_local()

    if protocol == "ARP":
        # ARP who-has / is-at on the LAN; frames are small and fixed-ish.
        destination_ip = BROADCAST_IP if random.random() < 0.6 else pick_peer(source_ip)
        if destination_ip in EXTERNAL_HOSTS:
            destination_ip = GATEWAY_IP
        packet_size = random.choice([42, 60])
    elif protocol == "ICMP":
        destination_ip = pick_peer(source_ip)
        packet_size = random.choice([64, 74, 84, 98, 128])
    elif protocol == "UDP":
        destination_ip = pick_peer(source_ip)
        packet_size = random.choice([
            random.randint(60, 140),     # DNS / NTP style
            random.randint(140, 600),    # small media / game traffic
            random.randint(600, 1400),   # QUIC / streaming
        ])
    else:  # TCP
        destination_ip = pick_peer(source_ip)
        packet_size = random.choice([
            54,                          # bare ACK
            random.randint(60, 200),
            random.randint(200, 800),
            1514,                        # full MTU segment
            random.randint(1000, 1500),
        ])

    # Occasionally have an external host respond to a LAN host (inbound flow).
    if protocol in ("TCP", "UDP", "ICMP") and random.random() < 0.25:
        source_ip, destination_ip = (
            (random.choice(EXTERNAL_HOSTS), pick_local())
            if destination_ip in EXTERNAL_HOSTS
            else (destination_ip, source_ip)
        )

    return {
        "timestamp": utc_iso(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "packet_size": int(packet_size),
    }


def make_batch():
    # Vary the batch size so the dashboard feels alive; add the occasional burst.
    size = random.randint(8, 30)
    if random.random() < 0.08:
        size = random.randint(60, 120)
    return [make_packet() for _ in range(size)]


def main():
    parser = argparse.ArgumentParser(description="Virtual Raspberry Pi traffic simulator")
    parser.add_argument("--url", default=DEFAULT_URL, help="Backend ingest endpoint")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL, help="Seconds between batches")
    args = parser.parse_args()

    print(f"[{NODE_ID}] Simulator started -> {args.url} (every {args.interval}s). Press Ctrl+C to stop.")

    session = requests.Session()
    batch_number = 0

    try:
        while True:
            started = time.monotonic()
            batch = make_batch()
            batch_number += 1
            payload = {"node_id": NODE_ID, "logs": batch}

            try:
                response = session.post(args.url, json=payload, timeout=5)
                if response.status_code in (200, 201):
                    body = response.json()
                    print(
                        f"[{datetime.now().strftime('%H:%M:%S')}] batch #{batch_number}: "
                        f"sent {len(batch)} packets, accepted {body.get('accepted')} "
                        f"(storage: {body.get('storage_mode')})"
                    )
                else:
                    print(
                        f"[{datetime.now().strftime('%H:%M:%S')}] batch #{batch_number}: "
                        f"server returned HTTP {response.status_code}: {response.text[:200]}",
                        file=sys.stderr,
                    )
            except requests.exceptions.ConnectionError:
                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] backend unreachable at {args.url}; will retry...",
                    file=sys.stderr,
                )
            except requests.exceptions.Timeout:
                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] request timed out; will retry...",
                    file=sys.stderr,
                )
            except requests.exceptions.RequestException as exc:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] request error: {exc}", file=sys.stderr)

            elapsed = time.monotonic() - started
            time.sleep(max(0.0, args.interval - elapsed))
    except KeyboardInterrupt:
        print(f"\n[{NODE_ID}] Simulator stopped after {batch_number} batches.")


if __name__ == "__main__":
    main()
