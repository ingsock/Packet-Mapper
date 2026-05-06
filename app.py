from __future__ import annotations

import argparse
import functools
import http.server
import ipaddress
import json
import os
import queue
import socket
import threading
import time
import webbrowser
from collections import Counter, deque
from itertools import count
from pathlib import Path
from urllib.parse import urlparse

import geoip2.database
import geoip2.errors
from scapy.all import ICMP, IP, TCP, UDP, sniff, sr1


BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"
GEO_DB_PATH = BASE_DIR / "GeoLite2-City.mmdb"

HOST = "127.0.0.1"
PORT = 8765

MAX_PACKETS = 500
MAX_PINNED_PACKETS = 100
MAX_TRACE_HOPS = 30
TRACE_TIMEOUT_SECONDS = 1.2
TRACE_QUEUE_SIZE = 128
TRACE_ICMP_ID = 0xC0DE

PROTOCOLS = ("tcp", "udp", "icmp")
packet_counter = count(1)

state_lock = threading.Lock()
packets = deque(maxlen=MAX_PACKETS)
pinned_packets = {}
locations = {protocol: Counter() for protocol in PROTOCOLS}
companies = Counter()
route_cache = {}
route_waiting = {}
pending_traces = set()
urgent_traces = set()
trace_queue = queue.Queue(maxsize=TRACE_QUEUE_SIZE)
hostname_cache = {}

geo_reader = None

COMPANY_MAPPINGS = {
    "google": "Google",
    "1e100": "Google",
    "youtube": "Google",
    "facebook": "Meta",
    "fbcdn": "Meta",
    "instagram": "Meta",
    "whatsapp": "Meta",
    "amazon": "Amazon",
    "aws": "Amazon",
    "cloudfront": "Amazon",
    "microsoft": "Microsoft",
    "azure": "Microsoft",
    "live": "Microsoft",
    "office": "Microsoft",
    "apple": "Apple",
    "icloud": "Apple",
    "netflix": "Netflix",
    "akamai": "Akamai",
    "cloudflare": "Cloudflare",
}

COUNTRY_CENTROIDS = {
    "AE": [23.4241, 53.8478],
    "AU": [-25.2744, 133.7751],
    "BR": [-14.235, -51.9253],
    "CA": [56.1304, -106.3468],
    "CN": [35.8617, 104.1954],
    "DE": [51.1657, 10.4515],
    "EG": [26.8206, 30.8025],
    "ES": [40.4637, -3.7492],
    "FR": [46.2276, 2.2137],
    "GB": [55.3781, -3.436],
    "HK": [22.3193, 114.1694],
    "ID": [-0.7893, 113.9213],
    "IE": [53.1424, -7.6921],
    "IN": [20.5937, 78.9629],
    "IQ": [33.2232, 43.6793],
    "IR": [32.4279, 53.688],
    "IT": [41.8719, 12.5674],
    "JP": [36.2048, 138.2529],
    "KR": [35.9078, 127.7669],
    "NL": [52.1326, 5.2913],
    "QA": [25.3548, 51.1839],
    "RU": [61.524, 105.3188],
    "SA": [23.8859, 45.0792],
    "SG": [1.3521, 103.8198],
    "TR": [38.9637, 35.2433],
    "US": [37.751, -97.822],
}

CONTINENT_CENTROIDS = {
    "AF": [1.6508, 17.6791],
    "AS": [34.0479, 100.6197],
    "EU": [54.526, 15.2551],
    "NA": [54.526, -105.2551],
    "OC": [-22.7359, 140.0188],
    "SA": [-8.7832, -55.4915],
}

DEMO_ROUTES = [
    {
        "protocol": "tcp",
        "source": {
            "ip": "103.21.244.10",
            "hostname": "simulated-india.example",
            "company": "Demo",
            "coords": [20.5937, 78.9629],
            "coords_source": "simulated",
            "geo_label": "India simulated origin",
            "country": "India",
            "public": True,
        },
        "destination": {
            "ip": "185.76.32.10",
            "hostname": "simulated-iraq.example",
            "company": "Demo",
            "coords": [33.2232, 43.6793],
            "coords_source": "simulated",
            "geo_label": "Iraq simulated destination",
            "country": "Iraq",
            "public": True,
        },
        "hops": [
            {
                "ttl": 1,
                "ip": "103.21.244.1",
                "hostname": "simulated-india-gateway.example",
                "coords": [20.5937, 78.9629],
                "coords_source": "simulated",
                "geo_label": "India simulated gateway",
            },
            {
                "ttl": 2,
                "ip": "103.30.0.1",
                "hostname": "simulated-mumbai-core.example",
                "coords": [19.076, 72.8777],
                "coords_source": "simulated",
                "geo_label": "Mumbai simulated core",
            },
            {
                "ttl": 3,
                "ip": "94.200.0.1",
                "hostname": "simulated-uae-transit.example",
                "coords": [25.2048, 55.2708],
                "coords_source": "simulated",
                "geo_label": "Dubai simulated transit",
            },
            {
                "ttl": 4,
                "ip": "82.148.0.1",
                "hostname": "simulated-qatar-transit.example",
                "coords": [25.2854, 51.531],
                "coords_source": "simulated",
                "geo_label": "Doha simulated transit",
            },
            {
                "ttl": 5,
                "ip": "185.76.32.1",
                "hostname": "simulated-iraq-edge.example",
                "coords": [33.3128, 44.3615],
                "coords_source": "simulated",
                "geo_label": "Baghdad simulated edge",
            },
            {
                "ttl": 6,
                "ip": "185.76.32.1",
                "hostname": "simulated-iraq-destination.example",
                "coords": [33.2232, 43.6793],
                "coords_source": "simulated",
                "geo_label": "Iraq simulated destination",
            },
        ],
    },
    {
        "protocol": "udp",
        "source": {
            "ip": "8.8.8.8",
            "hostname": "simulated-us.example",
            "company": "Demo",
            "coords": [37.751, -97.822],
            "coords_source": "simulated",
            "geo_label": "United States simulated origin",
            "country": "United States",
            "public": True,
        },
        "destination": {
            "ip": "185.76.32.20",
            "hostname": "simulated-iraq.example",
            "company": "Demo",
            "coords": [33.2232, 43.6793],
            "coords_source": "simulated",
            "geo_label": "Iraq simulated destination",
            "country": "Iraq",
            "public": True,
        },
        "hops": [
            {
                "ttl": 1,
                "ip": "8.8.8.1",
                "hostname": "simulated-us-gateway.example",
                "coords": [37.751, -97.822],
                "coords_source": "simulated",
                "geo_label": "United States simulated gateway",
            },
            {
                "ttl": 2,
                "ip": "198.51.100.1",
                "hostname": "simulated-new-york-transit.example",
                "coords": [40.7128, -74.006],
                "coords_source": "simulated",
                "geo_label": "New York simulated transit",
            },
            {
                "ttl": 3,
                "ip": "203.0.113.44",
                "hostname": "simulated-london-transit.example",
                "coords": [51.5072, -0.1276],
                "coords_source": "simulated",
                "geo_label": "London simulated transit",
            },
            {
                "ttl": 4,
                "ip": "203.0.113.49",
                "hostname": "simulated-frankfurt-transit.example",
                "coords": [50.1109, 8.6821],
                "coords_source": "simulated",
                "geo_label": "Frankfurt simulated transit",
            },
            {
                "ttl": 5,
                "ip": "203.0.113.90",
                "hostname": "simulated-istanbul-transit.example",
                "coords": [41.0082, 28.9784],
                "coords_source": "simulated",
                "geo_label": "Istanbul simulated transit",
            },
            {
                "ttl": 6,
                "ip": "185.76.32.1",
                "hostname": "simulated-baghdad-edge.example",
                "coords": [33.3128, 44.3615],
                "coords_source": "simulated",
                "geo_label": "Baghdad simulated edge",
            },
            {
                "ttl": 7,
                "ip": "185.76.32.1",
                "hostname": "simulated-iraq-destination.example",
                "coords": [33.2232, 43.6793],
                "coords_source": "simulated",
                "geo_label": "Iraq simulated destination",
            },
        ],
    },
]


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def lookup_geo(ip: str) -> dict:
    result = {
        "coords": None,
        "source": "none",
        "label": "not geolocated",
        "country": None,
    }
    if not is_public_ip(ip) or geo_reader is None:
        return result

    try:
        response = geo_reader.city(ip)
    except geoip2.errors.AddressNotFoundError:
        return result

    country = response.country.name or response.registered_country.name
    result["country"] = country

    lat = response.location.latitude
    lon = response.location.longitude
    if lat is not None and lon is not None:
        city = response.city.name
        place = ", ".join(part for part in (city, country) if part)
        result.update(
            {
                "coords": [lat, lon],
                "source": "city",
                "label": place or "GeoLite city coordinate",
            }
        )
        return result

    country_code = response.country.iso_code or response.registered_country.iso_code
    if country_code in COUNTRY_CENTROIDS:
        result.update(
            {
                "coords": COUNTRY_CENTROIDS[country_code],
                "source": "registered_country",
                "label": f"{country_code} approximate country center",
            }
        )
        return result

    continent_code = response.continent.code
    if continent_code in CONTINENT_CENTROIDS:
        result.update(
            {
                "coords": CONTINENT_CENTROIDS[continent_code],
                "source": "continent",
                "label": f"{continent_code} approximate continent center",
            }
        )

    return result


def get_coords(ip: str) -> list[float] | None:
    return lookup_geo(ip)["coords"]


def get_hostname(ip: str) -> str:
    if ip in hostname_cache:
        return hostname_cache[ip]

    previous_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(0.8)
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.timeout, OSError):
        hostname = "Unknown"
    finally:
        socket.setdefaulttimeout(previous_timeout)

    hostname_cache[ip] = hostname
    return hostname


def classify_company(hostname: str) -> str:
    if not hostname or hostname == "Unknown":
        return "Other"

    hostname_lower = hostname.lower()
    for keyword, company in COMPANY_MAPPINGS.items():
        if keyword in hostname_lower:
            return company
    return "Other"


def location_key(coords: list[float]) -> tuple[float, float]:
    return (round(coords[0], 5), round(coords[1], 5))


def make_endpoint(ip: str) -> dict:
    hostname = get_hostname(ip)
    geo = lookup_geo(ip)
    return {
        "ip": ip,
        "hostname": hostname,
        "company": classify_company(hostname),
        "coords": geo["coords"],
        "coords_source": geo["source"],
        "geo_label": geo["label"],
        "country": geo["country"],
        "public": is_public_ip(ip),
    }


def route_points(packet: dict, hops: list[dict]) -> list[list[float]]:
    points = []

    def add_point(coords):
        if coords and (not points or points[-1] != coords):
            points.append(coords)

    add_point(packet["source"]["coords"])
    for hop in hops:
        add_point(hop.get("coords"))
    add_point(packet["destination"]["coords"])
    return points


def store_packet(packet: dict) -> None:
    with state_lock:
        packets.append(packet)
        for endpoint_name in ("source", "destination"):
            endpoint = packet[endpoint_name]
            coords = endpoint["coords"]
            if not coords:
                continue

            locations[packet["protocol"]][location_key(coords)] += 1
            companies[endpoint["company"]] += 1


def seed_demo_packets() -> None:
    """
    Adds two deterministic startup examples so the UI has routes immediately.
    """
    for index, demo in enumerate(DEMO_ROUTES, start=1):
        packet = {
            "id": next(packet_counter),
            "protocol": demo["protocol"],
            "captured_at": f"demo-{index}",
            "source": demo["source"],
            "destination": demo["destination"],
            "route": {
                "status": "simulated",
                "hops": demo["hops"],
                "points": route_points(demo, demo["hops"]),
            },
            "simulated": True,
        }
        store_packet(packet)


def unique_packets_locked() -> list[dict]:
    packet_list = list(packets)
    seen_ids = {packet["id"] for packet in packet_list}
    packet_list.extend(
        packet
        for packet_id, packet in pinned_packets.items()
        if packet_id not in seen_ids
    )
    return packet_list


def find_packet_locked(packet_id: int) -> dict | None:
    for packet in packets:
        if packet["id"] == packet_id:
            return packet
    return pinned_packets.get(packet_id)


def pin_packet_locked(packet: dict) -> None:
    pinned_packets[packet["id"]] = packet
    while len(pinned_packets) > MAX_PINNED_PACKETS:
        pinned_packets.pop(next(iter(pinned_packets)))


def update_packet_route(packet_id: int, hops: list[dict], status: str) -> None:
    with state_lock:
        packet = find_packet_locked(packet_id)
        if packet is None:
            return
        packet["route"] = {
            "status": status,
            "hops": hops,
            "points": route_points(packet, hops),
        }


def trace_target_ip(packet: dict) -> str | None:
    if packet["destination"]["public"]:
        return packet["destination"]["ip"]
    if packet["source"]["public"]:
        return packet["source"]["ip"]
    return None


def queue_trace(packet: dict) -> None:
    destination_ip = trace_target_ip(packet)
    if destination_ip is None or not packet["destination"]["public"]:
        return

    with state_lock:
        cached_hops = route_cache.get(destination_ip)
        if cached_hops is not None:
            packet["route"] = {
                "status": "trace complete",
                "hops": cached_hops,
                "points": route_points(packet, cached_hops),
            }
            return

        route_waiting.setdefault(destination_ip, []).append(packet["id"])
        if destination_ip in pending_traces:
            return
        pending_traces.add(destination_ip)

    try:
        trace_queue.put_nowait(destination_ip)
    except queue.Full:
        with state_lock:
            pending_traces.discard(destination_ip)
            waiting_ids = route_waiting.pop(destination_ip, [])
        for packet_id in waiting_ids:
            update_packet_route(packet_id, [], "trace queue full")


def finish_trace(
    destination_ip: str, hops: list[dict], status: str, urgent: bool = False
) -> None:
    with state_lock:
        route_cache[destination_ip] = hops
        waiting_ids = route_waiting.pop(destination_ip, [])
        pending_traces.discard(destination_ip)
        if urgent:
            urgent_traces.discard(destination_ip)

    for packet_id in waiting_ids:
        update_packet_route(packet_id, hops, status)


def update_trace_progress(destination_ip: str, hops: list[dict]) -> None:
    hop_snapshot = [dict(hop) for hop in hops]
    status = f"trace in progress ({len(hop_snapshot)} hop"
    if len(hop_snapshot) != 1:
        status += "s"
    status += ")"

    with state_lock:
        waiting_ids = set(route_waiting.get(destination_ip, []))
        for packet in unique_packets_locked():
            if packet["id"] in waiting_ids:
                packet["route"] = {
                    "status": status,
                    "hops": hop_snapshot,
                    "points": route_points(packet, hop_snapshot),
                }


def trace_route(destination_ip: str, on_progress=None) -> list[dict]:
    print(f"Tracing {destination_ip} with ICMP...")
    hops = []

    for ttl in range(1, MAX_TRACE_HOPS + 1):
        try:
            reply = sr1(
                IP(dst=destination_ip, ttl=ttl) / ICMP(id=TRACE_ICMP_ID, seq=ttl),
                timeout=TRACE_TIMEOUT_SECONDS,
                verbose=False,
            )
        except (PermissionError, OSError) as exc:
            print(f"ICMP trace failed for {destination_ip}: {exc}")
            break

        if reply is None or IP not in reply:
            hops.append(
                {
                    "ttl": ttl,
                    "ip": None,
                    "hostname": "Timed out",
                    "coords": None,
                    "coords_source": "none",
                    "geo_label": "not geolocated",
                    "public": False,
                }
            )
            if on_progress is not None:
                on_progress(hops)
            continue

        hop_ip = reply[IP].src
        geo = lookup_geo(hop_ip)
        hops.append(
            {
                "ttl": ttl,
                "ip": hop_ip,
                "hostname": get_hostname(hop_ip),
                "coords": geo["coords"],
                "coords_source": geo["source"],
                "geo_label": geo["label"],
                "public": is_public_ip(hop_ip),
            }
        )
        if on_progress is not None:
            on_progress(hops)

        if hop_ip == destination_ip or (ICMP in reply and reply[ICMP].type == 0):
            break

    return hops


def execute_trace(destination_ip: str) -> tuple[list[dict], str]:
    try:
        return trace_route(
            destination_ip,
            on_progress=lambda hops: update_trace_progress(destination_ip, hops),
        ), "trace complete"
    except Exception as exc:
        print(f"Trace error for {destination_ip}: {exc}")
        return [], "trace failed"


def complete_from_cache(destination_ip: str) -> bool:
    with state_lock:
        cached_hops = route_cache.get(destination_ip)
        if cached_hops is None:
            return False
        waiting_ids = route_waiting.pop(destination_ip, [])
        pending_traces.discard(destination_ip)

    for packet_id in waiting_ids:
        update_packet_route(packet_id, cached_hops, "trace complete")
    return True


def urgent_trace_worker(destination_ip: str) -> None:
    hops, status = execute_trace(destination_ip)
    finish_trace(destination_ip, hops, status, urgent=True)


def start_selected_trace(packet_id: int) -> tuple[int, dict]:
    with state_lock:
        packet = find_packet_locked(packet_id)
        if packet is None:
            return 404, {"error": "Packet not found"}
        pin_packet_locked(packet)

        if packet.get("simulated"):
            return 200, {"status": "selected", "trace_ip": None}

        destination_ip = trace_target_ip(packet)
        if destination_ip is None:
            return 400, {"error": "Packet has no public IP to trace"}

        if packet["route"].get("status") == "trace complete":
            return 200, {"status": "selected", "trace_ip": destination_ip}

        cached_hops = route_cache.get(destination_ip)
        if cached_hops is not None:
            packet["route"] = {
                "status": "trace complete",
                "hops": cached_hops,
                "points": route_points(packet, cached_hops),
            }
            return 200, {"status": "cached", "trace_ip": destination_ip}

        waiting_ids = route_waiting.setdefault(destination_ip, [])
        if packet_id not in waiting_ids:
            waiting_ids.append(packet_id)
        packet["route"]["status"] = "selected trace pending"
        pending_traces.add(destination_ip)

        if destination_ip in urgent_traces:
            return 202, {"status": "already tracing", "trace_ip": destination_ip}
        urgent_traces.add(destination_ip)

    threading.Thread(
        target=urgent_trace_worker, args=(destination_ip,), daemon=True
    ).start()
    return 202, {"status": "started", "trace_ip": destination_ip}


def trace_worker() -> None:
    while True:
        destination_ip = trace_queue.get()
        try:
            if complete_from_cache(destination_ip):
                continue

            hops, status = execute_trace(destination_ip)
            finish_trace(destination_ip, hops, status)
        finally:
            trace_queue.task_done()


def protocol_for(packet) -> str | None:
    if TCP in packet:
        return "tcp"
    if UDP in packet:
        return "udp"
    if ICMP in packet:
        return "icmp"
    return None


def ignore_own_probe(packet) -> bool:
    if ICMP not in packet:
        return False
    if packet[ICMP].type not in (0, 8):
        return False
    return getattr(packet[ICMP], "id", None) == TRACE_ICMP_ID


def process_packet(raw_packet) -> None:
    if IP not in raw_packet or ignore_own_probe(raw_packet):
        return

    protocol = protocol_for(raw_packet)
    if protocol is None:
        return

    source = make_endpoint(raw_packet[IP].src)
    destination = make_endpoint(raw_packet[IP].dst)
    if not source["public"] and not destination["public"]:
        return

    packet = {
        "id": next(packet_counter),
        "protocol": protocol,
        "captured_at": time.strftime("%H:%M:%S"),
        "source": source,
        "destination": destination,
        "route": {
            "status": "trace pending" if destination["public"] else "not public",
            "hops": [],
            "points": route_points({"source": source, "destination": destination}, []),
        },
    }

    store_packet(packet)
    queue_trace(packet)
    public_ips = [
        endpoint["ip"] for endpoint in (source, destination) if endpoint["public"]
    ]
    print(f"#{packet['id']} {protocol.upper()} {' -> '.join(public_ips)}")


def heatmap_points() -> dict[str, list[list[float]]]:
    data = {}
    for protocol, counter in locations.items():
        data[protocol] = [
            [coords[0], coords[1], count] for coords, count in counter.items()
        ]
    return data


def marker_points() -> list[dict]:
    by_location = {}
    for packet in packets:
        for endpoint_name in ("source", "destination"):
            endpoint = packet[endpoint_name]
            coords = endpoint["coords"]
            if not coords:
                continue

            key = location_key(coords)
            entry = by_location.setdefault(
                key,
                {
                    "coords": [key[0], key[1]],
                    "count": 0,
                    "items": [],
                },
            )
            entry["count"] += 1
            if len(entry["items"]) < 8:
                entry["items"].append(
                    {
                        "protocol": packet["protocol"],
                        "direction": endpoint_name,
                        "ip": endpoint["ip"],
                        "hostname": endpoint["hostname"],
                        "geo_label": endpoint["geo_label"],
                        "coords_source": endpoint["coords_source"],
                    }
                )

    return list(by_location.values())


def has_public_endpoint(packet: dict) -> bool:
    return packet["source"]["public"] or packet["destination"]["public"]


def snapshot() -> dict:
    with state_lock:
        packet_list = [
            packet for packet in unique_packets_locked() if has_public_endpoint(packet)
        ]
        return {
            "updated_at": time.strftime("%H:%M:%S"),
            "packets": packet_list,
            "heatmap": heatmap_points(),
            "markers": marker_points(),
            "companies": companies.most_common(),
            "totals": {
                "packets": len(packet_list),
                "geolocated_points": sum(
                    sum(counter.values()) for counter in locations.values()
                ),
                "pending_traces": len(pending_traces),
            },
        }


class AppHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def send_json(self, status_code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/state":
            self.send_json(200, snapshot())
            return

        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        if path == "/":
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/trace":
            self.send_json(404, {"error": "Not found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = 0

        try:
            body = self.rfile.read(content_length) if content_length else b"{}"
            data = json.loads(body.decode("utf-8") or "{}")
            packet_id = int(data["packet_id"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Expected JSON body with packet_id"})
            return

        status_code, payload = start_selected_trace(packet_id)
        self.send_json(status_code, payload)

    def log_message(self, format, *args):
        return


def start_server(host: str, port: int):
    for candidate_port in range(port, port + 20):
        try:
            server = http.server.ThreadingHTTPServer(
                (host, candidate_port), AppHandler
            )
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            return server, f"http://{host}:{candidate_port}/"
        except OSError:
            continue
    raise RuntimeError("Could not bind a local HTTP port")


def start_sniffer(interface: str | None) -> None:
    print("Starting packet sniffer...")
    kwargs = {"prn": process_packet, "store": False}
    if interface:
        kwargs["iface"] = interface
    sniff(**kwargs)


def init_geoip() -> None:
    global geo_reader
    if not GEO_DB_PATH.exists():
        raise FileNotFoundError(f"Missing GeoLite database: {GEO_DB_PATH}")
    geo_reader = geoip2.database.Reader(str(GEO_DB_PATH))


def parse_args():
    parser = argparse.ArgumentParser(description="Live packet route mapper")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--iface", default=None, help="Optional Scapy interface")
    parser.add_argument(
        "--no-browser", action="store_true", help="Do not open the browser"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    init_geoip()
    seed_demo_packets()

    threading.Thread(target=trace_worker, daemon=True).start()
    threading.Thread(
        target=start_sniffer, args=(args.iface,), daemon=True
    ).start()

    server, url = start_server(args.host, args.port)
    print(f"Serving live map at {url}")
    if not args.no_browser:
        webbrowser.open(url)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        server.shutdown()
        if geo_reader is not None:
            geo_reader.close()


if __name__ == "__main__":
    main()
