"""
GeoTrace data builder.
  python build_data.py --demo            -> synthetic data, no pcap / no internet needed
  python build_data.py capture.pcap      -> parse a real capture (pcap or pcapng)
Writes frontend/data.json
"""
import sys, os, json, time, random, ipaddress, urllib.request
from collections import defaultdict, deque, Counter

HOME = {"lat": 19.9975, "lng": 73.7898, "country": "India (You)"}   # <- change to your city
OUT = os.path.join("frontend", "data.json")
SCAN_PORTS, SCAN_WINDOW = 20, 10      # >=20 distinct ports in 10 s = port scan
MAX_FLOWS = 400


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_multicast
                or a.is_link_local or a.is_reserved or a.is_unspecified)


def arc(src, dst, sg, dg, proto, packets, size, t, alert=False):
    return {"src": src, "dst": dst, "startLat": sg["lat"], "startLng": sg["lng"],
            "endLat": dg["lat"], "endLng": dg["lng"], "sc": sg["country"], "dc": dg["country"],
            "proto": proto, "packets": packets, "bytes": size, "t": round(t, 2), "alert": alert}


def finish(arcs, alerts, duration, total):
    protos, countries = Counter(), Counter()
    for a in arcs:
        protos[a["proto"]] += a["packets"]
        other = a["dc"] if a["sc"] == HOME["country"] else a["sc"]
        if other != HOME["country"]:
            countries[other] += a["packets"]
    arcs.sort(key=lambda a: a["t"])
    data = {"home": HOME, "duration": max(duration, 1), "total_packets": total,
            "flows": arcs, "alerts": alerts,
            "stats": {"protocols": dict(protos), "countries": countries.most_common(8)}}
    os.makedirs("frontend", exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(data, f)
    print(f"OK: {len(arcs)} arcs, {len(alerts)} alerts, {total} packets -> {OUT}")


# ---------------------------------------------------------------- demo mode
CITIES = {
    "New York": (40.71, -74.0, "United States"), "San Francisco": (37.77, -122.42, "United States"),
    "London": (51.5, -0.12, "United Kingdom"), "Frankfurt": (50.11, 8.68, "Germany"),
    "Singapore": (1.35, 103.82, "Singapore"), "Tokyo": (35.68, 139.69, "Japan"),
    "Sydney": (-33.87, 151.21, "Australia"), "Sao Paulo": (-23.55, -46.63, "Brazil"),
    "Dubai": (25.2, 55.27, "UAE"), "Johannesburg": (-26.2, 28.04, "South Africa"),
    "Moscow": (55.75, 37.62, "Russia"), "Mumbai": (19.07, 72.88, "India"),
}


def rand_ip():
    return f"{random.randint(11, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def make_demo():
    random.seed(7)
    protos = ["HTTPS"] * 5 + ["DNS"] * 2 + ["HTTP", "UDP", "TCP", "ICMP"]
    arcs = []
    for _ in range(160):
        lat, lng, c = CITIES[random.choice(list(CITIES))]
        remote = {"lat": lat, "lng": lng, "country": c}
        a, b, ia, ib = HOME, remote, "192.168.1.10", rand_ip()
        if random.random() < 0.5:
            a, b, ia, ib = b, a, ib, ia
        arcs.append(arc(ia, ib, a, b, random.choice(protos), random.randint(5, 400),
                        random.randint(500, 90000), random.uniform(0, 60)))
    lat, lng, c = CITIES["Moscow"]
    attacker = {"lat": lat, "lng": lng, "country": c}
    for i in range(14):
        arcs.append(arc("203.0.113.66", "192.168.1.10", attacker, HOME, "TCP", 40, 2400, 30 + i * 0.4, True))
    alerts = [{"ip": "203.0.113.66", "country": c, "t": 30.0, "type": "Port scan (20+ ports in 10 s)"}]
    finish(arcs, alerts, 60, sum(a["packets"] for a in arcs))


# ---------------------------------------------------------------- real pcap
def parse_pcap(path):
    from scapy.all import PcapReader, IP, TCP, UDP, ICMP
    flows, windows, scanners = {}, defaultdict(deque), {}
    t0 = last = None
    total = 0
    with PcapReader(path) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            ip, t = pkt[IP], float(pkt.time)
            t0 = t if t0 is None else t0
            last = t
            total += 1
            sport = dport = None
            if TCP in pkt:
                proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
            elif UDP in pkt:
                proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
            elif ICMP in pkt:
                proto = "ICMP"
            else:
                proto = "OTHER"
            ports = {sport, dport}
            if 53 in ports: proto = "DNS"
            elif 443 in ports: proto = "HTTPS"
            elif 80 in ports: proto = "HTTP"

            key = (ip.src, ip.dst, proto)
            f = flows.setdefault(key, {"t": t - t0, "packets": 0, "bytes": 0})
            f["packets"] += 1
            f["bytes"] += len(pkt)

            # port-scan rule: count only SYN-without-ACK packets (new connection attempts)
            if TCP in pkt and (pkt[TCP].flags & 0x12) == 0x02:
                q = windows[ip.src]
                q.append((t, dport))
                while q and t - q[0][0] > SCAN_WINDOW:
                    q.popleft()
                if len({p for _, p in q}) >= SCAN_PORTS and ip.src not in scanners:
                    scanners[ip.src] = t - t0
    if not total:
        sys.exit("No IPv4 packets found in that file.")
    return flows, scanners, total, (last - t0)


def resolve_geo(ips):
    try:
        cache = json.load(open("geo_cache.json"))
    except Exception:
        cache = {}
    todo = [i for i in ips if i not in cache]
    for n in range(0, len(todo), 100):
        batch = todo[n:n + 100]
        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=status,country,lat,lon,query",
                data=json.dumps(batch).encode(), headers={"Content-Type": "application/json"})
            for r in json.load(urllib.request.urlopen(req, timeout=20)):
                cache[r["query"]] = ({"lat": r["lat"], "lng": r["lon"], "country": r["country"]}
                                     if r.get("status") == "success" else None)
        except Exception as e:
            print("Geo lookup failed (check internet):", e)
        if n + 100 < len(todo):
            time.sleep(4.5)                      # free API: 15 batch calls / minute
    json.dump(cache, open("geo_cache.json", "w"))
    return cache


def make_from_pcap(path):
    print("Reading", path, "...")
    flows, scanners, total, duration = parse_pcap(path)
    ranked = sorted(flows.items(), key=lambda kv: -kv[1]["packets"])
    chosen = ranked[:MAX_FLOWS]
    chosen += [kv for kv in ranked[MAX_FLOWS:] if kv[0][0] in scanners][:100]
    ips = {ip for (s, d, _), _ in chosen for ip in (s, d) if is_public(ip)}
    print(f"Resolving {len(ips)} public IPs ...")
    cache = resolve_geo(sorted(ips))
    geo = lambda ip: HOME if not is_public(ip) else cache.get(ip)

    arcs = []
    for (s, d, proto), f in chosen:
        sg, dg = geo(s), geo(d)
        if not sg or not dg or (sg["lat"], sg["lng"]) == (dg["lat"], dg["lng"]):
            continue
        arcs.append(arc(s, d, sg, dg, proto, f["packets"], f["bytes"], f["t"], s in scanners))
    alerts = [{"ip": ip, "country": (geo(ip) or {}).get("country", "Unknown"), "t": round(t, 2),
               "type": f"Port scan ({SCAN_PORTS}+ ports in {SCAN_WINDOW} s)"} for ip, t in scanners.items()]
    finish(arcs, alerts, duration, total)


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == "--demo":
        make_demo()
    else:
        make_from_pcap(sys.argv[1])
