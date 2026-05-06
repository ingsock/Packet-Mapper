# Packet Route Mapper

A fresh live packet mapper built as a Python backend plus a Leaflet frontend.

The app captures TCP, UDP, and ICMP packets, geolocates public IPs with `GeoLite2-City.mmdb`, traces public destinations with ICMP TTL probes, and updates the map in-place through `/api/state`. It does not regenerate HTML, reload the page, or open repeated tabs.

## Features

* Live packet list with source, destination, protocol, and trace status.
* TCP, UDP, and ICMP heat layers.
* Visible geolocated packet points for sparse captures.
* Packet route overlay with directional arrows when at least two geolocated route points exist.
* ICMP traceroute-style hop list.
* Company traffic summary from reverse DNS heuristics.
* Single localhost web page that polls JSON every two seconds.
* Two multi-hop startup demo packets: India to Iraq and United States to Iraq.

## Setup

```bash
pip install -r requirements.txt
```

Keep `GeoLite2-City.mmdb` in this directory.

## Run

Packet capture and ICMP probing need administrator privileges.

Windows:

```bash
python app.py
```

Run that from an Administrator PowerShell or Command Prompt.

Optional interface selection:

```bash
python app.py --iface "Wi-Fi"
```

The app opens one browser tab at `http://127.0.0.1:8765/`.

The first two packets are simulated examples so the map has visible routes immediately when it opens. Live captured packets appear after those examples, and the currently selected packet stays selected when new packets arrive.

## Notes

The app uses city coordinates from the local GeoLite database when they are present. If the database has a public IP record without latitude/longitude, the backend falls back to an approximate registered-country or continent center so the packet can still be represented on the map. Private LAN IPs still cannot be geolocated.

Some routers and firewalls block ICMP responses. In those cases, hops may time out or appear without coordinates.
