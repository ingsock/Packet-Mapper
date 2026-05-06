const map = L.map("map", {
  worldCopyJump: true,
  zoomControl: true,
}).setView([20, 0], 2);

L.tileLayer("https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png", {
  attribution: "&copy; OpenStreetMap contributors &copy; CARTO",
  subdomains: "abcd",
  maxZoom: 19,
}).addTo(map);

const heatLayers = {
  tcp: L.heatLayer([], heatOptions("#ef4444")).addTo(map),
  udp: L.heatLayer([], heatOptions("#2563eb")).addTo(map),
  icmp: L.heatLayer([], heatOptions("#16a34a")).addTo(map),
};
const heatLayerProtocols = new Map(
  Object.entries(heatLayers).map(([protocol, layer]) => [layer, protocol])
);

const markerLayer = L.layerGroup().addTo(map);
const routeLayer = L.layerGroup().addTo(map);

L.control
  .layers(
    {},
    {
      "TCP heat": heatLayers.tcp,
      "UDP heat": heatLayers.udp,
      "ICMP heat": heatLayers.icmp,
      Points: markerLayer,
      Route: routeLayer,
    },
    { collapsed: false }
  )
  .addTo(map);

const packetSelect = document.getElementById("packet-select");
const packetDetails = document.getElementById("packet-details");
const companyList = document.getElementById("company-list");
const statusDot = document.getElementById("status-dot");
const packetCount = document.getElementById("packet-count");
const geoCount = document.getElementById("geo-count");
const traceCount = document.getElementById("trace-count");
const refreshIntervalMs = 1000;

let packetsById = new Map();
let selectedPacketId = "";
let latestHeatmap = { tcp: [], udp: [], icmp: [] };
let selectedPacketLocked = false;
const traceRequestsInFlight = new Set();

packetSelect.addEventListener("change", () => {
  selectPacket(packetSelect.value, true);
});

document.addEventListener("keydown", (event) => {
  if (!event.ctrlKey || event.altKey || event.metaKey) {
    return;
  }

  if (event.key === "ArrowUp") {
    event.preventDefault();
    selectAdjacentPacket(-1);
  } else if (event.key === "ArrowDown") {
    event.preventDefault();
    selectAdjacentPacket(1);
  }
});

function heatOptions() {
  return {
    minOpacity: 0.45,
    radius: 38,
    blur: 24,
    maxZoom: 8,
  };
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function isPublicIpv4(ip) {
  const parts = String(ip || "")
    .split(".")
    .map((part) => Number(part));

  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return false;
  }

  const [first, second] = parts;
  if (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    first >= 224 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  ) {
    return false;
  }

  return true;
}

function publicEndpoints(packet) {
  return [
    ["Source", packet.source],
    ["Destination", packet.destination],
  ].filter(([, endpoint]) => endpoint?.public);
}

function packetLabel(packet) {
  const prefix = packet.simulated ? "Demo " : "";
  const endpoints = publicEndpoints(packet)
    .map(([label, endpoint]) => `${label}: ${endpoint.ip}`)
    .join(" -> ");
  return `${prefix}#${packet.id} ${packet.protocol.toUpperCase()} ${endpoints || "No public IP"} ${packet.captured_at}`;
}

function setOnline(isOnline) {
  statusDot.classList.toggle("online", isOnline);
  statusDot.classList.toggle("offline", !isOnline);
}

function updateStats(state) {
  packetCount.textContent = state.totals.packets;
  geoCount.textContent = state.totals.geolocated_points;
  traceCount.textContent = state.totals.pending_traces;
}

function updateHeatmaps(heatmap) {
  latestHeatmap = heatmap || {};

  for (const protocol of ["tcp", "udp", "icmp"]) {
    const layer = heatLayers[protocol];
    const latLngs = latestHeatmap[protocol] || [];

    if (map.hasLayer(layer)) {
      layer.setLatLngs(latLngs);
    } else {
      layer._latlngs = latLngs;
    }
  }
}

map.on("overlayadd", (event) => {
  const protocol = heatLayerProtocols.get(event.layer);

  if (protocol) {
    event.layer.setLatLngs(latestHeatmap[protocol] || []);
  }
});

function updateMarkers(markers) {
  markerLayer.clearLayers();

  for (const marker of markers) {
    const items = marker.items
      .map(
        (item) =>
          `<li><strong>${escapeHtml(item.protocol.toUpperCase())}</strong> ${escapeHtml(item.direction)} ${escapeHtml(item.ip)} (${escapeHtml(item.hostname)}) - ${escapeHtml(item.geo_label || item.coords_source || "mapped")}</li>`
      )
      .join("");

    const popup = `
      <div style="width: 280px; max-height: 220px; overflow: auto;">
        <strong>${marker.count} geolocated packet point${marker.count === 1 ? "" : "s"}</strong>
        <ol>${items}</ol>
      </div>
    `;

    L.circleMarker(marker.coords, {
      radius: Math.min(18, 7 + marker.count),
      color: "#e11d48",
      weight: 2,
      fillColor: "#f97316",
      fillOpacity: 0.72,
    })
      .bindPopup(popup)
      .addTo(markerLayer);
  }
}

function isSelectedPacketLocked() {
  return selectedPacketLocked && Boolean(selectedPacketId);
}

function updatePacketSelect(packets) {
  for (const packet of packets) {
    packetsById.set(String(packet.id), packet);
  }

  const previousSelection = packetSelect.value || selectedPacketId;
  const keepCurrentMap = isSelectedPacketLocked();
  const livePacketIds = new Set(packets.map((packet) => String(packet.id)));
  for (const packetId of packetsById.keys()) {
    if (!livePacketIds.has(packetId) && packetId !== selectedPacketId) {
      packetsById.delete(packetId);
    }
  }

  packetSelect.replaceChildren();

  if (packets.length === 0) {
    if (keepCurrentMap) {
      const selectedPacket = packetsById.get(selectedPacketId);
      packetSelect.add(
        new Option(
          selectedPacket ? packetLabel(selectedPacket) : `Selected #${selectedPacketId}`,
          selectedPacketId
        )
      );
      packetSelect.value = selectedPacketId;
      renderSelectedRoute(false);
    } else {
      packetSelect.add(new Option("Waiting for public IP packets", ""));
      selectedPacketId = "";
      packetDetails.textContent = "Capture traffic with public IPs to populate routes.";
      routeLayer.clearLayers();
    }
    return;
  }

  for (const packet of packets.slice().reverse()) {
    packetSelect.add(new Option(packetLabel(packet), String(packet.id)));
  }

  if (keepCurrentMap) {
    if (!livePacketIds.has(selectedPacketId)) {
      const selectedPacket = packetsById.get(selectedPacketId);
      packetSelect.add(
        new Option(
          selectedPacket ? packetLabel(selectedPacket) : `Selected #${selectedPacketId}`,
          selectedPacketId
        )
      );
    }
    packetSelect.value = selectedPacketId;
    if (packetsById.has(selectedPacketId)) {
      renderSelectedRoute(false);
    }
    return;
  }

  if (previousSelection && packetsById.has(previousSelection)) {
    selectedPacketId = previousSelection;
  } else {
    selectedPacketId = String(packets[0].id);
  }

  packetSelect.value = selectedPacketId;
  renderSelectedRoute(false);
}

function selectPacket(packetId, fitRoute) {
  selectedPacketId = packetId;
  selectedPacketLocked = Boolean(selectedPacketId);
  packetSelect.value = selectedPacketId;
  renderSelectedRoute(fitRoute);
  requestSelectedTrace(selectedPacketId);
}

function selectAdjacentPacket(direction) {
  const options = Array.from(packetSelect.options).filter((option) => option.value);
  if (options.length === 0) {
    return;
  }

  const currentIndex = options.findIndex((option) => option.value === selectedPacketId);
  if (currentIndex === -1) {
    selectPacket(direction > 0 ? options[0].value : options[options.length - 1].value, true);
    return;
  }

  const startIndex = currentIndex;
  const nextIndex = (startIndex + direction + options.length) % options.length;
  packetSelect.value = options[nextIndex].value;
  selectPacket(options[nextIndex].value, true);
}

function addArrow(from, to) {
  const fromPoint = map.latLngToLayerPoint(from);
  const toPoint = map.latLngToLayerPoint(to);
  const angle =
    (Math.atan2(toPoint.y - fromPoint.y, toPoint.x - fromPoint.x) * 180) /
    Math.PI;
  const middle = [(from[0] + to[0]) / 2, (from[1] + to[1]) / 2];

  L.marker(middle, {
    icon: L.divIcon({
      className: "route-arrow-icon",
      html: `<div class="route-arrow" style="transform: rotate(${angle}deg);"></div>`,
      iconSize: [18, 18],
      iconAnchor: [9, 9],
    }),
    interactive: false,
  }).addTo(routeLayer);
}

function routeStopPopup(title, subtitle, geo) {
  return `
    <div class="route-stop-popup">
      <strong>${escapeHtml(title)}</strong>
      <div>${escapeHtml(subtitle)}</div>
      <div>${escapeHtml(geo || "not geolocated")}</div>
    </div>
  `;
}

function addRouteStopMarker(coords, kind, label, popupHtml) {
  const styleByKind = {
    start: { color: "#047857", fillColor: "#10b981", radius: 10 },
    end: { color: "#b45309", fillColor: "#f59e0b", radius: 10 },
    hop: { color: "#1d4ed8", fillColor: "#60a5fa", radius: 7 },
  };
  const style = styleByKind[kind] || styleByKind.hop;

  L.circleMarker(coords, {
    radius: style.radius,
    color: "#ffffff",
    weight: 5,
    fillColor: style.fillColor,
    fillOpacity: 0.95,
  }).addTo(routeLayer);

  L.circleMarker(coords, {
    radius: style.radius,
    color: style.color,
    weight: 2,
    fillColor: style.fillColor,
    fillOpacity: 0.88,
  })
    .bindPopup(popupHtml)
    .bindTooltip(label, {
      permanent: true,
      direction: "top",
      className: `route-stop-label route-stop-label-${kind}`,
    })
    .addTo(routeLayer);
}

function endpointGeoLabel(endpoint) {
  return endpoint.coords
    ? `${endpoint.coords.join(", ")} (${endpoint.geo_label || endpoint.coords_source || "mapped"})`
    : "not geolocated";
}

function addEndpointMarker(label, endpoint, kind) {
  if (!endpoint?.public || !endpoint.coords) {
    return;
  }

  addRouteStopMarker(
    endpoint.coords,
    kind,
    label === "Source" ? "Start" : "End",
    routeStopPopup(
      label === "Source" ? "Start" : "End",
      `${endpoint.ip} (${endpoint.hostname})`,
      endpointGeoLabel(endpoint)
    )
  );
}

function addHopMarkers(packet) {
  const hops = packet.route.hops || [];
  for (const hop of hops) {
    if (!hop.coords || !(hop.public === true || isPublicIpv4(hop.ip))) {
      continue;
    }

    const geo = hop.geo_label || hop.coords_source || "mapped";
    addRouteStopMarker(
      hop.coords,
      "hop",
      `TTL ${hop.ttl}`,
      routeStopPopup(`ICMP TTL ${hop.ttl}`, `${hop.ip} (${hop.hostname})`, geo)
    );
  }
}

function addRouteHighlights(packet) {
  addEndpointMarker("Source", packet.source, "start");
  addHopMarkers(packet);
  addEndpointMarker("Destination", packet.destination, "end");
}

function renderSelectedRoute(fitRoute) {
  routeLayer.clearLayers();
  const packet = packetsById.get(selectedPacketId);
  if (!packet) {
    packetDetails.textContent = "No packet selected.";
    return;
  }

  const points = packet.route.points || [];
  if (points.length >= 2) {
    L.polyline(points, {
      color: "#e11d48",
      weight: 4,
      opacity: 0.9,
    }).addTo(routeLayer);

    for (let index = 0; index < points.length - 1; index += 1) {
      addArrow(points[index], points[index + 1]);
    }

    if (fitRoute) {
      map.fitBounds(L.latLngBounds(points), { padding: [48, 48] });
    }
  } else if (points.length === 1) {
    L.circleMarker(points[0], {
      radius: 9,
      color: "#e11d48",
      weight: 3,
      fillColor: "#f43f5e",
      fillOpacity: 0.86,
    }).addTo(routeLayer);

    if (fitRoute) {
      map.setView(points[0], Math.max(map.getZoom(), 5));
    }
  }

  addRouteHighlights(packet);
  packetDetails.innerHTML = detailsHtml(packet);
}

async function requestSelectedTrace(packetId) {
  if (!packetId || traceRequestsInFlight.has(packetId)) {
    return;
  }

  const packet = packetsById.get(String(packetId));
  if (!packet) {
    return;
  }

  const shouldTrace =
    !packet.simulated &&
    packet.route?.status !== "trace complete" &&
    packet.route?.status !== "simulated";

  traceRequestsInFlight.add(packetId);
  try {
    if (shouldTrace) {
      packet.route.status = "selected trace pending";
      if (selectedPacketId === String(packetId)) {
        packetDetails.innerHTML = detailsHtml(packet);
      }
    }

    const response = await fetch("/api/trace", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ packet_id: Number(packetId) }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    if (!isSelectedPacketLocked() || shouldTrace) {
      refreshState();
    }
  } catch (error) {
    console.error(error);
  } finally {
    traceRequestsInFlight.delete(packetId);
  }
}

function endpointHtml(label, endpoint) {
  const geo = endpoint.coords
    ? `${endpoint.coords.join(", ")} (${endpoint.geo_label || endpoint.coords_source || "mapped"})`
    : "not geolocated";
  return `<div><strong>${label}:</strong> ${escapeHtml(endpoint.ip)} (${escapeHtml(endpoint.hostname)}) - ${escapeHtml(geo)}</div>`;
}

function detailsHtml(packet) {
  const publicEndpointItems = publicEndpoints(packet)
    .map(([label, endpoint]) => endpointHtml(label, endpoint))
    .join("");
  const hops = (packet.route.hops || []).filter(
    (hop) => !hop.ip || hop.public === true || isPublicIpv4(hop.ip)
  );
  const hopItems =
    hops.length === 0
      ? "<li>No public ICMP hops returned yet.</li>"
      : hops
          .map((hop) => {
            const ip = hop.ip || "*";
            const geo = hop.coords
              ? hop.geo_label || hop.coords_source || "mapped"
              : "not geolocated";
            return `<li><strong>TTL ${escapeHtml(hop.ttl)}:</strong> ${escapeHtml(ip)} (${escapeHtml(hop.hostname)}) - ${geo}</li>`;
          })
          .join("");

  const pointCount = (packet.route.points || []).length;
  let note = "";
  if (pointCount === 0) {
    note =
      '<div class="note"><strong>Note:</strong> This packet has no geolocated source, destination, or hop yet, so there is nothing geographic to draw.</div>';
  } else if (pointCount === 1) {
    note =
      '<div class="note"><strong>Note:</strong> One geolocated point is available. Arrows need at least two geolocated points.</div>';
  }

  return `
    <div><strong>${escapeHtml(packetLabel(packet))}</strong></div>
    <div><strong>Status:</strong> ${escapeHtml(packet.route.status)}</div>
    ${publicEndpointItems || "<div>No public endpoint found.</div>"}
    ${note}
    <div style="margin-top: 8px;"><strong>ICMP hops:</strong></div>
    <ol>${hopItems}</ol>
  `;
}

function updateCompanies(companies) {
  companyList.replaceChildren();
  const total = companies.reduce((sum, [, count]) => sum + count, 0);

  if (total === 0) {
    companyList.textContent = "No geolocated company data yet.";
    return;
  }

  for (const [company, count] of companies) {
    const percent = (count / total) * 100;
    const row = document.createElement("div");
    row.className = "company-row";
    row.innerHTML = `
      <div class="company-line">
        <strong>${escapeHtml(company)}</strong>
        <span>${count} (${percent.toFixed(1)}%)</span>
      </div>
      <div class="bar"><span style="width: ${percent}%;"></span></div>
    `;
    companyList.appendChild(row);
  }
}

async function refreshState() {
  let state;

  try {
    const response = await fetch("/api/state", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    state = await response.json();
  } catch (error) {
    setOnline(false);
    packetDetails.textContent = `Cannot reach backend: ${error.message}`;
    return;
  }

  try {
    const keepCurrentMap = isSelectedPacketLocked();
    setOnline(true);
    updateStats(state);
    if (!keepCurrentMap) {
      updateHeatmaps(state.heatmap);
      updateMarkers(state.markers);
    }
    updatePacketSelect(state.packets);
    updateCompanies(state.companies);
  } catch (error) {
    setOnline(true);
    packetDetails.textContent = `Map update failed: ${error.message}`;
    console.error(error);
  }
}

setInterval(refreshState, refreshIntervalMs);
refreshState();
