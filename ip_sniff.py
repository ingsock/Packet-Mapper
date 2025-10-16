from scapy.all import sniff, IP, TCP, UDP
import geoip2.database
import geoip2.errors
import folium
from folium.plugins import HeatMap
import threading
import time
import webbrowser
import os

# --- Configuration ---
# Path to the GeoLite2-City.mmdb file
GEOLITE_DB_PATH = "GeoLite2-City.mmdb"
# Output HTML map file
OUTPUT_MAP_FILE = "ip_heatmap.html"
# Dictionary to store coordinates for TCP and UDP
location_data = {"tcp": [], "udp": []}
# Lock for thread-safe access to location_data
location_lock = threading.Lock()

# --- Geolocation Engine ---
def get_coords(ip):
    """
    Converts an IP address to geographic coordinates using the GeoLite2 database.
    Returns (latitude, longitude) or None if the IP is not found or is private.
    """
    # Ignore private IP addresses
    if ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1":
        return None
    try:
        with geoip2.database.Reader(GEOLITE_DB_PATH) as reader:
            response = reader.city(ip)
            if response.location.latitude is not None and response.location.longitude is not None:
                return (response.location.latitude, response.location.longitude)
            else:
                return None
    except geoip2.errors.AddressNotFoundError:
        return None
    except FileNotFoundError:
        print(f"Error: GeoLite2 database not found at {GEOLITE_DB_PATH}")
        return None

# --- Packet Sniffer ---
def process_packet(packet):
    """
    Callback function to process each captured packet.
    """
    if IP in packet:
        protocol = None
        if TCP in packet:
            protocol = "tcp"
        if UDP in packet:
            protocol = "udp"

        if protocol:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            print(f"Protocol: {protocol.upper()}, Source IP: {source_ip}, Destination IP: {destination_ip}")

            source_coords = get_coords(source_ip)
            dest_coords = get_coords(destination_ip)

            with location_lock:
                if source_coords:
                    location_data[protocol].append(source_coords)
                    print(f"Source Coords: {source_coords}")
                if dest_coords:
                    location_data[protocol].append(dest_coords)
                    print(f"Destination Coords: {dest_coords}")

# --- Map Generator ---
def generate_map():
    """
    Generates and saves the heatmap HTML file with separate layers for TCP and UDP.
    """
    with location_lock:
        if not location_data["tcp"] and not location_data["udp"]:
            print("No location data to generate map.")
            return

    # Create a base map
    world_map = folium.Map(location=[20, 0], zoom_start=2)

    # Create HeatMap layers for TCP and UDP
    with location_lock:
        tcp_heat = HeatMap(location_data["tcp"], name="TCP")
        world_map.add_child(tcp_heat)
        print(location_data["udp"])
        udp_heat = HeatMap(location_data["udp"], name="UDP")
        world_map.add_child(udp_heat)

    # Add layer control to toggle between heatmaps
    folium.LayerControl().add_to(world_map)

    # Save the map to an HTML file
    world_map.save(OUTPUT_MAP_FILE)
    print(f"Map saved to {OUTPUT_MAP_FILE}")

# --- Main Application ---
def sniffer_thread():
    """
    Thread for running the packet sniffer.
    """
    print("Starting packet sniffer...")
    sniff(prn=process_packet, store=False)

def main():
    """
    Main function to run the application.
    """
    # Start the sniffer in a background thread
    sniffer = threading.Thread(target=sniffer_thread)
    sniffer.daemon = True
    sniffer.start()

    # Periodically generate the map in the main thread
    try:
        while True:
            time.sleep(10)
            generate_map()
            # Open the map in the default web browser
            webbrowser.open(f"file://{os.path.realpath(OUTPUT_MAP_FILE)}")
    except KeyboardInterrupt:
        print("\nStopping the application...")
        generate_map()
        print("Final map generated.")

if __name__ == "__main__":
    main()