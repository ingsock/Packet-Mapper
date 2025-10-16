# Global Packet Heatmap Visualizer

This project captures network packets in real-time, identifies the geographic location of their source and destination IP addresses, and visualizes this data as a heatmap on an interactive world map.

## Features

*   **Real-time Packet Sniffing:** Captures TCP and UDP packets on your network.
*   **IP Geolocation:** Converts public IP addresses to geographic coordinates (latitude and longitude).
*   **Interactive Heatmap:** Generates an HTML file (`ip_heatmap.html`) with a world map that displays the geographic distribution of packet traffic.
*   **Protocol-based Filtering:** The map displays separate, toggleable layers for TCP and UDP traffic.
*   **Automatic Updates:** The map automatically regenerates every 10 seconds and opens in your default web browser.

## Technology Stack

*   **Packet Sniffing:** [Scapy](https://scapy.net/)
*   **IP Geolocation:** [GeoIP2](https://pypi.org/project/geoip2/) with the [MaxMind GeoLite2 City Database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
*   **Map Visualization:** [Folium](https://python-visualization.github.io/folium/)

## Prerequisites & Setup

1.  **Python:** Ensure you have Python 3.6+ installed.
2.  **Install Libraries:**
    ```bash
    pip install scapy geoip2 folium
    ```
3.  **Download GeoLite2 Database:**
    *   Go to the [MaxMind GeoLite2 free database page](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
    *   Sign up for a free account to get a license key.
    *   Download the "GeoLite2 City" database (`.tar.gz`).
    *   Extract the archive and place the `GeoLite2-City.mmdb` file in the project directory.

## How to Run

Because packet sniffing requires elevated privileges, you must run the script as an administrator or with `sudo`.

*   **Windows:** Open Command Prompt or PowerShell as an Administrator and run:
    ```bash
    python ip_sniff.py
    ```
*   **macOS/Linux:**
    ```bash
    sudo python ip_sniff.py
    ```

The script will start sniffing packets. After 10 seconds, it will generate `ip_heatmap.html` and open it in your default web browser. The map will update automatically as more packets are captured. To stop the script, press `Ctrl+C`.

## How It Works

1.  **Packet Sniffing:** The script uses Scapy to listen for network traffic. A sniffer runs in a background thread, processing each packet.
2.  **Geolocation:** For each captured IP packet (TCP or UDP), the source and destination IP addresses are extracted. Private/local IPs are ignored. Public IPs are looked up in the `GeoLite2-City.mmdb` database to find their latitude and longitude.
3.  **Data Aggregation:** The geographic coordinates are stored in separate lists for TCP and UDP traffic.
4.  **Map Generation:** Every 10 seconds, the main thread generates a new map using Folium. It creates a base world map and adds two `HeatMap` layers: one for TCP locations and one for UDP locations. A layer control is added to the map to allow toggling between them.
5.  **Visualization:** The final map is saved as an HTML file and automatically opened in a web browser for viewing.
