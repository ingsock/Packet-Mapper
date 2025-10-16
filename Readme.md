Project Plan: Global Packet Heatmap Visualizer

1. Project Goal

The primary objective of this project is to create a Python application that captures network packets in real-time, determines the geographical location of the source and destination IP addresses, and visualizes this data as a live heatmap on a world map.

2. Technology Stack

Packet Sniffing: Scapy (scapy)

IP Geolocation: GeoIP2 (geoip2) with the MaxMind GeoLite2 database.

Map Visualization: Folium (folium)

3. Prerequisites & Setup

Before writing any code, the following setup is required:

Install Python: Ensure you have Python 3.6+ installed on your system.

Install Libraries: Open your terminal or command prompt and install the necessary libraries.

pip install scapy geoip2-city folium


Download GeoLite2 Database:

Go to the MaxMind GeoLite2 free database page.

Sign up for an account to get a license key (it's free).

Download the "GeoLite2 City" database in tar.gz format.

Extract the archive and place the GeoLite2-City.mmdb file in your project directory.

Administrator Privileges: Packet sniffing requires low-level access to the network card. You will need to run your final Python script with administrator or root privileges.

Windows: Run Command Prompt or PowerShell as an Administrator.

macOS/Linux: Use the sudo command (e.g., sudo python your_script.py).

4. Development Phases

We will build the application in logical, incremental steps.

Phase 1: The Sniffer

Goal: Capture IP packets and print their source and destination addresses to the console.

Tasks:

Create a new Python file (e.g., packet_visualizer.py).

Import sniff and IP from the scapy library.

Define a callback function process_packet(packet) that checks if a packet has an IP layer.

If it does, extract the src and dst IP addresses.

Print the IPs to the console to verify it's working.

Start the sniffer using sniff(prn=process_packet, store=False).

Phase 2: The Geolocation Engine

Goal: Convert the captured IP addresses into geographic coordinates (latitude and longitude).

Tasks:

Integrate the geoip2 library into your script.

Load the GeoLite2-City.mmdb database using the geoip2.database.Reader.

Create a function get_coords(ip) that takes an IP address and returns (latitude, longitude).

Inside process_packet, call get_coords for both the source and destination IPs.

Crucially, add error handling:

Wrap the geolocation lookup in a try...except block to handle IPs not found in the database.

Add a check to ignore private/local IP addresses (e.g., 192.168.x.x, 10.x.x.x, 127.0.0.1), as they cannot be geolocated.

Print the coordinates to the console.

Phase 3: The Map Generator

Goal: Generate a static HTML map with a heatmap of all captured locations.

Tasks:

Create a global list to store all valid coordinates: location_data = [].

In process_packet, after successfully getting coordinates, append them to the location_data list.

Integrate the folium library.

Create a function generate_map(). This function will be called when the script is stopped (e.g., by pressing Ctrl+C).

Inside generate_map():

Create a base folium.Map.

Use folium.plugins.HeatMap to add the location_data.

Save the map to an HTML file: map.save("ip_heatmap.html").

Wrap the sniff() call in a try...finally block to ensure generate_map() is always called on exit.

Phase 4: Making it Dynamic (Advanced)

Goal: Update the map periodically without stopping the script.

Approach: We'll use threading to run the sniffer and the map generator concurrently.

Tasks:

Import the threading and time libraries.

Place the sniff() function call into its own function and run it in a separate thread.

In the main thread, create a loop that runs every 10-30 seconds.

Inside the loop, call the generate_map() function to overwrite the ip_heatmap.html file with the latest data.

The user can then open the HTML file in a browser and simply refresh the page to see the updated heatmap.

5. File Structure

Your project directory should look like this:

/packet-heatmap-project/
|-- packet_visualizer.py    # Your main Python script
|-- GeoLite2-City.mmdb      # The MaxMind database file
|-- ip_heatmap.html         # The generated map (output)


6. Future Enhancements

Once the core application is working, consider these improvements:

Web Framework: Use Flask or Django to serve the ip_heatmap.html file and automatically refresh the data using JavaScript, creating a true real-time dashboard.

Data Filtering: Add options to filter traffic by port, protocol (TCP/UDP), or specific IP addresses.

Visual Distinction: Use different colors or even separate maps to distinguish between incoming and outgoing traffic.

Data Persistence: Save the location data to a database or a CSV file to analyze traffic patterns over longer periods.

Clickable Markers: Instead of just a heatmap, add clickable markers for unique IPs that show more details (like City, Country, ISP).