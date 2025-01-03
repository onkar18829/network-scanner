import streamlit as st
from scapy.all import *
import ipaddress
import socket
import threading
import subprocess

def get_local_ip():
    """Gets the local IP address of the machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        st.error(f"Error getting local IP: {e}")
        return None

def get_network_range():
    """Determines the network range based on the local IP."""
    try:
        local_ip = get_local_ip()
        if local_ip:
            ip_obj = ipaddress.ip_interface(local_ip)
            return str(ip_obj.network)
        else:
            return None
    except Exception as e:
        st.error(f"Error determining network range: {e}")
        return None

def scan_host(ip):
    """Scans a single host for open ports."""
    try:
        ip_address = ipaddress.ip_address(ip)
    except ValueError:
        st.error(f"Invalid IP address: {ip}")
        return

    open_ports = []
    for port in range(1, 1025):  # Scan ports 1-1024
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((str(ip), port))
            open_ports.append(port)
            sock.close()
        except:
            pass

    return open_ports

def scan_network(network_range):
    """Scans a range of IP addresses."""
    try:
        ip_range = ipaddress.ip_network(network_range)
    except ValueError:
        st.error("Invalid IP range.")
        return

    results = {}
    for ip in ip_range:
        ip_str = str(ip)
        open_ports = scan_host(ip_str)
        results[ip_str] = {"open_ports": open_ports}

    return results

def analyze_safety(open_ports):
    """Provides a basic safety assessment based on open ports."""
    if 21 in open_ports or 22 in open_ports:
        return "Potential Security Risk: Open ports for FTP/SSH"
    elif 80 in open_ports or 443 in open_ports:
        return "Web Server Detected: Check for proper security configurations"
    else:
        return "Appears to be relatively safe"

def main():
    st.title("Network Scanner")

    if st.button("Scan Local Network"):
        network_range = get_network_range()
        if network_range:
            with st.spinner("Scanning..."):
                results = scan_network(network_range)

            if results:
                st.success("Scan Completed")
                for ip, data in results.items():
                    st.write(f"**Host:** {ip}")
                    if data["open_ports"]:
                        st.write(f"Open Ports: {', '.join(map(str, data['open_ports']))}")
                        st.write(f"Safety Assessment: {analyze_safety(data['open_ports'])}")
                    else:
                        st.write("No open ports found.")
            else:
                st.warning("No hosts found in the specified range.")
        else:
            st.warning("Could not determine local network range.")

if __name__ == "__main__":
    main()
