# main.py - cyberdudebivash's wireless net-scanner
# This app scans for nearby wireless networks using win32wifi on Windows, fetches details like BSSID (host), vendor (system), network info (SSID, auth, enc), wireless config (channel, radio, signal), and location via API.
# Fixed iteration over available_networks by using available_networks.Network
# Set channel to 'Unknown' as it's not directly available in WLAN_AVAILABLE_NETWORK; use BSS list for accurate channel if needed.
# Assumes all detected networks are within ~100m range (WiFi typical). Requires internet for API calls.
# GUI dashboard with colors using Tkinter.
# Note: For educational purposes. Scanning is legal, but do not attempt to connect without permission. May require admin privileges.

import tkinter as tk
from tkinter import messagebox, Listbox
import requests
from threading import Thread
from win32wifi.Win32Wifi import getWirelessInterfaces, WlanOpenHandle, WlanScan, WlanGetAvailableNetworkList, WlanCloseHandle
from win32wifi.Win32NativeWifiApi import WLAN_AVAILABLE_NETWORK
import time

class WirelessScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("cyberdudebivash's wireless net-scanner")
        self.root.geometry("800x600")
        self.root.configure(bg="#2c3e50")  # Dark background for dashboard
        
        # Title Label
        self.title_label = tk.Label(root, text="Wireless Network Scanner Dashboard", font=("Arial", 16, "bold"), bg="#2c3e50", fg="#ecf0f1")
        self.title_label.pack(pady=10)
        
        # Scan Button
        self.scan_btn = tk.Button(root, text="Scan Nearby Networks", command=self.start_scan, bg="#27ae60", fg="white", font=("Arial", 12))
        self.scan_btn.pack(pady=10)
        
        # Network List
        self.network_list = Listbox(root, width=100, height=10, bg="#34495e", fg="#ecf0f1", selectbackground="#2980b9")
        self.network_list.pack(pady=10)
        self.network_list.bind('<<ListboxSelect>>', self.show_details)
        
        # Details Frame
        self.details_frame = tk.Frame(root, bg="#2c3e50")
        self.details_frame.pack(pady=10, fill=tk.BOTH, expand=True)
        
        # Details Labels (initialized empty)
        self.host_label = tk.Label(self.details_frame, text="", bg="#e74c3c", fg="white", anchor="w", justify="left")
        self.host_label.pack(fill=tk.X, pady=2)
        
        self.system_label = tk.Label(self.details_frame, text="", bg="#f39c12", fg="white", anchor="w", justify="left")
        self.system_label.pack(fill=tk.X, pady=2)
        
        self.network_label = tk.Label(self.details_frame, text="", bg="#3498db", fg="white", anchor="w", justify="left")
        self.network_label.pack(fill=tk.X, pady=2)
        
        self.isp_label = tk.Label(self.details_frame, text="", bg="#9b59b6", fg="white", anchor="w", justify="left")
        self.isp_label.pack(fill=tk.X, pady=2)
        
        self.config_label = tk.Label(self.details_frame, text="", bg="#1abc9c", fg="white", anchor="w", justify="left")
        self.config_label.pack(fill=tk.X, pady=2)
        
        self.location_label = tk.Label(self.details_frame, text="", bg="#2ecc71", fg="white", anchor="w", justify="left")
        self.location_label.pack(fill=tk.X, pady=2)
        
        self.networks = []  # List of dicts for networks

    def start_scan(self):
        self.network_list.delete(0, tk.END)
        self.clear_details()
        self.scan_btn.config(state=tk.DISABLED)
        Thread(target=self.scan_networks).start()

    def scan_networks(self):
        try:
            interfaces = getWirelessInterfaces()
            if len(interfaces) == 0:
                self.root.after(0, lambda: messagebox.showerror("Error", "No WiFi interfaces found. Ensure you have a wireless adapter and WiFi is enabled."))
                return
            
            iface = interfaces[0]
            handle = WlanOpenHandle()
            WlanScan(handle, iface.guid)
            
            # Wait for scan to complete
            time.sleep(5)
            
            available_networks = WlanGetAvailableNetworkList(handle, iface.guid)
            WlanCloseHandle(handle)
            
            self.parse_networks(available_networks)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Scan failed: {str(e)}\nEnsure WiFi is enabled and try running as administrator."))
        finally:
            self.root.after(0, lambda: self.scan_btn.config(state=tk.NORMAL))

    def parse_networks(self, available_networks_list):
        self.networks = []
        available_networks = available_networks_list.Network  # Access the Network array
        for network in available_networks:
            ssid = network.dot11Ssid.SSID.decode('utf-8') if network.dot11Ssid.SSIDLength > 0 else "Hidden"
            bssid_bytes = network.dot11Bssid
            bssid = ':'.join(format(x, '02x') for x in bssid_bytes)
            signal = network.wlanSignalQuality
            channel = 'Unknown'  # Not directly available; could use WlanGetNetworkBssList for frequency/channel
            auth = self.get_auth_type(network.dot11DefaultAuthAlgorithm)
            enc = self.get_enc_type(network.dot11DefaultCipherAlgorithm)
            radio = self.get_phy_type(network.dot11PhyTypes[0]) if network.numberOfPhyTypes > 0 else 'Unknown'
            
            net = {
                'ssid': ssid,
                'bssid': bssid,
                'signal': str(signal),
                'radio': radio,
                'channel': channel,
                'network_type': 'Infrastructure' if network.bssType == 1 else 'Adhoc' if network.bssType == 2 else 'Unknown',
                'auth': auth,
                'enc': enc,
            }
            self.networks.append(net)
            self.root.after(0, lambda n=net: self.network_list.insert(tk.END, f"{n['ssid']} - {n['bssid']} (Signal: {n['signal']}% )"))
        
        if not self.networks:
            self.root.after(0, lambda: messagebox.showinfo("No Networks", "No wireless networks detected. Ensure there are networks in range and WiFi is enabled."))

    def get_auth_type(self, algo):
        auth_map = {1: 'Open', 2: 'Shared', 3: 'WPA', 4: 'WPA-PSK', 5: 'WPA2', 6: 'WPA2-PSK', 7: 'WPA3'}
        return auth_map.get(algo, 'Unknown')

    def get_enc_type(self, algo):
        enc_map = {1: 'None', 2: 'WEP', 3: 'TKIP', 4: 'CCMP', 5: 'GCMP'}
        return enc_map.get(algo, 'Unknown')

    def get_phy_type(self, phy):
        phy_map = {0: 'Unknown', 1: 'FHSS', 2: 'DSSS', 3: 'IR Baseband', 4: 'OFDM', 5: 'HRDSSS', 6: 'ERP', 7: 'HT', 8: 'VHT', 9: 'DMG', 10: 'HE'}
        return phy_map.get(phy, 'Unknown')

    def show_details(self, event):
        selected = self.network_list.curselection()
        if selected:
            index = selected[0]
            network = self.networks[index]
            Thread(target=self.fetch_additional_details, args=(network,)).start()

    def fetch_additional_details(self, network):
        # Vendor (System details)
        vendor = "Unknown"
        try:
            response = requests.get(f"https://api.macvendors.com/{network['bssid']}", timeout=5)
            if response.status_code == 200:
                vendor = response.text
        except:
            pass
        
        # Location
        location = "Not found"
        try:
            resp = requests.get(f"https://api.mylnikov.org/geolocation/wifi?v=1.2&bssid={network['bssid']}", timeout=5).json()
            if resp.get('result') == 200:
                data = resp['data']
                location = f"Lat: {data.get('lat', 'N/A')}, Lon: {data.get('lon', 'N/A')}, Range: {data.get('range', 'N/A')}m"
        except:
            pass
        
        # ISP: Not directly available; approximate with vendor or note
        isp = "Not available without connection (possibly related to vendor)"
        
        # Update labels on main thread
        self.root.after(0, lambda: self.update_details(network, vendor, isp, location))

    def update_details(self, network, vendor, isp, location):
        self.host_label.config(text=f"Host Details: BSSID - {network['bssid']}")
        self.system_label.config(text=f"System Details: Vendor - {vendor}")
        self.network_label.config(text=f"Network Details: SSID - {network['ssid']}, Type - {network['network_type']}, Auth - {network['auth']}, Enc - {network['enc']}")
        self.isp_label.config(text=f"ISP Details: {isp}")
        self.config_label.config(text=f"Wireless Config: Channel - {network['channel']}, Radio - {network['radio']}, Signal - {network['signal']}%")
        self.location_label.config(text=f"Location Details: {location}")

    def clear_details(self):
        self.host_label.config(text="")
        self.system_label.config(text="")
        self.network_label.config(text="")
        self.isp_label.config(text="")
        self.config_label.config(text="")
        self.location_label.config(text="")

if __name__ == "__main__":
    root = tk.Tk()
    app = WirelessScannerApp(root)
    root.mainloop()