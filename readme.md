# cyberdudebivash's wireless net-scanner

## Description

This is a GUI application built with Tkinter for scanning nearby wireless networks on Windows (using netsh). It detects networks (assumed within ~100m WiFi range), fetches host (BSSID), system (vendor via API), network (SSID, auth, enc), ISP (approximated/not available), wireless config (channel, radio, signal), and location (via API if available).

**Note:** For educational purposes. Requires Windows and internet for API calls (vendor and location). Scanning is passive and legal, but respect privacy.

## Requirements

- Python 3.x
- Windows OS (for netsh)
- Packages: See `requirements.txt`

## Installation

1. Install dependencies: `pip install -r requirements.txt`
2. Run `python main.py`

## Usage

1. Launch the app: `python main.py`
2. Click "Scan Nearby Networks" to detect WiFi.
3. Networks appear in the list (SSID - BSSID (Signal)).
4. Select a network to view colorful details in the dashboard:
   - Host: Red panel
   - System: Orange
   - Network: Blue
   - ISP: Purple (limited)
   - Config: Teal
   - Location: Green

## Limitations

- Windows-only (netsh); adapt for Linux/Mac.
- ISP details limited (not directly fetchable without connection).
- Location via free API (may not always find data).
- Vendor API rate-limited; may fail on heavy use.
- All detected networks shown (filter by signal for range if needed).

## License

MIT License .

##COPYRIGHT@CYBERDUDEBIVASH 2025