# ASIC Detector

A Python tool for discovering and analyzing Antminer ASIC miners across IP ranges. This utility helps mining operations identify the number of ASICs and chains that are online or offline within their network.

## Features

- Scan multiple IP ranges to detect Antminer devices
- Count and report online/offline ASICs per miner
- Identify chains with zero ASICs
- Calculate percentage of online ASICs and chains
- Support for both standard and VNish firmware
- Multi-threaded scanning for efficient network traversal

## Setup Instructions

### Prerequisites
- Python 3.6 or higher
- Network access to the miners you want to scan

### Installation

1. Clone this repository:
   ```
   git clone https://github.com/Lyzer25/asic-detector.git
   cd asic-detector
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the script:

python asic_detector.py

When prompted, enter the IP range(s) to scan in the format:
10.1.10.0-255, 10.1.20.0-100

### Example Output

The tool will provide:
- A list of all detected miners with their IP addresses
- Serial numbers and firmware information for each miner
- ASIC counts for each chain on each miner
- A summary of miners with zero-ASIC chains
- Overall statistics including:
  - Total miners found
  - Total ASICs detected vs. expected
  - Percentage of ASICs online
  - Percentage of chains online

## Troubleshooting

- Ensure you have network connectivity to the miners
- Verify that port 4028 (CGMiner API port) is accessible
- For VPN-connected sites, make sure your VPN connection is active

## License

[MIT License](LICENSE)
