import socket
import json
import concurrent.futures
import requests
import argparse
from typing import Dict, List, Optional, Tuple
import time

class AntminerScanner:
    MODEL_ASIC_COUNTS = {
        "Antminer S19J Pro": 126,
        "Antminer S19 (88)": 88,
        "Antminer S19": 76,
        "Antminer S19J": 108,
        "Antminer S19 Pro": 114
    }
    ASIC_TO_MODEL = {v: k for k, v in MODEL_ASIC_COUNTS.items()}

    def __init__(self, ip_ranges: str, timeout: int = 15, retries: int = 3, debug: bool = False, debug_ip: str = None):
        self.ip_ranges = ip_ranges
        self.timeout = timeout
        self.retries = retries
        self.cgminer_port = 4028
        self.debug = debug
        self.debug_ip = debug_ip

    def parse_ip_ranges(self) -> List[str]:
        ip_list = []
        ranges = [r.strip() for r in self.ip_ranges.split(',')]
        for ip_range in ranges:
            try:
                start_ip, end_num = ip_range.split('-')
                base_ip = '.'.join(start_ip.split('.')[:-1])
                start_num = int(start_ip.split('.')[-1])
                end_num = int(end_num)
                ip_list.extend([f"{base_ip}.{i}" for i in range(start_num, end_num + 1)])
            except (ValueError, IndexError) as e:
                raise ValueError(f"Invalid IP range format in '{ip_range}'. Use 'x.x.x.x-yyy'. Error: {str(e)}")
        return ip_list

    def send_cgminer_command(self, ip: str, command: str) -> Optional[Dict]:
        for attempt in range(self.retries):
            try:
                payload = {"command": command}
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((ip, self.cgminer_port))
                s.send(json.dumps(payload).encode('utf-8'))
                s.send(b'\x00')
                response = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if response.endswith(b'\x00'):
                        response = response[:-1]
                        break
                if response:
                    try:
                        return json.loads(response.decode('utf-8'))
                    except json.JSONDecodeError:
                        return None
            except (socket.timeout, socket.error, ConnectionRefusedError) as e:
                if attempt < self.retries - 1:
                    print(f"Retrying {ip} (attempt {attempt + 1}/{self.retries}) due to {str(e)}...")
                    time.sleep(1)
                continue
            finally:
                try:
                    s.close()
                except:
                    pass
        print(f"Failed to connect to {ip} after {self.retries} attempts.")
        return None

    def send_vnish_command(self, ip: str, endpoint: str) -> Optional[List]:
        """Send HTTP request to VNish API endpoint, returning the list of chains."""
        url = f"http://{ip}:{self.cgminer_port}/api/v1/{endpoint}"
        try:
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            result = response.json()
            if self.debug and ip == self.debug_ip:
                print(f"Debug: VNish API response for {ip}/{endpoint}:")
                print(json.dumps(result, indent=2))
            return result
        except requests.exceptions.HTTPError as e:
            print(f"HTTP error fetching VNish {endpoint} for {ip}: {e}")
            print(f"Status code: {e.response.status_code}")
            print(f"Response: {e.response.text}")
        except requests.exceptions.ConnectionError as e:
            print(f"Connection error fetching VNish {endpoint} for {ip}: {e}")
        except requests.exceptions.Timeout as e:
            print(f"Timeout fetching VNish {endpoint} for {ip}: {e}")
        except requests.exceptions.RequestException as e:
            print(f"Error fetching VNish {endpoint} for {ip}: {e}")
        except json.JSONDecodeError as e:
            print(f"JSON decode error for VNish {endpoint} response from {ip}: {e}")
        return None

    def is_vnish_firmware(self, stats_response: Dict) -> bool:
        """Detect if the miner is running VNish firmware (e.g., based on CGMiner version or firmware field)."""
        if stats_response and 'STATS' in stats_response:
            for stat in stats_response['STATS']:
                # Check for CGMiner version
                if 'CGMiner' in stat and '4.11.1' in str(stat.get('CGMiner', '')):
                    if self.debug:
                        print(f"VNish firmware detected via CGMiner version: {stat.get('CGMiner', '')}")
                    return True
                # Check for Firmware field containing 'vnish'
                if 'Firmware' in stat and 'vnish' in str(stat.get('Firmware', '')).lower():
                    if self.debug:
                        print(f"VNish firmware detected via Firmware field: {stat.get('Firmware', '')}")
                    return True
                # Check for specific version 1.2.6-rc4
                if 'Firmware' in stat and '1.2.6-rc4' in str(stat.get('Firmware', '')):
                    if self.debug:
                        print(f"VNish firmware detected via version 1.2.6-rc4: {stat.get('Firmware', '')}")
                    return True
        return False

    def extract_data(self, stats_response: Optional[Dict], ip: str) -> Tuple[List[str], Dict[str, int], int, str]:
        serials = []
        chain_counts = {}
        chain_total = 0
        model = "Unknown"
        
        if stats_response:
            stats = stats_response.get('STATS', [])
            for stat in stats:
                serial_fields = ['Serial', 'ID', 'miner_id', 'board_sn']
                for field in serial_fields:
                    if field in stat:
                        serials.append(f"{field}: {stat[field]}")
                for key in stat:
                    if 'chain_acn' in key.lower():
                        count = stat[key]
                        chain_counts[key] = count  # Keep exact count, including 0
                        chain_total += 1
                    elif 'chain_sn' in key.lower():
                        serials.append(f"{key}: {stat[key]}")
                # Display firmware version
                if 'CGMiner' in stat:
                    serials.append(f"Firmware: {stat['CGMiner']}")
                if 'Firmware' in stat:
                    serials.append(f"Firmware Version: {stat['Firmware']}")

            # Use VNish API if detected
            if self.is_vnish_firmware(stats_response):
                if self.debug and ip == self.debug_ip:
                    print(f"Debug: VNish firmware detected for {ip}")
                
                chains_response = self.send_vnish_command(ip, "chains")
                if chains_response:  # chains_response is a list of chain objects
                    if self.debug and ip == self.debug_ip:
                        print(f"Debug: Using VNish API data for {ip}")
                    
                    chain_counts.clear()  # Reset to use VNish data
                    for chain in chains_response:
                        chain_id = chain['id']  # Use 'id' as the chain number (1, 2, 3)
                        status_state = chain['status'].get('state', 'unknown')
                        chips = chain.get('chips', [])
                        
                        # Determine ASIC count: online if mining and chips have non-zero hr, else 0
                        if status_state == "mining" and chips and any(chip['hr'] > 0 for chip in chips):
                            asic_count = len(chips)
                            if self.debug and ip == self.debug_ip:
                                print(f"Debug: Chain {chain_id} is online with {asic_count} ASICs")
                        else:
                            asic_count = 0  # Offline if not mining or no active chips
                            if self.debug and ip == self.debug_ip:
                                print(f"Debug: Chain {chain_id} is offline (status: {status_state}, chips: {len(chips)})")
                        
                        chain_counts[f"chain_acn{chain_id}"] = asic_count
                        chain_total = len(chains_response)  # 3 chains per miner
                    
                    # Re-infer model based on VNish chain data (max non-zero ASIC count)
                    non_zero_counts = [count for count in chain_counts.values() if count > 0]
                    max_asic = max(non_zero_counts) if non_zero_counts else 0
                    model = self.ASIC_TO_MODEL.get(max_asic, "Unknown")
                    serials.append(f"Model (inferred from VNish ASIC count {max_asic}): {model}")
                else:
                    # Fall back to CGMiner stats if VNish /chains fails
                    if self.debug and ip == self.debug_ip:
                        print(f"Debug: VNish API failed, falling back to CGMiner stats for {ip}")
                    
                    non_zero_counts = [count for count in chain_counts.values() if count > 0]
                    max_asic = max(non_zero_counts) if non_zero_counts else 0
                    model = self.ASIC_TO_MODEL.get(max_asic, "Unknown")
                    serials.append(f"Model (inferred from CGMiner ASIC count {max_asic}): {model}")
            else:
                # Use CGMiner stats if not VNish
                if self.debug and ip == self.debug_ip:
                    print(f"Debug: Not VNish firmware, using CGMiner stats for {ip}")
                
                non_zero_counts = [count for count in chain_counts.values() if count > 0]
                max_asic = max(non_zero_counts) if non_zero_counts else 0
                model = self.ASIC_TO_MODEL.get(max_asic, "Unknown")
                serials.append(f"Model (inferred from CGMiner ASIC count {max_asic}): {model}")

        return serials, chain_counts, chain_total, model

    def scan_miner(self, ip: str) -> Tuple[str, List[str], Dict[str, int], int, str]:
        serials = []
        chain_counts = {}
        chain_total = 0
        model = "Unknown"
        
        if self.debug and ip == self.debug_ip:
            print(f"Debug: Scanning miner {ip}")
        
        stats_response = self.send_cgminer_command(ip, "stats")
        if stats_response:
            if self.debug and ip == self.debug_ip:
                print(f"Debug: Got CGMiner stats response for {ip}")
                print(json.dumps(stats_response, indent=2))
            
            serials, chain_counts, chain_total, model = self.extract_data(stats_response, ip)
        elif self.debug and ip == self.debug_ip:
            print(f"Debug: Failed to get CGMiner stats response for {ip}")
        
        return ip, serials, chain_counts, chain_total, model

    def scan_network(self, max_workers: int = 20) -> Dict[str, Tuple[List[str], Dict[str, int], int, str]]:
        results = {}
        ip_list = self.parse_ip_ranges()
        
        print(f"Starting scan of {len(ip_list)} IP addresses in ranges {self.ip_ranges}...")
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(self.scan_miner, ip): ip for ip in ip_list}
            completed = 0
            for future in concurrent.futures.as_completed(future_to_ip):
                completed += 1
                if completed % 10 == 0:
                    print(f"Progress: {completed}/{len(ip_list)} IPs scanned...")
                ip = future_to_ip[future]
                try:
                    ip, serials, chain_counts, chain_total, model = future.result()
                    if serials or chain_counts:
                        results[ip] = (serials, chain_counts, chain_total, model)
                except Exception as e:
                    print(f"Error scanning {ip}: {str(e)}")
        
        scan_time = time.time() - start_time
        print(f"\nScan completed in {scan_time:.2f} seconds")
        print(f"Total IPs scanned: {len(ip_list)}, Miners found: {len(results)}")
        return results

def main():
    parser = argparse.ArgumentParser(description='Scan for Antminer ASICs')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--ip', help='Specific IP to debug')
    parser.add_argument('--range', help='IP range to scan (e.g., 10.1.10.0-255)')
    args = parser.parse_args()
    
    ip_ranges = args.range
    if not ip_ranges:
        while True:
            try:
                ip_ranges = input("Enter IP ranges to scan (e.g., 10.1.10.0-255, 10.1.20.0-100): ")
                if ip_ranges:
                    break
            except ValueError as e:
                print(f"Error: {e}. Please try again.")
    
    try:
        scanner = AntminerScanner(ip_ranges, timeout=15, retries=3, debug=args.debug, debug_ip=args.ip)
        ip_list = scanner.parse_ip_ranges()
    except ValueError as e:
        print(f"Error: {e}. Please try again.")
        return
    
    results = scanner.scan_network()
    
    print("\nScan Results:")
    print("=" * 50)
    if not results:
        print("No miners found or no data could be retrieved.")
    else:
        zero_asic_ips = []
        less_than_three_chains_ips = []
        total_asic_count = 0
        total_chains = 0
        chains_online = 0
        chains_offline = 0
        model_counts = {}
        
        for ip, (serials, chain_counts, chain_total, model) in results.items():
            print(f"\nIP Address: {ip}")
            for serial in serials:
                print(f"  {serial}")
            if chain_counts:
                for chain, count in chain_counts.items():
                    print(f"  {chain}: {count}")
                    total_asic_count += count
                    if count > 0:
                        chains_online += 1
                    else:
                        chains_offline += 1
                total_chains += chain_total
            
            # Fix: Correctly identify chains with zero ASICs
            zero_chains = [k for k, v in chain_counts.items() if v == 0]
            if zero_chains:
                zero_asic_ips.append(f"'{ip}' '{', '.join(zero_chains)}'")
            if chain_total > 0 and chain_total < 3:
                less_than_three_chains_ips.append(f"'{ip}' 'Reported {chain_total} chains'")
            
            model_counts[model] = model_counts.get(model, 0) + 1
        
        print("\nIPs with 1 or more chains showing 0 ASICs:")
        print("=" * 50)
        if zero_asic_ips:
            for entry in zero_asic_ips:
                print(entry)
        else:
            print("None found.")
        
        print("\nIPs reporting fewer than 3 chains:")
        print("=" * 50)
        if less_than_three_chains_ips:
            for entry in less_than_three_chains_ips:
                print(entry)
        else:
            print("None found.")
        
        print("\nASIC Statistics Summary:")
        print("=" * 50)
        total_miners = len(results)
        print(f"Total miners found: {total_miners}")
        print(f"Total ASICs detected: {total_asic_count}")
        
        total_expected = 0
        for model, count in model_counts.items():
            if model in AntminerScanner.MODEL_ASIC_COUNTS:
                expected_per_miner = AntminerScanner.MODEL_ASIC_COUNTS[model] * 3
                total_expected += expected_per_miner * count
                print(f"Detected {model}: {count} (Expected ASICs per miner: {expected_per_miner})")
            else:
                print(f"Unknown model '{model}' detected: {count} miners")
        
        print(f"Total ASICs expected: {total_expected}")
        percentage_online = (total_asic_count / total_expected * 100) if total_expected > 0 else 0
        print(f"Percentage of ASICs online: {percentage_online:.2f}%")

        total_chains_expected = 480 * 3  # Hardcoded to match expected 480 miners
        chains_offline += (total_chains_expected - total_chains)
        print(f"\nTotal chains online (>0 ASICs): {chains_online}")
        print(f"Total chains offline (0 ASICs or missing): {chains_offline}")
        print(f"Total chains expected (3 per miner, assuming 480 miners): {total_chains_expected}")
        chain_percentage_online = (chains_online / total_chains_expected * 100) if total_chains_expected > 0 else 0
        print(f"Percentage of chains online: {chain_percentage_online:.2f}%")

if __name__ == "__main__":
    main()
