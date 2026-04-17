import pyshark
import sys
import ipaddress
from collections import Counter

def run_analysis(pcap_file):
    # Setup trackers
    protocols = Counter()
    external_comms = Counter()
    dns_destinations = Counter()
    
    # Trusted DNS list (Google, Cloudflare, etc.)
    # You can add your local router IP here too
    TRUSTED_DNS = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']

    print(f"[*] Analyzing: {pcap_file}")
    
    try:
        # keep_packets=False processes packets one-by-one to save memory
        cap = pyshark.FileCapture(pcap_file, keep_packets=False)
        
        for pkt in cap:
            try:
                # 1. Track highest layer protocol (e.g., HTTP, DNS, TCP)
                protocols[pkt.highest_layer] += 1
                
                # 2. Identify Foreign/External IPs
                if 'IP' in pkt:
                    src = pkt.ip.src
                    dst = pkt.ip.dst
                    
                    # If the IP is NOT in a private range (192.168.x.x, etc.), it's external
                    if not ipaddress.ip_address(src).is_private:
                        external_comms[src] += 1
                    if not ipaddress.ip_address(dst).is_private:
                        external_comms[dst] += 1
                
                # 3. Monitor DNS query destinations
                if 'DNS' in pkt:
                    dns_server = pkt.ip.dst
                    dns_destinations[dns_server] += 1
                    
                    # Alert if DNS is going somewhere weird
                    if dns_server not in TRUSTED_DNS and hasattr(pkt.dns, 'qry_name'):
                        print(f"  [!] Non-standard DNS: {pkt.dns.qry_name} -> {dns_server}")

            except AttributeError:
                # Some packets might not have the expected attributes; skip them
                continue
        
        cap.close()

        # --- Final Readout ---
        print("\n" + "="*30)
        print("       ANALYSIS RESULTS")
        print("="*30)
        
        print("\nTOP PROTOCOLS:")
        for proto, count in protocols.most_common(5):
            print(f" - {proto}: {count}")

        print("\nMOST ACTIVE EXTERNAL IPs:")
        for ip, count in external_comms.most_common(5):
            print(f" - {ip}: {count} interactions")

        print("\nDNS SERVERS ACCESSED:")
        for server, count in dns_destinations.most_common(5):
            status = "(Trusted)" if server in TRUSTED_DNS else "(Unknown/Foreign)"
            print(f" - {server} {status}: {count}")

    except FileNotFoundError:
        print(f"Error: The file '{pcap_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Check if a filename was provided as a command line argument
    if len(sys.argv) < 2:
        print("Usage: python analyze.py <filename.pcap>")
    else:
        target_file = sys.argv[1]
        run_analysis(target_file)