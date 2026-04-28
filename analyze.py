import pyshark
import sys
import ipaddress
from collections import Counter

def run_analysis(pcap_file):
    # Setup trackers
    protocols = Counter()
    external_comms = Counter()
    dns_destinations = Counter()
    dns_queries = Counter()
    suspicious_dns = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    src_ports = Counter()
    dst_ports = Counter()
    flow_pairs = Counter()
    alerts = []
    
    # Trusted DNS list (Google, Cloudflare, etc.)
    # You can add your local router IP here too
    TRUSTED_DNS = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']


    #Common Domain names to reduce noise 
    COMMON_DOMAINS = [
    "microsoft.com", "msn.com", "bing.com",
    "windows.com", "office.com", "live.com"
    ]

    #Suspcious_tlds these are smaples
    SUSPICIOUS_TLDS = (".xyz", ".top", ".ru")

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

                    src_ips[src] += 1
                    dst_ips[dst] += 1
                    flow_pairs[(src, dst)] += 1
                    
                    # If the IP is NOT in a private range (192.168.x.x, etc.), it's external
                    if not ipaddress.ip_address(src).is_private:
                        external_comms[src] += 1
                    if not ipaddress.ip_address(dst).is_private:
                        external_comms[dst] += 1

                #Identify Ports
                if 'TCP' in pkt:
                    src_ports[pkt.tcp.srcport] += 1
                    dst_ports[pkt.tcp.dstport] += 1
                elif 'UDP' in pkt:
                    src_ports[pkt.udp.srcport] += 1
                    dst_ports[pkt.udp.dstport] += 1
                
                # 3. Monitor DNS query destinations
                if 'DNS' in pkt and 'IP' in pkt and hasattr(pkt.dns, 'qry_name'):
                    domain = pkt.dns.qry_name.lower().strip(".")
                    dns_server = pkt.ip.dst

                    # ignore common domains to reduce noise
                    if any(common in domain for common in COMMON_DOMAINS):
                        continue

                    dns_queries[domain] += 1

                    # only track external DNS servers as suspicious
                    if not ipaddress.ip_address(dns_server).is_private:
                        dns_destinations[dns_server] += 1

                    # real malware signal: suspicious TLDs
                    if domain.endswith(SUSPICIOUS_TLDS):
                        suspicious_dns[domain] += 1
            # Some packets might not have the expected attributes; skip them
            except AttributeError:  
                continue
            except ValueError:
                continue

        
        cap.close()

       
        # Rules for detecting suspicous behavor and to build final alerts after processing
        for domain, count in suspicious_dns.items():
            if count >= 1:
                alerts.append(f"Suspicious domain detected: {domain} ({count} queries)")

        for server, count in dns_destinations.items():
            if count > 3:
                alerts.append(f"Repeated DNS queries sent to external DNS server {server} ({count} times)")

        for ip, count in external_comms.items():
            if count > 300:
                alerts.append(f"Very high communication volume with external IP {ip} ({count} interactions)")

        for (src, dst), count in flow_pairs.items():
            if count > 100:
                alerts.append(f"High repeated traffic between {src} -> {dst} ({count} packets)")

         # Final Readout
        print("\n" + "=" * 30)
        print("       ANALYSIS RESULTS")
        print("=" * 30)

        print("\nTOP PROTOCOLS:")
        for proto, count in protocols.most_common(5):
            print(f" - {proto}: {count}")

        print("\nTOP SOURCE IPs:")
        for ip, count in src_ips.most_common(5):
            print(f" - {ip}: {count}")

        print("\nTOP DESTINATION IPs:")
        for ip, count in dst_ips.most_common(5):
            print(f" - {ip}: {count}")

        print("\nTOP SOURCE PORTS:")
        for port, count in src_ports.most_common(5):
            print(f" - {port}: {count}")

        print("\nTOP DESTINATION PORTS:")
        for port, count in dst_ports.most_common(5):
            print(f" - {port}: {count}")

        print("\nTOP FLOW PAIRS:")
        for (src, dst), count in flow_pairs.most_common(5):
            print(f" - {src} -> {dst}: {count}")

        print("\nMOST ACTIVE EXTERNAL IPs:")
        for ip, count in external_comms.most_common(5):
            print(f" - {ip}: {count} interactions")

        print("\nTOP DNS QUERIES:")
        for domain, count in dns_queries.most_common(5):
            print(f" - {domain}: {count}")

        print("\nEXTERNAL DNS SERVERS ACCESSED:")
        if dns_destinations:
            for server, count in dns_destinations.most_common(5):
                status = "(Trusted)" if server in TRUSTED_DNS else "(Unknown/Foreign)"
                print(f" - {server} {status}: {count}")
        else:
            print(" - None")

        print("\nSUSPICIOUS DNS DOMAINS:")
        if suspicious_dns:
            for domain, count in suspicious_dns.most_common(5):
                print(f" - {domain}: {count}")
        else:
            print(" - None detected")

        print("\nALERTS:")
        if alerts:
            for alert in alerts:
                print(f" [!] {alert}")
        else:
            print(" - No major alerts found")

    except FileNotFoundError:
        print(f"Error: The file '{pcap_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze.py <filename.pcap>")
    else:
        target_file = sys.argv[1]
        run_analysis(target_file)

