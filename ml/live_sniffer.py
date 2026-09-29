from scapy.all import sniff, IP, TCP, UDP, IPv6
from collections import defaultdict
import time
import os

def capture_live_packet():
    """
    Captures live packets from the network for a 3-second window, groups them into flows,
    and calculates true network statistics for the most active flow.
    """
    try:
        # Get timeout from environment, default to 3
        timeout_val = int(os.environ.get("SNIFFER_TIMEOUT", 3))
        
        # Sniff packets for dynamic timeout window
        packets = sniff(timeout=timeout_val)
        
        if not packets:
            return {"error": "No packets found on interface within timeout."}
            
        flows = {}
        
        for pkt in packets:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt[IP].proto
                length = pkt[IP].len
            elif IPv6 in pkt:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst
                proto = pkt[IPv6].nh
                length = pkt[IPv6].plen
            else:
                continue
                
            sport = 0
            dport = 0
            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                
            flow_key_fwd = (src, dst, sport, dport, proto)
            flow_key_bwd = (dst, src, dport, sport, proto)
            
            if flow_key_fwd in flows:
                flows[flow_key_fwd]['packets'].append((pkt, 'fwd', pkt.time, length))
            elif flow_key_bwd in flows:
                flows[flow_key_bwd]['packets'].append((pkt, 'bwd', pkt.time, length))
            else:
                flows[flow_key_fwd] = {
                    'packets': [(pkt, 'fwd', pkt.time, length)], 
                    'src_ip': src, 
                    'dst_port': dport, 
                    'proto': proto
                }
                
        if not flows:
            return {"error": "No valid IP/IPv6 flows captured."}
            
        # Select the flow with the most packets to analyze
        best_flow_key = max(flows, key=lambda k: len(flows[k]['packets']))
        flow_data = flows[best_flow_key]
        pkts = flow_data['packets']
        
        # Sort packets by time
        pkts.sort(key=lambda x: x[2])
        
        start_time = pkts[0][2]
        end_time = pkts[-1][2]
        duration_sec = float(end_time - start_time)
        
        # CIC-IDS2017 uses Microseconds for flow duration
        flow_duration = duration_sec * 1_000_000
        
        fwd_pkts = sum(1 for p in pkts if p[1] == 'fwd')
        bwd_pkts = sum(1 for p in pkts if p[1] == 'bwd')
        
        fwd_length = sum(p[3] for p in pkts if p[1] == 'fwd')
        bwd_length = sum(p[3] for p in pkts if p[1] == 'bwd')
        total_length = fwd_length + bwd_length
        
        # Calculate Flow Bytes/s
        if flow_duration > 0:
            flow_bytes_s = (total_length / duration_sec)
        else:
            # If duration is 0 (e.g., single packet), flow bytes/s is technically undefined,
            # but usually represented as 0 or total length in datasets for isolated packets
            flow_bytes_s = 0.0
            
        packet_features = {
            "Source IP": flow_data['src_ip'],
            "Flow Duration": flow_duration,
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": bwd_pkts,
            "Total Length of Fwd Packets": fwd_length,
            "Destination Port": flow_data['dst_port'],
            "Protocol": flow_data['proto'],
            "Flow Bytes/s": flow_bytes_s,
            "Failed Logins": 0 # This dataset feature is rarely populated from pure pcap without deep inspection
        }
        
        summary = f"Flow {flow_data['src_ip']} -> Port {flow_data['dst_port']} | {len(pkts)} pkts | {flow_duration/1000:.1f}ms"
        
        return {"status": "success", "packet": packet_features, "raw_summary": summary}
        
    except Exception as e:
        return {"error": f"Failed to sniff packet: {str(e)}"}
