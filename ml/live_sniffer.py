from scapy.all import sniff, IP, TCP, UDP, IPv6, conf
import os

def capture_live_packet():
    """
    Captures live packets from the network for a 3-second window, groups them into flows,
    and calculates true network statistics for the most active flow.
    """
    try:
        # Get timeout from environment, default to 3
        timeout_val = int(os.environ.get("SNIFFER_TIMEOUT", 3))
        if timeout_val < 1:
            return {"error": "SNIFFER_TIMEOUT must be at least 1 second."}

        # Scapy's default interface can differ between machines or processes.
        # Allow an explicit Scapy interface name (for example, \Device\NPF_{...}).
        interface = os.environ.get("SNIFFER_INTERFACE") or None
        
        # Sniff packets for dynamic timeout window
        packets = sniff(iface=interface, timeout=timeout_val)
        
        if not packets:
            selected_interface = interface or str(conf.iface)
            return {
                "error": (
                    f"No packets were captured on '{selected_interface}' within "
                    f"{timeout_val} seconds. Check that this is the active network "
                    "interface and that traffic is present."
                )
            }
            
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
                    'dst_ip': dst,
                    'dst_port': dport, 
                    'proto': proto
                }
                
        if not flows:
            return {"error": "No valid IP/IPv6 flows captured."}
            
        # Process ALL flows
        processed_flows = []
        for flow_key, flow_data in flows.items():
            pkts = flow_data['packets']
            pkts.sort(key=lambda x: x[2])
            
            start_time = pkts[0][2]
            end_time = pkts[-1][2]
            duration_sec = float(end_time - start_time)
            flow_duration = duration_sec * 1_000_000
            
            fwd_pkts = sum(1 for p in pkts if p[1] == 'fwd')
            bwd_pkts = sum(1 for p in pkts if p[1] == 'bwd')
            fwd_length = sum(p[3] for p in pkts if p[1] == 'fwd')
            bwd_length = sum(p[3] for p in pkts if p[1] == 'bwd')
            total_length = fwd_length + bwd_length
            
            flow_bytes_s = (total_length / duration_sec) if duration_sec > 0 else 0.0
                
            packet_features = {
                "Source IP": flow_data['src_ip'],
                "Destination IP": flow_data.get('dst_ip', 'Unknown'),
                "Flow Duration": flow_duration,
                "Total Fwd Packets": fwd_pkts,
                "Total Backward Packets": bwd_pkts,
                "Total Length of Fwd Packets": fwd_length,
                "Destination Port": flow_data['dst_port'],
                "Protocol": flow_data['proto'],
                "Flow Bytes/s": flow_bytes_s,
                "Failed Logins": 0
            }
            processed_flows.append(packet_features)
            
        summary = f"Analyzed {len(processed_flows)} distinct flows."
        return {"status": "success", "packets": processed_flows, "raw_summary": summary}
        
    except Exception as e:
        return {"error": f"Failed to sniff packet: {str(e)}"}
