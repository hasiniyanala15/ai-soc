from scapy.all import sniff
print("Starting sniff test...")
try:
    packets = sniff(count=1, timeout=5)
    if packets:
        print(f"Success! Sniffed: {packets[0].summary()}")
    else:
        print("Success! No packets found in 5s, but sniffing works.")
except Exception as e:
    print(f"Error sniffing: {e}")
