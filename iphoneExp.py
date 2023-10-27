from scapy.all import IP, TCP, sr1
import threading

# Replace with the iPhone's actual IP address
iphone_ip = "10.9.20.36"  # Example IP address

def ping_thread(iphone_ip):
    # Create an ICMP packet (ping)
    ping_packet = IP(dst=iphone_ip) / TCP(dport=80, sport=80, flags="S")

    # Send the packet and wait for a response
    response = sr1(ping_packet, timeout=2)

    # Check if a response was received
    if response:
        print(f"Response received from {iphone_ip}")
    else:
        print(f"No response from {iphone_ip}")

# Create 4 threads
threads = []
for _ in range(4):
    thread = threading.Thread(target=ping_thread, args=(iphone_ip,))
    threads.append(thread)
    thread.start()

# Wait for all threads to finish
for thread in threads:
    thread.join()