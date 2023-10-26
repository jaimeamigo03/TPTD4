from scapy.all import *
import socket
import time

# TraceRoute (Ejercicio 1)
def traceRoute(destination):
    TimeToLive = 1
    maxHops = 30
    hostIP = socket.gethostbyname(destination)

    print("Destination IP: {hostIP}".format(hostIP=hostIP))

    while TimeToLive <= maxHops:  # Adjust the loop condition to include maxHops
        # Create the ICMP Echo Request packet with TTL
        packet = IP(dst=destination, ttl=TimeToLive) / ICMP(type=8, code=0)

        # Capture the packet and record the timestamp before sending
        start_time = time.time()
        reply = sr1(packet, verbose=0, timeout=1)

        if reply is None:
            # If there is no response, print '*' and calculate the time
            end_time = time.time()
            print(f"[{TimeToLive}] * (Time: {int((end_time - start_time) * 1000)} ms)")
        else:
            # If a response is received, print the source IP and calculate the time
            end_time = time.time()
            print(f"[{TimeToLive}] {reply.src} (Time: {int((end_time - start_time) * 1000)} ms)")

            # Stop when we reach the destination
            if reply.src == hostIP:
                break

        TimeToLive += 1

if __name__ == "__main__":
    destination = input("Destino: ")
    traceRoute(destination)
