from scapy.all import *
import socket
import time

# TraceRoute (Ejercicio 1)
def traceRoute(destination):
    TimeToLive = 1
    maxHops = 30
    hostIP = socket.gethostbyname(destination)
    TTL_ZERO = 0

    print("Destination IP: {hostIP}".format(hostIP=hostIP))

    while TimeToLive <= maxHops:  

        packet = IP(dst=destination, ttl=TimeToLive) / ICMP(type=8, code=0)

        start_time = time.time()
        reply = sr1(packet, verbose=0, timeout=1)

        if reply is None:
            
            end_time = time.time()
            print(f"[{TimeToLive}] * (Time: {int((end_time - start_time) * 1000)} ms)")
            TTL_ZERO+=1

        else:
            
            end_time = time.time()
            print(f"[{TimeToLive}] {reply.src} (Time: {int((end_time - start_time) * 1000)} ms)")

            
            if reply.src == hostIP:
                break

        TimeToLive += 1

    return TTL_ZERO*100/30

traceRoute("www.utdt.edu")
traceRoute("www.harvard.edu")
traceRoute("www.unisa.ac.za")
traceRoute("www.pku.edu.cn")
traceRoute("www.cam.ac.uk")