from scapy.all import *
import socket

#TraceRoute (Ejercicio 1)
def traceRoute(destination):
    TimeToLive = 1
    maxHops = 64 # Son 30 por convencion
    hostIP = socket.gethostbyname(destination)


    print("Destination IP: {hostIP}".format(hostIP=hostIP))

    while TimeToLive < maxHops:
        # Crea el ICMP Echo Request packet con TTL
        packet = IP(dst=destination, ttl=TimeToLive) / ICMP(type=8, code=0)

        # Capturamos el paquete
        reply = sr1(packet, verbose=0, timeout=1)

        if reply is None:
            # Si no hay respuesta se imprime '*'
            print(f"{TimeToLive}: *")
        else:
            # Si se recibe una respuesta, se devuelve el IP del host
            print(f"{TimeToLive}: {reply.src}")

            # Paramos cuando llegamos al destino
            if reply.src == hostIP:
                break

        TimeToLive += 1