from scapy.all import *
import socket

#TraceRoute (Ejercicio 1)
def traceRoute(destination):
    TimeToLive = 1
    maxHops=31 # Son 30 por convencion
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

def port_scanner(destination, comando):
    puertos = open("EstadoPuertos.txt", "w")     
    cant_puertos_open = 0
    cant_puertos_filtered = 0
    tout = 0.5

    for dest_port in range(1001):
        print(f"Escaneando puerto {dest_port} de 1000")

        packet = IP(dst=destination)/TCP(flags="S", dport = dest_port)
        reply = sr1(packet, timeout=tout,verbose=0)

        if reply is None:
            puertos.write("Puerto {dest_port}: filtered \n".format(dest_port = dest_port))
            print("Puerto {dest_port}: filtered \n".format(dest_port = dest_port))
            cant_puertos_filtered+=1 

        elif reply.haslayer(TCP) and reply['TCP'].flags == 'SA':
            if comando == "-h":
                puertos.write("Puerto {dest_port}: open \n".format(dest_port = dest_port))
                print("Puerto {dest_port}: open \n".format(dest_port = dest_port))
                cant_puertos_open+=1

            elif comando == "-f":
                packet2 = IP(dst=destination)/TCP(flags="A", dport = dest_port)/Raw(load=b"hola")
                reply2 = sr1(packet2, timeout=tout, verbose=0)

                if reply2 is None:
                    puertos.write("Puerto {dest_port}: filtered \n".format(dest_port=dest_port))
                    print("Puerto {dest_port}: filtered \n".format(dest_port=dest_port))
                    cant_puertos_filtered+=1
                
                elif reply2.haslayer(TCP) and reply2['TCP'].flags == 'A':
                    puertos.write("Puerto {dest_port}: open \n".format(dest_port=dest_port))
                    print("Puerto {dest_port}: open \n".format(dest_port=dest_port))
                    
                    cant_puertos_open+=1
    
    print("Hay {prop_open_ports} porciento de puertos abiertos".format(prop_open_ports = (cant_puertos_open*100/i)))
    print("Hay {prop_filtered_ports} porciento de puertos filtrados".format(prop_filtered_ports = (cant_puertos_filtered*100/i)))  

if __name__ == "__main__":
    destination = input("Enter the destination: ")
    funcion = input("Que funcion quiere correr (traceroute o portscanner): ")

    if funcion == "traceroute":
        traceRoute(destination)
    
    elif funcion == "portscanner":
        command = input("Enter the command (-h or -f): ")
        port_scanner(destination, command)