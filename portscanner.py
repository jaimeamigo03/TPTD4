from scapy.all import *

def portscanner(destination, comando):
    puertos = open("EstadoPuertos.txt", "w")     
    cant_puertos_open = 0
    cant_puertos_filtered = 0
    TOUT = 0.5

    for dest_port in range(1,1001):
        print(f"Escaneando puerto {dest_port} de 1000")

        # Mandamos el SYN al puerto dest_port (entre 1 y 1000)
        packet = IP(dst=destination)/TCP(dport=dest_port, flags="S")
        SYNACK = sr1(packet, timeout=TOUT,verbose=0)
        print(SYNACK)

        # Si no hay respuesta, o las flags recibidas no son las esperadas
        if SYNACK is None:
            puertos.write("Puerto {dest_port}: filtered \n".format(dest_port = dest_port))
            cant_puertos_filtered+=1

        elif SYNACK.haslayer(TCP) and SYNACK['TCP'].flags == "SA":

            if comando == "-h":
                puertos.write("Puerto {dest_port}: open \n".format(dest_port = dest_port))
                cant_puertos_open+=1

            elif comando == "-f":

                PAYLOAD_ACK = IP(dst=SYNACK.src)/TCP(dport=SYNACK.sport, ack=SYNACK.getlayer(TCP).seq+1, flags="A")/ "Hola mundo!"
                ACK = sr1(PAYLOAD_ACK, timeout=TOUT, verbose=0)
                print(ACK)

                if ACK is None:
                    puertos.write("Puerto {dest_port}: filtered \n".format(dest_port=dest_port))
                    cant_puertos_filtered+=1
                
                elif ACK.haslayer(TCP) and ACK['TCP'].flags == 'A':
                    puertos.write("Puerto {dest_port}: open \n".format(dest_port=dest_port))
                    cant_puertos_open+=1
                
                else:
                    puertos.write("Puerto {dest_port}: filtered \n".format(dest_port=dest_port))
                    cant_puertos_filtered+=1
    
        else:
            puertos.write("Puerto {dest_port}: filtered \n".format(dest_port=dest_port))
            cant_puertos_filtered+=1

    print("Hay {prop_open_ports} porciento de puertos abiertos".format(prop_open_ports = (cant_puertos_open*100/100)))
    print("Hay {prop_filtered_ports} porciento de puertos filtrados".format(prop_filtered_ports = (cant_puertos_filtered*100/100)))  