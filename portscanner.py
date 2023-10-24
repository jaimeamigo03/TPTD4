from scapy.all import *

def port_scanner(destination, comando):
    puertos = open("EstadoPuertos.txt", "w")     
    cant_puertos_open = 0
    cant_puertos_filtered = 0
    tout = 0.5

    for dest_port in range(1,1001):
        print(f"Escaneando puerto {dest_port} de 1000")

        # Mandamos el SYN al puerto dest_port (entre 1 y 1000)
        packet = IP(dst=destination)/TCP(sport=389, dport=dest_port, seq=100, ack=0, flags="S")
        syn_ack = sr1(packet, timeout=tout,verbose=0)
        print(syn_ack)

        # Si no hay respuesta, o las flags recibidas no son las esperadas
        if syn_ack is None or (syn_ack.haslayer(TCP) and str(syn_ack['TCP'].flags) != "SA"):
            puertos.write("Puerto {dest_port}: filtered \n".format(dest_port = dest_port))
            print("Puerto {dest_port}: filtered \n".format(dest_port = dest_port))
            cant_puertos_filtered+=1 

        elif syn_ack.haslayer(TCP) and syn_ack['TCP'].flags == 'SA':

            if comando == "-h":
                puertos.write("Puerto {dest_port}: open \n".format(dest_port = dest_port))
                print("Puerto {dest_port}: open \n".format(dest_port = dest_port))
                cant_puertos_open+=1

            elif comando == "-f":

                ack_con_payload = IP(dst=syn_ack.src)/TCP(sport=syn_ack.dport, dport=syn_ack.sport, seq=101, ack=syn_ack.seq+1, flags="A")/Raw(load=b"hola")
                ans = sr1(ack_con_payload, timeout=tout, verbose=0)
                print(ans)

                if ans is None:
                    puertos.write("Puerto {dest_port}: filtered \n".format(dest_port=dest_port))
                    print("Puerto {dest_port}: filtered \n".format(dest_port=dest_port))
                    cant_puertos_filtered+=1
                
                elif ans.haslayer(TCP) and ans['TCP'].flags == 'A':
                    puertos.write("Puerto {dest_port}: open \n".format(dest_port=dest_port))
                    print("Puerto {dest_port}: open \n".format(dest_port=dest_port))
                    cant_puertos_open+=1
    
    print("Hay {prop_open_ports} porciento de puertos abiertos".format(prop_open_ports = (cant_puertos_open*100/1000)))
    print("Hay {prop_filtered_ports} porciento de puertos filtrados".format(prop_filtered_ports = (cant_puertos_filtered*100/1000)))  