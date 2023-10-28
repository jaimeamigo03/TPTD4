from scapy.all import *
import threading

def portscanner(destination, comando, start_port, end_port, result):
    cant_puertos_open = 0
    cant_puertos_filtered = 0
    TOUT = 0.5

    for dest_port in range(start_port, end_port + 1):
        print(f"Thread {threading.current_thread().name} - Escaneando puerto {dest_port} de {end_port}")

        packet = IP(dst=destination) / TCP(dport=dest_port, flags="S")
        SYNACK = sr1(packet, timeout=TOUT, verbose=0)

        if SYNACK is None:
            result[dest_port] = "filtered"
            cant_puertos_filtered += 1
        elif SYNACK.haslayer(TCP) and SYNACK['TCP'].flags == "SA":
            if comando == "-h":
                result[dest_port] = "open"
                cant_puertos_open += 1
            elif comando == "-f":
                PAYLOAD_ACK = IP(dst=SYNACK.src) / TCP(dport=SYNACK.sport, ack=SYNACK.getlayer(TCP).seq + 1, flags="A") / "Hello, world!"
                ACK = sr1(PAYLOAD_ACK, timeout=TOUT, verbose=0)
                if ACK is None:
                    result[dest_port] = "filtered"
                    cant_puertos_filtered += 1
                elif ACK.haslayer(TCP) and ACK['TCP'].flags == 'A':
                    result[dest_port] = "open"
                    cant_puertos_open += 1
                else:
                    result[dest_port] = "filtered"
                    cant_puertos_filtered += 1
        else:
            result[dest_port] = "filtered"
            cant_puertos_filtered += 1

    print(f"Thread {threading.current_thread().name} - Escaneo completo.")

# Define the destination and command here
destination = "target_ip"
comando = "-h"

# Split the port range into 10 threads
port_range = range(1, 1001)
split_port_ranges = [port_range[i:i + len(port_range) // 10] for i in range(0, len(port_range), len(port_range) // 10)]

results = [None] * 1001  # To store the results

# Create 10 threads
threads = []
for i, port_range in enumerate(split_port_ranges):
    start_port = port_range[0]
    end_port = port_range[-1]
    thread = threading.Thread(target=portscanner, args=(destination, comando, start_port, end_port, results))
    thread.name = f"Thread-{i + 1}"
    threads.append(thread)
    thread.start()

# Wait for all threads to complete
for thread in threads:
    thread.join()

# Analyze results
cant_puertos_open = results.count("open")
cant_puertos_filtered = results.count("filtered")

print("Hay {prop_open_ports} porciento de puertos abiertos".format(prop_open_ports=(cant_puertos_open * 100 / 1000)))
print("Hay {prop_filtered_ports} porciento de puertos filtrados".format(prop_filtered_ports=(cant_puertos_filtered * 100 / 1000)))
