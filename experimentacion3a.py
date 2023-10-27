from scapy.all import *
import socket
import time
import matplotlib.pyplot as plt

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
        reply = sr1(packet, verbose=0, timeout=0.25)

        if reply is None:
            end_time = time.time()
            TTL_ZERO += 1
        else:
            end_time = time.time()

            if reply.src == hostIP:
                break

        TimeToLive += 1

    return TTL_ZERO * 100 / TimeToLive

def correr_100_veces(dest):
    promedio = 0

    for i in range(11):
        promedio = promedio + traceRoute(dest)
        print(i)
    
    return promedio/10

print("UTDT")
ttl_zero_utdt = correr_100_veces("www.utdt.edu")

print("Harvard")
ttl_zero_hvd = correr_100_veces("www.harvard.edu")

print("Unisa")
ttl_zero_unisa = correr_100_veces("www.unisa.ac.za")

print("PKU")
ttl_zero_pku = correr_100_veces("www.pku.edu.cn")

print("Cambridge")
ttl_zero_cam = correr_100_veces("www.cam.ac.uk")

destinos = ["UTDT", "Harvard", "UNISA", "PKU", "Cambridge"]
porcentajes_ttl_zero = [ttl_zero_hvd, ttl_zero_unisa, ttl_zero_pku, ttl_zero_cam]

# Crear un gráfico de barras
fig, ax = plt.subplots()
bars = ax.bar(destinos, porcentajes_ttl_zero, color="cornflowerblue")
ax.set_xlabel('Destino', labelpad=15, color='black')
ax.set_ylabel('Porcentaje de ttl_zero', labelpad=15, color='black')
ax.set_title('Porcentaje de ttl_zero para diferentes destinos', pad=15, color='black', weight='bold')
ax.set_ylim(0, 100)
ax.grid(False)

# Agregar los valores en la parte superior de cada barra
bar_color = bars[0].get_facecolor()
for bar, valor in zip(bars, porcentajes_ttl_zero):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f'{valor:.2f}%', ha='center', va='bottom', color="black")

fig.tight_layout()
plt.show()