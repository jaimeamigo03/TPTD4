def traceRoute(destination):
    TimeToLive = 1
    maxHops = 30
    hostIP = socket.gethostbyname(destination)

    print("Destination IP: {hostIP}".format(hostIP=hostIP))

    while TimeToLive <= maxHops:  # Ciclo para modificar el TTL de cada paquete
        
        # Creamos paquete con el TTL correspondiente 
        packet = IP(dst=destination, ttl=TimeToLive) / ICMP(type=8, code=0)

        # Iniciamos el tiempo para calcular el RTT
        start_time = time.time()
        reply = sr1(packet, verbose=0, timeout=1)

        if reply is None:
            # Si no hay respuesta, imprimimos "*" y calculamos el tiempo 
            end_time = time.time()
            print(f"[{TimeToLive}] * (Time: {int((end_time - start_time) * 1000)} ms)")
        else:
            # Si hay respuesta, imprimimos la IP source y calculamos el tiempo 
            end_time = time.time()
            print(f"[{TimeToLive}] {reply.src} (Time: {int((end_time - start_time) * 1000)} ms)")

            # Rompemos el ciclo si llegamos a la IP deseada
            if reply.src == hostIP:
                break

        TimeToLive += 1
