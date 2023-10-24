import traceroute
import portscanner

if __name__ == "__main__":
    destination = input("Enter the destination: ")
    funcion = input("Que funcion quiere correr (traceroute o portscanner): ")

    if funcion == "traceroute":
        traceroute.traceRoute(destination)
    
    elif funcion == "portscanner":
        command = input("Enter the command (-h or -f): ")
        portscanner.port_scanner(destination, command)