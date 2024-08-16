# XDP TCP/ICMP Filtro básico

Este script proporciona un filtro XDP (eBPF) para proteger una interfaz de red de ataques TCP y ICMP. El programa está diseñado para ser utilizado en un entorno Linux y se centra en la detección y filtrado de tráfico de red potencialmente malicioso.

## Descripción

El programa XDP implementa un filtro de red que examina los paquetes TCP e ICMP y descarta aquellos que coincidan con patrones de ataque conocidos, como SYN Flood, FIN Flood, RST Flood, y varios otros ataques TCP. También filtra ciertos tipos de paquetes ICMP, como Ping of Death y Smurf Attack.

## Características

- Filtrado de paquetes TCP con base en flags TCP y longitud del encabezado.
- Filtrado de paquetes ICMP para proteger contra ataques comunes.
- Utiliza la infraestructura XDP para procesamiento de paquetes a nivel de kernel.

## Requisitos

- Un sistema Linux con soporte para XDP y eBPF.
- Clang y LLVM para compilar el programa.
- Herramientas de red como `ip` y `bpftool` para cargar y verificar el programa XDP.

## Compilación

1. **Instalar Dependencias**:

   Asegúrate de tener Clang y las herramientas necesarias instaladas. Puedes instalar estas herramientas en una distribución basada en Debian/Ubuntu usando:

   ```bash
   sudo apt-get update
   sudo apt-get install clang llvm libelf-dev gcc make iproute2
2. **Compilar el Programa:**
   Utiliza Clang para compilar el código fuente en bytecode BPF:
   ```bash
   clang -O2 -target bpf -c xdp-tcpsyn.c -o xdp-tcpsyn.o
## Cargar el Programa XDP
Usa la herramienta `ip` para cargar el programa en la interfaz de red:
   ```bash
   ip link set dev eth0 xdp obj xdp-tcpsyn.o
   ```
Reemplaza `eth0` con el nombre de tu interfaz de red.

## Verificar el Programa
Verifica que el programa se ha cargado correctamente:
   ```bash
   bpftool prog show
   ip link show dev eth0
   ```
## Desactivar el Programa
Si necesitas desactivar el programa XDP, usa:
   ```bash
   ip link set dev eth0 xdp off
   ```





