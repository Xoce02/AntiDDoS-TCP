# FILTRO XDP TCP/ICMP

Este repositorio contiene un script de filtrado de paquetes basado en **XDP (eXpress Data Path)**, diseñado para proporcionar protección avanzada contra varios tipos de ataques a nivel de red, específicamente ataques TCP y ICMP. El script está optimizado para ser ejecutado en el kernel, lo que garantiza un alto rendimiento y una baja latencia en la detección y bloqueo de tráfico malicioso.

## Características principales

### 1. **Registro de estadísticas en tiempo real**
   El script utiliza un **mapa BPF** para registrar estadísticas sobre los paquetes TCP procesados. Este mapa permite hacer un seguimiento básico de la cantidad de paquetes TCP recibidos, lo cual es útil para monitorear el tráfico en tiempo real.

### 2. **Filtrado avanzado de paquetes TCP**
   El script filtra y bloquea varios tipos de tráfico TCP que pueden ser indicadores de ataques. Algunas de las reglas implementadas incluyen:

   - **Protección contra SYN flood**: Bloquea paquetes TCP que solo tengan el flag `SYN` activado, ya que estos son típicamente utilizados en ataques de tipo SYN flood para saturar un servidor con solicitudes de conexión falsas.
   - **Protección contra FIN flood**: Bloquea paquetes que contienen el flag `FIN` sin la presencia de un `ACK`, previniendo así ataques basados en desconexiones abruptas.
   - **RST Protection**: Bloquea paquetes con el flag `RST`, que se utilizan para finalizar conexiones, lo que puede ser explotado en ataques para cortar conexiones legítimas.
   - **Combinaciones de banderas inválidas**: Se bloquean paquetes que tienen combinaciones inválidas de flags, como `SYN + FIN`, `PSH + URG`, y otros.
   - **Protección contra ventanas TCP de tamaño 0**: Paquetes con una ventana de tamaño 0 son bloqueados, ya que pueden ser utilizados para evadir el control de congestión de la red.
   - **Protección contra IP spoofing**: Bloquea paquetes en los que la IP de origen es igual a la IP de destino, lo cual es un indicativo de ataques de **IP spoofing**.
   - **Fragmentación maliciosa**: Paquetes IP fragmentados de forma inapropiada son detectados y bloqueados.

### 3. **Filtrado avanzado de paquetes ICMP**
   Además de filtrar tráfico TCP, este script también implementa protección contra ataques de tipo ICMP flood, bloqueando las solicitudes `ECHO` (ping) y sus respuestas `ECHOREPLY` si coinciden con patrones sospechosos. Esto ayuda a prevenir que un atacante utilice el protocolo ICMP para saturar el servidor con pings continuos.

## Funcionamiento del script

El script opera en el espacio de **XDP**. Esto significa que los paquetes son procesados a nivel kernel antes de llegar a la pila de red de Linux, proporcionando un alto rendimiento y bajo consumo de recursos, ideal para entornos donde se necesita filtrar grandes volúmenes de tráfico en tiempo real.

### Flujo del procesamiento:

1. **Recepción del paquete**: El script intercepta los paquetes en la interfaz de red.
2. **Verificación de cabeceras**: Se verifica que el paquete sea un paquete IP y luego se procesa en función de si es un paquete TCP o ICMP.
3. **Filtrado de TCP**: Se analizan las banderas (flags) del paquete TCP y se decide si debe ser bloqueado o permitido según las reglas configuradas.
4. **Filtrado de ICMP**: Se identifican paquetes ICMP tipo `ECHO` y `ECHOREPLY` y se bloquean si corresponden a un patrón de ataque.
5. **Registro de estadísticas**: Los paquetes TCP que pasan el filtro se registran en el mapa BPF para su monitoreo en tiempo real.


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





