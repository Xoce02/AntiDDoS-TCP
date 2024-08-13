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
