#!/usr/bin/env python3
"""
Validador de Puertos y Procesos Activos
======================================
Este script escanea y valida los puertos de red (internet/intranet) activos en la máquina,
mostrando qué procesos (PID, nombre de usuario y ejecutable) están ocupando cada puerto.

Requisitos:
    - psutil
    - tabulate
    - colorama

Uso:
    python3 validador_puertos.py [--proto tcp|udp|all] [--status listen|established|all] [--puerto PUERTO] [--json]

Autor: Taller Seguridad Hacking
"""

import argparse
import sys
import json
from typing import List, Dict, Any, Optional
import psutil
from tabulate import tabulate
from colorama import init, Fore, Style

# Inicializar colorama para soporte multiplataforma de colores ANSI
init(autoreset=True)


def obtener_nombre_proceso(pid: Optional[int]) -> tuple[str, str]:
    """
    Obtiene el nombre del proceso y el usuario asociado a un PID dado.

    Args:
        pid (Optional[int]): ID del proceso a consultar.

    Returns:
        tuple[str, str]: (Nombre del proceso, Usuario del proceso)
    """
    if pid is None:
        return ("N/A", "N/A")
    try:
        proc = psutil.Process(pid)
        nombre = proc.name()
        try:
            usuario = proc.username()
        except (psutil.AccessDenied, AttributeError):
            usuario = "Desconocido"
        return (nombre, usuario)
    except psutil.NoSuchProcess:
        return ("Proceso finalizado", "N/A")
    except psutil.AccessDenied:
        return ("Acceso Denegado", "Requiere Root/Admin")
    except Exception as e:
        return (f"Error ({type(e).__name__})", "N/A")


def obtener_conexiones_red(
    protocolo: str = "all",
    estado_filtro: str = "all",
    puerto_filtro: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Obtiene la lista de conexiones de red activas aplicando filtros opcionales.

    Args:
        protocolo (str): 'tcp', 'udp', o 'all'.
        estado_filtro (str): 'listen', 'established', o 'all'.
        puerto_filtro (Optional[int]): Número de puerto específico a filtrar.

    Returns:
        List[Dict[str, Any]]: Lista de diccionarios con información detallada de cada puerto/conexión.
    """
    kind_map = {
        "tcp": "tcp",
        "udp": "udp",
        "all": "inet"
    }

    kind = kind_map.get(protocolo.lower(), "inet")
    
    try:
        conexiones = psutil.net_connections(kind=kind)
    except psutil.AccessDenied:
        print(f"{Fore.RED}[!] Error: Permiso denegado al listar conexiones del sistema. Ejecute con sudo/administrador para ver todas las conexiones.{Style.RESET_ALL}")
        # Intentar obtener conexiones parciales si es posible
        conexiones = []
    except Exception as err:
        print(f"{Fore.RED}[!] Error al consultar conexiones: {err}{Style.RESET_ALL}")
        return []

    resultados = []

    for conn in conexiones:
        # Extraer dirección local
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        puerto_local = conn.laddr.port if conn.laddr else None

        # Extraer dirección remota
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"

        # Tipo de socket (TCP / UDP)
        tipo_socket = "TCP" if conn.type == 1 else "UDP" if conn.type == 2 else f"Tipo_{conn.type}"

        # Estado de la conexión
        estado = conn.status if conn.status else ("UDP_OPEN" if tipo_socket == "UDP" else "DESCONOCIDO")

        # Filtrado por estado si aplica
        if estado_filtro.lower() == "listen" and estado != psutil.CONN_LISTEN:
            continue
        elif estado_filtro.lower() == "established" and estado != psutil.CONN_ESTABLISHED:
            continue

        # Filtrado por puerto si aplica
        if puerto_filtro is not None and puerto_local != puerto_filtro:
            continue

        # Obtener información del proceso
        pid = conn.pid
        proc_nombre, proc_usuario = obtener_nombre_proceso(pid)

        resultados.append({
            "proto": tipo_socket,
            "ip_local": conn.laddr.ip if conn.laddr else "N/A",
            "puerto_local": puerto_local,
            "laddr": laddr,
            "raddr": raddr,
            "estado": estado,
            "pid": pid if pid is not None else "N/A",
            "proceso": proc_nombre,
            "usuario": proc_usuario
        })

    return resultados


def colorear_estado(estado: str) -> str:
    """Aplica colores ANSI al estado de la conexión para mejorar visualización."""
    if estado == psutil.CONN_LISTEN:
        return f"{Fore.GREEN}{estado}{Style.RESET_ALL}"
    elif estado == psutil.CONN_ESTABLISHED:
        return f"{Fore.CYAN}{estado}{Style.RESET_ALL}"
    elif estado in ("TIME_WAIT", "CLOSE_WAIT"):
        return f"{Fore.YELLOW}{estado}{Style.RESET_ALL}"
    return f"{Fore.WHITE}{estado}{Style.RESET_ALL}"


def mostrar_reporte_consola(conexiones: List[Dict[str, Any]]) -> None:
    """Muestra la tabla de conexiones en la consola utilizando formato de tabla."""
    if not conexiones:
        print(f"\n{Fore.YELLOW}[i] No se encontraron puertos ni conexiones activas con los criterios especificados.{Style.RESET_ALL}")
        return

    tabla = []
    for c in conexiones:
        pid_str = f"{Fore.MAGENTA}{c['pid']}{Style.RESET_ALL}"
        proc_str = f"{Style.BRIGHT}{c['proceso']}{Style.RESET_ALL}"
        proto_str = f"{Fore.BLUE}{c['proto']}{Style.RESET_ALL}"
        
        tabla.append([
            proto_str,
            c["laddr"],
            c["raddr"],
            colorear_estado(c["estado"]),
            pid_str,
            proc_str,
            c["usuario"]
        ])

    encabezados = ["Protocolo", "Dirección Local", "Dirección Remota", "Estado", "PID", "Proceso", "Usuario"]
    
    print(f"\n{Fore.GREEN}{Style.BRIGHT}=== REPORTES DE PUERTOS Y PROCESOS EN USO ==={Style.RESET_ALL}")
    print(f"Total de puertos/conexiones detectadas: {len(conexiones)}\n")
    print(tabulate(tabla, headers=encabezados, tablefmt="fancy_grid"))


def main() -> None:
    """Punto de entrada principal para el script de consola."""
    parser = argparse.ArgumentParser(
        description="Script de validación de puertos de internet/red en uso y sus procesos asociados.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "-p", "--proto",
        choices=["tcp", "udp", "all"],
        default="all",
        help="Filtrar por protocolo: tcp, udp o all (por defecto: all)"
    )
    
    parser.add_argument(
        "-s", "--status",
        choices=["listen", "established", "all"],
        default="all",
        help="Filtrar por estado: listen (escuchando), established (establecido) o all (todos)"
    )
    
    parser.add_argument(
        "-pt", "--puerto",
        type=int,
        default=None,
        help="Filtrar por número de puerto específico (ej. 80, 443, 22)"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Exportar/mostrar resultados en formato JSON"
    )

    args = parser.parse_args()

    # Ejecutar escaneo
    conexiones = obtener_conexiones_red(
        protocolo=args.proto,
        estado_filtro=args.status,
        puerto_filtro=args.puerto
    )

    if args.json:
        print(json.dumps(conexiones, indent=4, ensure_ascii=False))
    else:
        mostrar_reporte_consola(conexiones)


if __name__ == "__main__":
    main()
