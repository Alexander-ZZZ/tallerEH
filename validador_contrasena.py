#!/usr/bin/env python3
"""
Validador y Evaluador de Seguridad de Contraseñas
=================================================
Este script analiza exhaustivamente una contraseña para determinar si es SEGURA o INSEGURA,
evaluando su longitud, variedad de caracteres, entropía de información, secuencias repetitivas
y presencia en diccionarios de contraseñas débiles comunes.

Requisitos:
    - tabulate
    - colorama

Uso Interactivo:
    python3 validador_contrasena.py

Uso en Línea de Comandos:
    python3 validador_contrasena.py -p "MiContraseña123!"

Autor: Taller Seguridad Hacking
"""

import argparse
import getpass
import math
import re
import sys
from typing import Dict, List, Any, Tuple
from tabulate import tabulate
from colorama import init, Fore, Style

# Inicializar colorama
init(autoreset=True)

# Lista integrada de contraseñas comunes e inseguras (Top contraseñas más vulneradas)
CONTRASENAS_COMUNES = {
    "123456", "password", "123456789", "12345678", "12345", "111111", "1234567",
    "sunshine", "qwerty", "iloveyou", "princess", "admin", "welcome", "654321",
    "clave", "contrasena", "secret", "password123", "abc123", "letmein", "monkey",
    "dragon", "master", "superman", "dios", "hola", "tequiero", "password12"
}

# Patrones de secuencias comunes de teclado o numéricas
SECUENCIAS_COMUNES = [
    r"123", r"234", r"345", r"456", r"567", r"678", r"789", r"890",
    r"abc", r"bcd", r"cde", r"def", r"efg", r"fgh", r"ghi",
    r"qwerty", r"asdf", r"zxcv", r"qwer"
]


def calcular_entropia(contrasena: str) -> float:
    """
    Calcula la entropía de la contraseña en bits.
    Formula: Entropía = L * log2(R)
    donde L es la longitud y R es el tamaño del juego de caracteres (conjunto de símbolos posibles).
    """
    tamano_conjunto = 0
    if re.search(r"[a-z]", contrasena):
        tamano_conjunto += 26
    if re.search(r"[A-Z]", contrasena):
        tamano_conjunto += 26
    if re.search(r"[0-9]", contrasena):
        tamano_conjunto += 10
    if re.search(r"[^a-zA-Z0-9]", contrasena):
        tamano_conjunto += 33  # Aproximación de caracteres especiales/símbolos ASCII

    if tamano_conjunto == 0 or len(contrasena) == 0:
        return 0.0

    entropia = len(contrasena) * math.log2(tamano_conjunto)
    return round(entropia, 2)


def analizar_contrasena(contrasena: str) -> Dict[str, Any]:
    """
    Analiza detalladamente una contraseña dada y devuelve un diccionario con métricas,
    clasificación de seguridad (SEGURA / INSEGURA) y recomendaciones.

    Args:
        contrasena (str): Contraseña a evaluar.

    Returns:
        Dict[str, Any]: Resultados de la evaluación.
    """
    longitud = len(contrasena)
    tiene_minusculas = bool(re.search(r"[a-z]", contrasena))
    tiene_mayusculas = bool(re.search(r"[A-Z]", contrasena))
    tiene_numeros = bool(re.search(r"[0-9]", contrasena))
    tiene_simbolos = bool(re.search(r"[^a-zA-Z0-9]", contrasena))
    entropia = calcular_entropia(contrasena)

    riesgos: List[str] = []
    recomendaciones: List[str] = []
    puntuacion = 0

    # 1. Evaluación de longitud
    if longitud < 8:
        riesgos.append("La contraseña es muy corta (menos de 8 caracteres). Es altamente vulnerable a fuerza bruta.")
        recomendaciones.append("Aumente la longitud a al menos 12 caracteres.")
    elif longitud < 12:
        puntuacion += 15
        recomendaciones.append("Recomendado: Extender la contraseña a 12 caracteres o más.")
    elif longitud < 16:
        puntuacion += 30
    else:
        puntuacion += 40

    # 2. Evaluación de diversidad de caracteres
    variedad_conteo = sum([tiene_minusculas, tiene_mayusculas, tiene_numeros, tiene_simbolos])
    if tiene_minusculas:
        puntuacion += 10
    else:
        riesgos.append("No contiene letras minúsculas (a-z).")
        recomendaciones.append("Agregue letras minúsculas.")

    if tiene_mayusculas:
        puntuacion += 10
    else:
        riesgos.append("No contiene letras mayúsculas (A-Z).")
        recomendaciones.append("Agregue letras mayúsculas.")

    if tiene_numeros:
        puntuacion += 10
    else:
        riesgos.append("No contiene números (0-9).")
        recomendaciones.append("Agregue números.")

    if tiene_simbolos:
        puntuacion += 15
    else:
        riesgos.append("No contiene caracteres especiales (!@#$%^&*...).")
        recomendaciones.append("Agregue caracteres especiales o símbolos.")

    # 3. Comprobación en lista de contraseñas comunes
    if contrasena.lower() in CONTRASENAS_COMUNES:
        puntuacion = 0
        riesgos.append("¡ALERTA CRÍTICA! La contraseña está en la lista de contraseñas más comunes del mundo.")
        recomendaciones.append("Cambie completamente la contraseña inmediatamente.")

    # 4. Comprobación de repeticiones y secuencias
    if re.search(r"(.)\1\1", contrasena):
        puntuacion -= 15
        riesgos.append("Contiene caracteres repetidos consecutivamente (ej. 'aaa', '111').")
        recomendaciones.append("Evite la repetición consecutiva de caracteres.")

    pwd_lower = contrasena.lower()
    for seq in SECUENCIAS_COMUNES:
        if seq in pwd_lower:
            puntuacion -= 10
            riesgos.append(f"Contiene secuencias obvias o predictivas (ej. '{seq}').")
            recomendaciones.append("Evite secuencias numéricas o del teclado (123, abc, qwerty).")
            break

    # Asegurar rango de puntuación entre 0 y 100
    puntuacion = max(0, min(100, puntuacion))

    # Determinar clasificación final
    if puntuacion < 40 or longitud < 8 or contrasena.lower() in CONTRASENAS_COMUNES:
        estado = "INSEGURA"
        categoria = "MUY INSEGURA" if puntuacion < 25 else "INSEGURA"
    elif puntuacion < 65:
        estado = "INSEGURA"  # Considerada aún insuficiente para entornos exigentes
        categoria = "MODERADA / INSUFICIENTE"
    elif puntuacion < 85:
        estado = "SEGURA"
        categoria = "SEGURA"
    else:
        estado = "SEGURA"
        categoria = "MUY SEGURA"

    return {
        "contrasena": contrasena,
        "longitud": longitud,
        "tiene_minusculas": tiene_minusculas,
        "tiene_mayusculas": tiene_mayusculas,
        "tiene_numeros": tiene_numeros,
        "tiene_simbolos": tiene_simbolos,
        "entropia_bits": entropia,
        "puntuacion": puntuacion,
        "estado": estado,
        "categoria": categoria,
        "riesgos": riesgos,
        "recomendaciones": recomendaciones
    }


def imprimir_reporte_evaluacion(resultado: Dict[str, Any]) -> None:
    """Muestra los resultados de la evaluación en un formato estructurado y visual."""
    estado = resultado["estado"]
    puntuacion = resultado["puntuacion"]
    categoria = resultado["categoria"]

    if estado == "SEGURA":
        color_estado = f"{Fore.GREEN}{Style.BRIGHT}"
    elif categoria == "MODERADA / INSUFICIENTE":
        color_estado = f"{Fore.YELLOW}{Style.BRIGHT}"
    else:
        color_estado = f"{Fore.RED}{Style.BRIGHT}"

    print(f"\n{Style.BRIGHT}==================================================")
    print(f"    RESULTADO DEL ANÁLISIS DE SEGURIDAD DE CLAVE")
    print(f"=================================================={Style.RESET_ALL}")

    print(f"Estado de la Contraseña: {color_estado}{estado} ({categoria}){Style.RESET_ALL}")
    print(f"Puntuación de Seguridad: {color_estado}{puntuacion} / 100{Style.RESET_ALL}")
    print(f"Entropía Estimada     : {Fore.CYAN}{resultado['entropia_bits']} bits{Style.RESET_ALL}\n")

    # Tabla de verificación de parámetros
    si_no = lambda b: f"{Fore.GREEN}Sí{Style.RESET_ALL}" if b else f"{Fore.RED}No{Style.RESET_ALL}"
    
    tabla_parametros = [
        ["Longitud total (mínimo 12)", f"{resultado['longitud']} caracteres", si_no(resultado['longitud'] >= 12)],
        ["Contiene Minúsculas (a-z)", "-", si_no(resultado['tiene_minusculas'])],
        ["Contiene Mayúsculas (A-Z)", "-", si_no(resultado['tiene_mayusculas'])],
        ["Contiene Números (0-9)", "-", si_no(resultado['tiene_numeros'])],
        ["Contiene Símbolos/Especiales", "-", si_no(resultado['tiene_simbolos'])],
    ]

    print(tabulate(tabla_parametros, headers=["Criterio", "Valor", "Cumple"], tablefmt="simple"))

    # Mostrar Riesgos detectados
    if resultado["riesgos"]:
        print(f"\n{Fore.RED}{Style.BRIGHT}Riesgos y Vulnerabilidades Detectadas:{Style.RESET_ALL}")
        for r in resultado["riesgos"]:
            print(f"  {Fore.RED}✗ {r}{Style.RESET_ALL}")

    # Mostrar Recomendaciones
    if resultado["recomendaciones"]:
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}Recomendaciones para Mejorar la Seguridad:{Style.RESET_ALL}")
        for rec in resultado["recomendaciones"]:
            print(f"  {Fore.YELLOW}➜ {rec}{Style.RESET_ALL}")
    elif estado == "SEGURA":
        print(f"\n{Fore.GREEN}✓ ¡Excelente! La contraseña cumple con los estándares modernos de ciberseguridad.{Style.RESET_ALL}")
    
    print()


def main() -> None:
    """Punto de entrada principal para ejecutar el validador."""
    parser = argparse.ArgumentParser(
        description="Script para evaluar si una contraseña es segura o insegura.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-p", "--password",
        type=str,
        help="Contraseña a evaluar directamente desde la línea de comandos"
    )

    args = parser.parse_args()

    if args.password:
        clave_evaluar = args.password
    else:
        print(f"{Fore.CYAN}{Style.BRIGHT}=== EVALUADOR DE SEGURIDAD DE CONTRASEÑAS ==={Style.RESET_ALL}")
        try:
            # Ocultar entrada del usuario por privacidad
            clave_evaluar = getpass.getpass("Ingrese la contraseña a analizar (la entrada estará oculta): ")
        except Exception:
            clave_evaluar = input("Ingrese la contraseña a analizar: ")

    if not clave_evaluar:
        print(f"{Fore.RED}[!] No se ingresó ninguna contraseña para analizar.{Style.RESET_ALL}")
        sys.exit(1)

    res = analizar_contrasena(clave_evaluar)
    imprimir_reporte_evaluacion(res)


if __name__ == "__main__":
    main()
