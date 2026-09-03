#!/usr/bin/env python3
"""
Programa de Cifrado y Descifrado Simétrico con Fernet
=====================================================
Este programa permite cifrar y descifrar texto plano o claves utilizando el algoritmo Fernet
(basado en AES-128 en modo CBC con HMAC-SHA256 para autenticación de integridad).

Soporta dos formas de clave:
1. Clave Fernet generada aleatoriamente (32 bytes codificados en Base64).
2. Clave de usuario (passphrase) derivada mediante PBKDF2HMAC con SHA-256.

Requisitos:
    - cryptography
    - colorama

Uso Interactivo:
    python3 encriptacion_fernet.py

Uso en Línea de Comandos:
    python3 encriptacion_fernet.py --gen-key --out mi_clave.key
    python3 encriptacion_fernet.py -e "Texto Secreto" -p "MiContraseña123"
    python3 encriptacion_fernet.py -d "gAAAAAB..." -p "MiContraseña123"

Autor: Taller Seguridad Hacking
"""

import argparse
import base64
import os
import sys
from typing import Optional, Tuple
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from colorama import init, Fore, Style

# Inicializar colorama
init(autoreset=True)

# Sal fija por defecto para derivación rápida de contraseñas de demostración.
# NOTA: En aplicaciones de producción crítica se recomienda usar sales dinámicas guardadas junto al hash.
DEFAULT_SALT = b"tallerEH_salt_seguro_2026"


def generar_clave_fernet() -> bytes:
    """
    Genera una nueva clave Fernet aleatoria segura (32 bytes codificada en URL-safe Base64).

    Returns:
        bytes: Clave Fernet codificada.
    """
    return Fernet.generate_key()


def derivar_clave_desde_password(password: str, salt: bytes = DEFAULT_SALT) -> bytes:
    """
    Deriva una clave compatible con Fernet a partir de cualquier contraseña textual dada por el usuario
    utilizando el algoritmo PBKDF2HMAC con SHA256 y 400,000 iteraciones.

    Args:
        password (str): Contraseña o clave textual del usuario.
        salt (bytes): Sal para el proceso de derivación (por defecto DEFAULT_SALT).

    Returns:
        bytes: Clave de 32 bytes codificada en Base64 apta para Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=400000,
    )
    clave_derivada = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(clave_derivada)


def encriptar_texto(texto: str, clave_fernet: bytes) -> str:
    """
    Encripta una cadena de texto usando la clave Fernet especificada.

    Args:
        texto (str): Texto plano a encriptar.
        clave_fernet (bytes): Clave Fernet válida (32 bytes Base64).

    Returns:
        str: Token Fernet cifrado (texto codificado en Base64).

    Raises:
        ValueError: Si la clave no es válida para Fernet.
    """
    try:
        f = Fernet(clave_fernet)
        token_cifrado = f.encrypt(texto.encode("utf-8"))
        return token_cifrado.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Error al encriptar: {str(e)}")


def desencriptar_texto(token_cifrado: str, clave_fernet: bytes) -> str:
    """
    Desencripta un token cifrado Fernet devolviendo el texto plano original.

    Args:
        token_cifrado (str): Cadena de texto cifrada previamente.
        clave_fernet (bytes): Clave Fernet correspondiente.

    Returns:
        str: Texto plano desencriptado.

    Raises:
        ValueError: Si la clave es incorrecta o el token ha sido alterado.
    """
    try:
        f = Fernet(clave_fernet)
        texto_plano = f.decrypt(token_cifrado.encode("utf-8"))
        return texto_plano.decode("utf-8")
    except InvalidToken:
        raise ValueError("Error de autenticación/clave: La clave introducida es incorrecta o el mensaje ha sido modificado.")
    except Exception as e:
        raise ValueError(f"Error al desencriptar: {str(e)}")


def guardar_clave_en_archivo(clave: bytes, ruta_archivo: str) -> None:
    """Guarda la clave Fernet en un archivo de texto con permisos restringidos."""
    with open(ruta_archivo, "wb") as f:
        f.write(clave)
    # Ajustar permisos en sistemas Unix a lectura/escritura solo por el dueño
    try:
        os.chmod(ruta_archivo, 0o600)
    except Exception:
        pass


def cargar_clave_desde_archivo(ruta_archivo: str) -> bytes:
    """Carga una clave Fernet desde un archivo."""
    if not os.path.exists(ruta_archivo):
        raise FileNotFoundError(f"No se encontró el archivo de clave: {ruta_archivo}")
    with open(ruta_archivo, "rb") as f:
        return f.read().strip()


def menu_interactivo() -> None:
    """Proporciona una interfaz interactiva de consola para el usuario."""
    while True:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}==========================================")
        print(f"      SISTEMA DE CIFRADO CON FERNET       ")
        print(f"=========================================={Style.RESET_ALL}")
        print("1. Encriptar un texto (usando una Contraseña de usuario)")
        print("2. Desencriptar un texto (usando la Contraseña de usuario)")
        print("3. Generar una nueva Clave Fernet aleatoria y guardarla en archivo")
        print("4. Encriptar texto usando un Archivo de Clave Fernet")
        print("5. Desencriptar texto usando un Archivo de Clave Fernet")
        print("6. Salir")

        opcion = input(f"\n{Fore.YELLOW}Seleccione una opción (1-6): {Style.RESET_ALL}").strip()

        if opcion == "1":
            texto = input("Ingrese el texto o clave a encriptar: ").strip()
            if not texto:
                print(f"{Fore.RED}[!] El texto no puede estar vacío.{Style.RESET_ALL}")
                continue
            pwd = input("Ingrese su contraseña/clave secreta: ").strip()
            if not pwd:
                print(f"{Fore.RED}[!] La contraseña no puede estar vacía.{Style.RESET_ALL}")
                continue

            clave = derivar_clave_desde_password(pwd)
            token = encriptar_texto(texto, clave)

            print(f"\n{Fore.GREEN}[+] Texto encriptado con éxito:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}{Style.BRIGHT}{token}{Style.RESET_ALL}\n")

        elif opcion == "2":
            token = input("Ingrese el texto encriptado (Token Fernet): ").strip()
            if not token:
                print(f"{Fore.RED}[!] El token no puede estar vacío.{Style.RESET_ALL}")
                continue
            pwd = input("Ingrese la contraseña/clave secreta usada para encriptar: ").strip()
            if not pwd:
                print(f"{Fore.RED}[!] La contraseña no puede estar vacía.{Style.RESET_ALL}")
                continue

            clave = derivar_clave_desde_password(pwd)
            try:
                original = desencriptar_texto(token, clave)
                print(f"\n{Fore.GREEN}[+] Texto desencriptado con éxito:{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{Style.BRIGHT}{original}{Style.RESET_ALL}\n")
            except ValueError as err:
                print(f"\n{Fore.RED}[!] {err}{Style.RESET_ALL}\n")

        elif opcion == "3":
            nombre_archivo = input("Nombre del archivo para guardar la clave (ej. mi_clave.key): ").strip()
            if not nombre_archivo:
                nombre_archivo = "mi_clave.key"
            clave = generar_clave_fernet()
            guardar_clave_en_archivo(clave, nombre_archivo)
            print(f"\n{Fore.GREEN}[+] Clave Fernet generada y guardada en '{nombre_archivo}':{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{clave.decode('utf-8')}{Style.RESET_ALL}\n")

        elif opcion == "4":
            ruta = input("Ruta del archivo de clave (.key): ").strip()
            try:
                clave = cargar_clave_desde_archivo(ruta)
                texto = input("Ingrese el texto a encriptar: ").strip()
                token = encriptar_texto(texto, clave)
                print(f"\n{Fore.GREEN}[+] Texto encriptado con éxito:{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{Style.BRIGHT}{token}{Style.RESET_ALL}\n")
            except Exception as e:
                print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}\n")

        elif opcion == "5":
            ruta = input("Ruta del archivo de clave (.key): ").strip()
            try:
                clave = cargar_clave_desde_archivo(ruta)
                token = input("Ingrese el texto encriptado: ").strip()
                original = desencriptar_texto(token, clave)
                print(f"\n{Fore.GREEN}[+] Texto desencriptado con éxito:{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{Style.BRIGHT}{original}{Style.RESET_ALL}\n")
            except Exception as e:
                print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}\n")

        elif opcion == "6":
            print(f"{Fore.GREEN}¡Hasta luego!{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}[!] Opción inválida. Intente de nuevo.{Style.RESET_ALL}")


def main() -> None:
    """Manejo de línea de comandos e inicio de modo interactivo si no hay argumentos."""
    parser = argparse.ArgumentParser(
        description="Programa de encriptación y desencriptación Fernet con contraseñas o claves simétricas.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-e", "--encrypt", type=str, help="Texto plano a encriptar")
    group.add_argument("-d", "--decrypt", type=str, help="Token cifrado a desencriptar")
    group.add_argument("--gen-key", action="store_true", help="Generar una clave Fernet aleatoria")

    parser.add_argument("-p", "--password", type=str, help="Contraseña del usuario para derivar la clave Fernet")
    parser.add_argument("-k", "--key-file", type=str, help="Ruta a un archivo de clave Fernet (.key)")
    parser.add_argument("-o", "--out", type=str, help="Ruta para guardar el resultado o la clave generada")

    args = parser.parse_args()

    # Si no se pasan argumentos de acción, ejecutar modo interactivo
    if not (args.encrypt or args.decrypt or args.gen_key):
        menu_interactivo()
        return

    try:
        # Generar clave
        if args.gen_key:
            clave = generar_clave_fernet()
            out_file = args.out or "fernet.key"
            guardar_clave_en_archivo(clave, out_file)
            print(f"{Fore.GREEN}[+] Clave generada exitosamente y guardada en: {out_file}{Style.RESET_ALL}")
            print(f"Clave: {clave.decode('utf-8')}")
            return

        # Obtener la clave para cifrar o descifrar
        clave_usar: Optional[bytes] = None

        if args.password:
            clave_usar = derivar_clave_desde_password(args.password)
        elif args.key_file:
            clave_usar = cargar_clave_desde_archivo(args.key_file)
        else:
            print(f"{Fore.RED}[!] Error: Debe especificar una contraseña (-p / --password) o un archivo de clave (-k / --key-file).{Style.RESET_ALL}")
            sys.exit(1)

        if args.encrypt:
            resultado = encriptar_texto(args.encrypt, clave_usar)
            print(f"{Fore.GREEN}[+] Texto Encriptado:{Style.RESET_ALL}\n{resultado}")
            if args.out:
                with open(args.out, "w") as f:
                    f.write(resultado)
                print(f"{Fore.BLUE}[i] Resultado guardado en {args.out}{Style.RESET_ALL}")

        elif args.decrypt:
            resultado = desencriptar_texto(args.decrypt, clave_usar)
            print(f"{Fore.GREEN}[+] Texto Desencriptado:{Style.RESET_ALL}\n{resultado}")
            if args.out:
                with open(args.out, "w") as f:
                    f.write(resultado)
                print(f"{Fore.BLUE}[i] Resultado guardado en {args.out}{Style.RESET_ALL}")

    except Exception as err:
        print(f"{Fore.RED}[!] Error en la operación: {err}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
