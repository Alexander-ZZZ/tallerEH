# Taller de Ciberseguridad y Hacking Ético - Scripts en Python (`tallerEH`)

Este repositorio contiene una suite de tres herramientas desarrolladas en Python para el análisis de seguridad en redes, encriptación/desencriptación de datos y evaluación de fortaleza de contraseñas.

---

## 📋 Contenido de la Suite

1. **`validador_puertos.py`**: Identifica qué puertos de internet y red local se encuentran activos/en uso e indica el proceso exacto (PID, nombre de usuario y ejecutable) que los está ocupando.
2. **`encriptacion_fernet.py`**: Cifra y descifra mensajes o secretos utilizando el algoritmo Fernet (AES-128-CBC + HMAC-SHA256), permitiendo usar contraseñas de usuario (con derivación PBKDF2) o claves Fernet aleatorias de 32 bytes.
3. **`validador_contrasena.py`**: Evalúa si una contraseña es **SEGURA** o **INSEGURA** analizando diversidad de caracteres, longitud, entropía de información, secuencias repetitivas y contraste con listas de contraseñas comunes vulneradas.

---

## 🛠️ Instalación y Requisitos

### Requisitos Previos
- Python 3.8 o superior (`python3 --version`).

### Paso 1: Clonar el Repositorio e Ingresar
```bash
git clone https://github.com/Alexander-ZZZ/tallerEH.git
cd tallerEH
```

### Paso 2: Crear e Iniciar el Entorno Virtual
```bash
python3 -m venv venv
source venv/bin/activate
```

### Paso 3: Instalar Dependencias
```bash
pip install -r requirements.txt
```

Las dependencias principales instaladas son:
- **`psutil`**: Inspección de sockets de red y procesos del sistema operativo.
- **`cryptography`**: Cifrado simétrico Fernet y derivación de clave PBKDF2HMAC.
- **`tabulate`**: Formateo de tablas en terminal.
- **`colorama`**: Estilizado con colores ANSI en la interfaz de línea de comandos.

---

## 🚀 Guía de Uso de los Scripts

### 1. Validador de Puertos y Procesos (`validador_puertos.py`)

Verifica los puertos de red que están escuchando (`LISTEN`) o con conexiones establecidas (`ESTABLISHED`) y el proceso asociado a cada uno.

#### Ejemplos de Uso:

* **Listar todos los puertos y conexiones activas:**
  ```bash
  python3 validador_puertos.py
  ```

* **Filtrar solo los puertos que están escuchando (`LISTEN`):**
  ```bash
  python3 validador_puertos.py --status listen
  ```

* **Filtrar por protocolo TCP y un puerto específico (ej. puerto 53 o 80):**
  ```bash
  python3 validador_puertos.py --proto tcp --puerto 53
  ```

* **Exportar o ver los resultados en formato JSON:**
  ```bash
  python3 validador_puertos.py --status listen --json
  ```

> **Nota:** Para ver los procesos que pertenecen a `root` o al sistema, ejecute el script con privilegios elevados (`sudo python3 validador_puertos.py`).

---

### 2. Programa de Cifrado y Descifrado Fernet (`encriptacion_fernet.py`)

Permite proteger información confidencial convirtiéndola en un token cifrado inalterable.

#### Modo Interactivo (Menú por Consola):
Simplemente ejecute el script sin argumentos:
```bash
python3 encriptacion_fernet.py
```

#### Modo por Línea de Comandos (CLI):

* **Encriptar un mensaje usando una contraseña de usuario:**
  ```bash
  python3 encriptacion_fernet.py -e "Mensaje ultra secreto" -p "MiContraseñaSegura2026"
  ```

* **Desencriptar el token generado:**
  ```bash
  python3 encriptacion_fernet.py -d "gAAAAABqmO3gwlRBCVPhbUSu96C5W_XWu1q..." -p "MiContraseñaSegura2026"
  ```

* **Generar una clave Fernet aleatoria de 32 bytes y guardarla en un archivo:**
  ```bash
  python3 encriptacion_fernet.py --gen-key --out mi_clave.key
  ```

* **Encriptar/Desencriptar usando un archivo de clave (.key):**
  ```bash
  # Encriptar
  python3 encriptacion_fernet.py -e "Clave Secreta" -k mi_clave.key
  # Desencriptar
  python3 encriptacion_fernet.py -d "gAAAAAB..." -k mi_clave.key
  ```

---

### 3. Validador de Seguridad de Contraseñas (`validador_contrasena.py`)

Analiza exhaustivamente la solidez de una contraseña e indica si es **SEGURA** o **INSEGURA**, otorgando un puntaje (0-100), su entropía en bits y recomendaciones específicas.

#### Modo Interactivo (con entrada oculta de contraseña):
```bash
python3 validador_contrasena.py
```

#### Modo Directo por Argumentos:
```bash
python3 validador_contrasena.py -p "K9#mP!9xL2@qZ8$w"
```

#### Criterios de Evaluación:
- **Longitud**: < 8 (Insegura), 8-11 (Moderada), >= 12 (Recomendada).
- **Variedad**: Presencia simultánea de Mayúsculas, Minúsculas, Números y Símbolos.
- **Entropía**: Cálculo matemático del espacio de búsqueda en bits ($L \times \log_2(\text{variedad})$).
- **Diccionario de Vulns**: Detección de contraseñas populares vulneradas (ej. `123456`, `password`, `qwerty`, `admin`).
- **Secuencias**: Detección de patrones consecutivos de teclado (`abc`, `123`, `aaa`).

---

## 📜 Historial de Commits del Repositorio

1. `init: agregar .gitignore y requirements.txt para dependencias del proyecto`
2. `feat: implementar validador_puertos.py para monitoreo de puertos y procesos`
3. `feat: implementar encriptacion_fernet.py para cifrado y descifrado seguro`
4. `feat: implementar validador_contrasena.py para analisis de fortaleza de claves`
5. `docs: actualizar README.md con documentacion exhaustiva de los scripts`

---

## 📄 Licencia y Uso
Desarrollado con fines educativos y de auditoría de seguridad dentro del marco de Hacking Ético.