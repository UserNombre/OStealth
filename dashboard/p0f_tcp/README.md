# OStealth – TCP Fingerprinting Dashboard (Streamlit)

**Antes de ejecutar el dashboard, es necesario instalar las dependencias de Python indicadas en `requirements.txt` usando un entorno virtual `venv`**.

Este dashboard proporciona una interfaz visual para OStealth, con el objetivo de observar y comparar características de fingerprinting TCP/IP (TTL, window size, opciones TCP, flags, etc.).

---

## 📁 Estructura del directorio

```
p0f_tcp/
├── app.py
├── requirements.txt
├── README.md
├── syn.log              # log de ejemplo (opcional)
├── tcpdump.log          # log de ejemplo (opcional)
└── venv/
```

---

## 🐍 Instalación del entorno Python

Desde el directorio del dashboard:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🚀 Ejecución del dashboard (Streamlit)

Con el entorno virtual activado:

```bash
streamlit run app.py
```

El dashboard estará disponible en: **http://localhost:8501**

> ⚠️ **No ejecutes Streamlit con sudo.**

---

## 📡 Captura de tráfico TCP (input del dashboard)

### Captura recomendada (todo TCP)

```bash
sudo tcpdump -i any -n -tt -vvv -l tcp | tee tcpdump.log
```

### Captura solo de paquetes SYN (más limpia)

```bash
sudo tcpdump -i any -n -tt -vvv -l 'tcp[tcpflags] & tcp-syn != 0' | tee syn.log
```

> 💡 La opción `-l` es importante para evitar buffering cuando se redirige la salida a un archivo.

---

## 🔁 Generación de tráfico TCP (ejemplo con netcat)

**En la máquina donde corre OStealth:**

```bash
sudo nc -lvp 1234
```

**Desde otra máquina (o el gateway de la VM):**

```bash
nc <IP_DE_LA_MAQUINA_OSTEALTH> 1234
```
