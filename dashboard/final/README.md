# 🛡️ OStealth

OStealth es un sistema de ofuscación y evasión de huellas de red basado en eBPF, complementado con un dashboard de Streamlit que permite el control interactivo y la verificación del comportamiento de la red.

## 📋 Descripción General

El proyecto está compuesto por tres componentes principales:

1. **Implementación eBPF de OStealth** - Motor de modificación de paquetes
2. **Dashboard de control Streamlit** - Interfaz de usuario interactiva
3. **Demostración con máquina remota** - Generación y análisis de tráfico TCP

---

## 1️⃣ Implementación OStealth (eBPF)

OStealth utiliza un programa eBPF adjunto al subsistema Linux Traffic Control (tc) para interceptar y modificar paquetes de red salientes (egress). Esto permite al sistema ocultar o alterar las firmas de red del sistema operativo.

### 📥 Carga del Programa eBPF

Primero, configura la cola de disciplina en la interfaz de red:
```bash
sudo tc qdisc add dev eth0 clsact
```

> ⚠️ **Nota:** Reemplaza `eth0` con la interfaz de red correcta para tu sistema.

Luego, adjunta el filtro eBPF al tráfico saliente:
```bash
sudo tc filter add dev eth0 egress bpf direct-action \
     obj ostealth.o sec tc_egress verbose
```

### 🔍 Verificación

Para verificar que el programa eBPF se cargó correctamente:
```bash
sudo tc filter show dev eth0 egress
```

### 🧹 Descargar OStealth

Para detener OStealth y limpiar la configuración del sistema:
```bash
sudo tc filter del dev eth0 egress
sudo tc qdisc del dev eth0 clsact
```

Esto elimina el filtro eBPF y la disciplina de cola asociada de la interfaz.

---

## 2️⃣ Dashboard de Control Streamlit

El proyecto incluye un dashboard interactivo de Streamlit que permite:

- Lanzar OStealth con diferentes huellas de SO
- Ejecutar inspecciones de tráfico usando p0f
- Confirmar visualmente los resultados de detección de SO en tiempo real

### 🐍 Configuración del Entorno Python

Desde el directorio del dashboard:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Esto crea un entorno Python aislado con todas las dependencias necesarias.

### 🚀 Ejecutar el Dashboard

Con el entorno virtual activado:
```bash
streamlit run app.py
```

Una vez iniciado, el dashboard estará disponible en el navegador y puede usarse para controlar OStealth a través de una interfaz gráfica.

---

## 3️⃣ Demostración con Máquina Remota

Para demostrar OStealth en acción, se puede generar tráfico TCP real desde una máquina remota y analizarlo para observar cómo se altera la huella del sistema operativo.

### 📡 Generación de Tráfico TCP (Ejemplo con Netcat)

**En la máquina que ejecuta OStealth:**

Inicia un listener TCP en un puerto elegido:
```bash
nc -lvp 1234
```

**En la máquina remota:**

Conéctate a la máquina OStealth:
```bash
nc <OSTEALTH_MACHINE_IP> 1234
```

Este tráfico TCP puede inspeccionarse usando herramientas como **p0f** para verificar cómo OStealth modifica las firmas de red y engaña a la detección del sistema operativo.

---

## 📚 Recursos Adicionales

- [Documentación eBPF](https://ebpf.io/)
- [Documentación Streamlit](https://docs.streamlit.io/)
- [Herramienta p0f](https://lcamtuf.coredump.cx/p0f3/)

---

## 📄 Licencia

[Incluir información de licencia aquí]

## 🤝 Contribuciones

[Incluir guías de contribución si aplica]

---

**Desarrollado con ❤️ usando eBPF y Python**
