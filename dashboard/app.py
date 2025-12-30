import streamlit as st
import pandas as pd
import subprocess
import threading
import time
from pathlib import Path

LOG_FILE = Path("p0f.log")


# ---------------------------------------------------------
# Ejecutar p0f en segundo plano
# ---------------------------------------------------------
def run_p0f_background(interface, duration):
    cmd = f"sudo timeout {duration} p0f -i {interface}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    LOG_FILE.write_text(result.stdout)


# ---------------------------------------------------------
# Parsear salida de p0f
# ---------------------------------------------------------
def parse_p0f_log(text):
    sessions = []
    current = {}

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        if line.startswith("-[") and line.endswith("]-"):
            if current:
                sessions.append(current)
            current = {"header": line}

        elif "=" in line:
            key, val = line.split("=", 1)
            current[key.strip()] = val.strip()

    if current:
        sessions.append(current)

    return sessions


# ---------------------------------------------------------
# STREAMLIT UI
# ---------------------------------------------------------
st.set_page_config(page_title="p0f Listener", layout="wide")
st.title("🕵️ p0f Listener – Captura de tráfico TCP con temporizador")


st.sidebar.title("⚙️ Configuración")
interface = st.sidebar.text_input("Interfaz a escuchar", "lo")
duration = 30
run_button = st.sidebar.button("🎧 Iniciar escucha de p0f (30s)")


# ---------------------------------------------------------
# Mensaje especial si se selecciona loopback
# ---------------------------------------------------------
if interface == "lo":
    st.warning("""
### ⚠️ Has seleccionado la interfaz loopback `lo`.

Para que p0f capture tráfico, **debes generarlo manualmente** desde dos terminales:

🟦 Terminal 1 (servidor)
nc -lvp 1234


🟩 Terminal 2 (cliente)
nc 127.0.0.1 1234

Realiza la conexión mientras p0f escucha.
""")


# ---------------------------------------------------------
# Acción cuando se pulsa el botón
# ---------------------------------------------------------
if run_button:

    st.info(f"🎧 p0f escuchará en `{interface}` durante {duration} segundos.")
    st.info("🔄 Genera el tráficoTCP ahora si estás usando loopback.")

    # Ejecutar p0f en segundo plano (no bloquea la UI)
    thread = threading.Thread(
        target=run_p0f_background,
        args=(interface, duration)
    )
    thread.start()

    # Temporizador en pantalla
    countdown = st.empty()
    for t in range(duration, 0, -1):
        countdown.markdown(f"## ⏳ Tiempo restante: **{t} segundos**")
        time.sleep(1)

    countdown.markdown("## 🟢 Tiempo agotado. Procesando resultados…")

    thread.join()

    st.success("¡Captura completada! Revisa los resultados abajo.")


# ---------------------------------------------------------
# Mostrar resultados
# ---------------------------------------------------------
if LOG_FILE.exists():
    raw_text = LOG_FILE.read_text(errors="ignore")
    sessions = parse_p0f_log(raw_text)

    if sessions:
        df = pd.DataFrame(sessions)

        st.subheader("📄 Sesiones detectadas por p0f")
        st.dataframe(df, use_container_width=True)

        st.subheader("📜 Log completo de p0f")
        st.code(raw_text)

    else:
        st.warning("No se detectó tráfico. Si usas `lo`, asegúrate de ejecutar los comandos netcat.")
else:
    st.info("Aún no se ha realizado ninguna captura.")

