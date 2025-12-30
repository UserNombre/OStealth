import streamlit as st
import pandas as pd
import re
from pathlib import Path
from datetime import datetime

LOG_FILE = Path("syn.log")

# ---------------------------------------------------------
# Parsear salida de tcpdump
# ---------------------------------------------------------
def parse_tcpdump_log(text):
    """
    Parsea el log de tcpdump y extrae información de los paquetes TCP.
    """
    packets = []
    
    for line in text.splitlines():
        line = line.strip()
        if not line or 'IP' not in line:
            continue
        
        packet = {}
        
        # Extraer timestamp (formato Unix epoch)
        timestamp_match = re.match(r'^([\d\.]+)', line)
        if timestamp_match:
            epoch = float(timestamp_match.group(1))
            dt = datetime.fromtimestamp(epoch)
            packet['timestamp'] = dt.strftime('%H:%M:%S.%f')[:-3]
            packet['epoch'] = epoch
        
        # Extraer IPs y puertos (formato: src.port > dst.port)
        ip_match = re.search(r'IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+)', line)
        if ip_match:
            packet['src_ip'] = ip_match.group(1)
            packet['src_port'] = ip_match.group(2)
            packet['dst_ip'] = ip_match.group(3)
            packet['dst_port'] = ip_match.group(4)
            packet['connection'] = f"{packet['src_ip']}:{packet['src_port']} → {packet['dst_ip']}:{packet['dst_port']}"
        
        # Extraer flags TCP
        flags_match = re.search(r'Flags \[([^\]]+)\]', line)
        if flags_match:
            packet['flags'] = flags_match.group(1)
        
        # Extraer seq number
        seq_match = re.search(r'seq (\d+)', line)
        if seq_match:
            packet['seq'] = seq_match.group(1)
        
        # Extraer ack number
        ack_match = re.search(r'ack (\d+)', line)
        if ack_match:
            packet['ack'] = ack_match.group(1)
        
        # Extraer window size
        win_match = re.search(r'win (\d+)', line)
        if win_match:
            packet['window'] = win_match.group(1)
        
        # Extraer MSS
        mss_match = re.search(r'mss (\d+)', line)
        if mss_match:
            packet['mss'] = mss_match.group(1)
        
        # Extraer opciones TCP completas
        options_match = re.search(r'options \[([^\]]+)\]', line)
        if options_match:
            packet['options'] = options_match.group(1)
        
        # Extraer timestamp values
        ts_match = re.search(r'TS val (\d+) ecr (\d+)', line)
        if ts_match:
            packet['ts_val'] = ts_match.group(1)
            packet['ts_ecr'] = ts_match.group(2)
        
        # Extraer window scale
        wscale_match = re.search(r'wscale (\d+)', line)
        if wscale_match:
            packet['wscale'] = wscale_match.group(1)
        
        # Detectar SACK OK
        if 'sackOK' in line:
            packet['sack'] = 'Yes'
        
        # Extraer length
        length_match = re.search(r'length (\d+)', line)
        if length_match:
            packet['length'] = length_match.group(1)
        
        if packet:
            packet['raw_line'] = line
            packets.append(packet)
    
    return packets

# ---------------------------------------------------------
# Función para determinar el tipo de paquete
# ---------------------------------------------------------
def get_packet_type(flags):
    """Determina el tipo de paquete según las flags TCP"""
    if not flags:
        return "❓ Unknown"
    
    flag_types = {
        'S': '🟢 SYN',
        'S.': '🔵 SYN-ACK',
        '.': '⚪ ACK',
        'F': '🔴 FIN',
        'F.': '🔴 FIN-ACK',
        'R': '🟠 RST',
        'P': '🟣 PSH',
        'P.': '🟣 PSH-ACK'
    }
    
    return flag_types.get(flags, f'📦 {flags}')

# ---------------------------------------------------------
# STREAMLIT UI
# ---------------------------------------------------------
st.set_page_config(page_title="TCP Packet Viewer", layout="wide")

st.title("🔍 TCP Packet Analyzer")
st.markdown("### Visualización de paquetes TCP capturados con tcpdump")

# Sidebar
st.sidebar.title("📊 Estadísticas")

# Botón para recargar datos
if st.sidebar.button("🔄 Recargar datos", use_container_width=True):
    st.rerun()

# ---------------------------------------------------------
# Procesar y mostrar datos
# ---------------------------------------------------------
if LOG_FILE.exists():
    raw_text = LOG_FILE.read_text(errors="ignore")
    packets = parse_tcpdump_log(raw_text)
    
    if packets:
        df = pd.DataFrame(packets)
        
        # Estadísticas en sidebar
        st.sidebar.metric("📦 Total de paquetes", len(packets))
        
        if 'flags' in df.columns:
            st.sidebar.markdown("---")
            st.sidebar.markdown("#### 🏷️ Distribución de flags")
            flag_counts = df['flags'].value_counts()
            for flag, count in flag_counts.items():
                st.sidebar.markdown(f"**{get_packet_type(flag)}**: {count}")
        
        # IPs únicas
        if 'src_ip' in df.columns and 'dst_ip' in df.columns:
            unique_src = df['src_ip'].nunique()
            unique_dst = df['dst_ip'].nunique()
            st.sidebar.markdown("---")
            st.sidebar.markdown("#### 🌐 IPs únicas")
            st.sidebar.text(f"Origen: {unique_src}")
            st.sidebar.text(f"Destino: {unique_dst}")
        
        # Filtros
        st.sidebar.markdown("---")
        st.sidebar.markdown("#### 🔎 Filtros")
        
        if 'src_ip' in df.columns:
            unique_ips = sorted(list(set(df['src_ip'].tolist() + df['dst_ip'].tolist())))
            selected_ip = st.sidebar.selectbox("Filtrar por IP", ["Todas"] + unique_ips)
        
        if 'flags' in df.columns:
            selected_flag = st.sidebar.selectbox("Filtrar por Flag", ["Todas"] + sorted(df['flags'].unique().tolist()))
        
        # Aplicar filtros
        filtered_df = df.copy()
        if selected_ip != "Todas":
            filtered_df = filtered_df[(filtered_df['src_ip'] == selected_ip) | (filtered_df['dst_ip'] == selected_ip)]
        
        if selected_flag != "Todas":
            filtered_df = filtered_df[filtered_df['flags'] == selected_flag]
        
        # Mostrar paquetes en tarjetas
        st.subheader(f"📦 Paquetes capturados ({len(filtered_df)} de {len(packets)})")
        
        for idx, packet in filtered_df.iterrows():
            packet_title = (
                f"{get_packet_type(packet.get('flags', ''))} | "
                f"{packet.get('connection', 'N/A')}"
            )
            
            with st.expander(packet_title, expanded=False):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.markdown("**⏱️ Temporal**")
                    st.text(f"⏰ {packet.get('timestamp', 'N/A')}")
                    st.text(f"🏷️  {get_packet_type(packet.get('flags', ''))}")
                
                with col2:
                    st.markdown("**🌐 Red**")
                    st.text(f"📤 {packet.get('src_ip', 'N/A')}:{packet.get('src_port', 'N/A')}")
                    st.text(f"📥 {packet.get('dst_ip', 'N/A')}:{packet.get('dst_port', 'N/A')}")
                
                with col3:
                    st.markdown("**📊 TCP Info**")
                    st.text(f"SEQ: {packet.get('seq', 'N/A')}")
                    if 'ack' in packet:
                        st.text(f"ACK: {packet.get('ack')}")
                    st.text(f"WIN: {packet.get('window', 'N/A')}")
                
                # Segunda fila de información detallada
                st.markdown("---")
                col4, col5 = st.columns(2)
                
                with col4:
                    st.markdown("**🔧 Opciones TCP**")
                    if 'mss' in packet:
                        st.text(f"🔹 MSS: {packet['mss']}")
                    if 'wscale' in packet:
                        st.text(f"🔹 Window Scale: {packet['wscale']}")
                    if 'sack' in packet:
                        st.text(f"🔹 SACK: {packet['sack']}")
                    if 'length' in packet:
                        st.text(f"🔹 Length: {packet['length']} bytes")
                
                with col5:
                    st.markdown("**⏲️ Timestamps**")
                    if 'ts_val' in packet:
                        st.text(f"🔹 TS val: {packet['ts_val']}")
                    if 'ts_ecr' in packet:
                        st.text(f"🔹 TS ecr: {packet['ts_ecr']}")
                
                # Opciones completas
                if 'options' in packet and packet['options']:
                    st.markdown("**📋 Opciones completas**")
                    st.code(packet['options'], language=None)
        
        # Tabla resumen
        st.markdown("---")
        st.subheader("📋 Tabla resumen")
        
        display_columns = ['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'flags', 'seq', 'window', 'mss']
        available_columns = [col for col in display_columns if col in filtered_df.columns]
        
        st.dataframe(
            filtered_df[available_columns],
            use_container_width=True,
            hide_index=True
        )
        
        # Log raw
        with st.expander("📜 Ver log completo de tcpdump"):
            st.code(raw_text, language=None)
    
    else:
        st.warning("⚠️ No se detectaron paquetes TCP en el archivo. Verifica el contenido de `syn.log`.")

else:
    st.info("ℹ️ **No se encontró el archivo `syn.log`**")
    st.markdown("""
    ### 📝 Instrucciones para capturar paquetes:
    
    **1. Inicia tcpdump para capturar paquetes TCP:**
    ```bash
    sudo tcpdump -i lo -nn tcp > syn.log
    ```
    
    **2. Genera tráfico TCP en otra terminal:**
    
    **Terminal 1 (servidor):**
    ```bash
    nc -lvp 1234
    ```
    
    **Terminal 2 (cliente):**
    ```bash
    nc 127.0.0.1 1234
    ```
    
    **3. Detén tcpdump con Ctrl+C** cuando hayas generado suficiente tráfico.
    
    **4. Recarga esta página** para ver los paquetes capturados.
    """)
    
    st.markdown("---")
    st.info("💡 **Tip:** Cambia la interfaz `-i lo` por tu interfaz de red (eth0, wlan0, etc.) para capturar tráfico real.")
