import streamlit as st
import pandas as pd
import re
from pathlib import Path
from datetime import datetime

LOG_FILE = Path("tcpdump.log")

# ---------------------------------------------------------
# Parsear salida de tcpdump con formato verbose
# ---------------------------------------------------------
def parse_tcpdump_log(text):
    """
    Parsea el log de tcpdump en formato verbose (-vvv).
    Maneja líneas que pueden estar divididas en múltiples partes.
    """
    packets = []
    lines = text.splitlines()
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Buscar línea que comienza con timestamp
        if not line or not re.match(r'^\d+\.\d+', line):
            i += 1
            continue
        
        packet = {}
        
        # Línea 1: metadata (tos, ttl, id, etc.)
        # Extraer timestamp
        timestamp_match = re.match(r'^([\d\.]+)', line)
        if timestamp_match:
            epoch = float(timestamp_match.group(1))
            dt = datetime.fromtimestamp(epoch)
            packet['timestamp'] = dt.strftime('%H:%M:%S.%f')[:-3]
            packet['epoch'] = epoch
        
        # Extraer TOS
        tos_match = re.search(r'tos (0x[0-9a-f]+)', line, re.IGNORECASE)
        if tos_match:
            packet['tos'] = tos_match.group(1)
        
        # Extraer TTL
        ttl_match = re.search(r'ttl (\d+)', line, re.IGNORECASE)
        if ttl_match:
            packet['ttl'] = ttl_match.group(1)
        
        # Extraer ID
        id_match = re.search(r'id (\d+)', line, re.IGNORECASE)
        if id_match:
            packet['ip_id'] = id_match.group(1)
        
        # Extraer flags IP
        ip_flags_match = re.search(r'flags \[([^\]]+)\]', line)
        if ip_flags_match:
            packet['ip_flags'] = ip_flags_match.group(1)
        
        # Extraer protocolo
        proto_match = re.search(r'proto (\w+)', line, re.IGNORECASE)
        if proto_match:
            packet['protocol'] = proto_match.group(1)
        
        # Extraer length IP
        length_match = re.search(r'length (\d+)', line)
        if length_match:
            packet['ip_length'] = length_match.group(1)
        
        # Línea 2: conexión TCP (si existe)
        if i + 1 < len(lines):
            next_line = lines[i + 1].strip()
            
            # Extraer IPs y puertos
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+)', next_line)
            if ip_match:
                packet['src_ip'] = ip_match.group(1)
                packet['src_port'] = ip_match.group(2)
                packet['dst_ip'] = ip_match.group(3)
                packet['dst_port'] = ip_match.group(4)
                packet['connection'] = f"{packet['src_ip']}:{packet['src_port']} → {packet['dst_ip']}:{packet['dst_port']}"
            
            # Extraer flags TCP
            tcp_flags_match = re.search(r'Flags \[([^\]]+)\]', next_line)
            if tcp_flags_match:
                packet['tcp_flags'] = tcp_flags_match.group(1)
            
            # Extraer checksum
            cksum_match = re.search(r'cksum (0x[0-9a-f]+)', next_line, re.IGNORECASE)
            if cksum_match:
                packet['checksum'] = cksum_match.group(1)
            
            # Verificar checksum status
            if 'correct' in next_line:
                packet['cksum_status'] = '✓ Correct'
            elif 'incorrect' in next_line:
                packet['cksum_status'] = '✗ Incorrect'
            
            # Extraer seq
            seq_match = re.search(r'seq (\d+)', next_line)
            if seq_match:
                packet['seq'] = seq_match.group(1)
            
            # Extraer ack
            ack_match = re.search(r'ack (\d+)', next_line)
            if ack_match:
                packet['ack'] = ack_match.group(1)
            
            # Extraer window
            win_match = re.search(r'win (\d+)', next_line)
            if win_match:
                packet['window'] = win_match.group(1)
            
            # Extraer opciones TCP
            options_match = re.search(r'options \[([^\]]+)\]', next_line)
            if options_match:
                packet['options'] = options_match.group(1)
                
                # Parsear opciones individuales
                opts = options_match.group(1)
                
                # MSS
                mss_match = re.search(r'mss (\d+)', opts)
                if mss_match:
                    packet['mss'] = mss_match.group(1)
                
                # Window scale
                wscale_match = re.search(r'wscale (\d+)', opts)
                if wscale_match:
                    packet['wscale'] = wscale_match.group(1)
                
                # SACK
                if 'sackOK' in opts:
                    packet['sack'] = 'Yes'
                
                # Timestamps
                ts_match = re.search(r'TS val (\d+) ecr (\d+)', opts)
                if ts_match:
                    packet['ts_val'] = ts_match.group(1)
                    packet['ts_ecr'] = ts_match.group(2)
            
            # Extraer length TCP
            tcp_length_match = re.search(r'length (\d+)$', next_line)
            if tcp_length_match:
                packet['tcp_length'] = tcp_length_match.group(1)
            
            i += 1  # Saltamos la segunda línea
        
        if packet and 'src_ip' in packet:
            packet['raw_line'] = line + '\n    ' + (lines[i] if i < len(lines) else '')
            packets.append(packet)
        
        i += 1
    
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
        'R.': '🟠 RST-ACK',
        'P': '🟣 PSH',
        'P.': '🟣 PSH-ACK'
    }
    
    return flag_types.get(flags, f'📦 {flags}')

# ---------------------------------------------------------
# STREAMLIT UI
# ---------------------------------------------------------
st.set_page_config(page_title="TCP Packet Viewer", layout="wide")

st.title("🔍 TCP Packet Analyzer")
st.markdown("### Visualización de paquetes TCP capturados con tcpdump -vvv")

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
        
        if 'tcp_flags' in df.columns:
            st.sidebar.markdown("---")
            st.sidebar.markdown("#### 🏷️ Distribución de flags")
            flag_counts = df['tcp_flags'].value_counts()
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
        
        # TTL stats
        if 'ttl' in df.columns:
            ttl_values = df['ttl'].value_counts()
            st.sidebar.markdown("---")
            st.sidebar.markdown("#### 🔢 TTL observados")
            for ttl, count in ttl_values.items():
                st.sidebar.text(f"TTL {ttl}: {count}")
        
        # Filtros
        st.sidebar.markdown("---")
        st.sidebar.markdown("#### 🔎 Filtros")
        
        if 'src_ip' in df.columns:
            unique_ips = sorted(list(set(df['src_ip'].tolist() + df['dst_ip'].tolist())))
            selected_ip = st.sidebar.selectbox("Filtrar por IP", ["Todas"] + unique_ips)
        
        if 'tcp_flags' in df.columns:
            selected_flag = st.sidebar.selectbox("Filtrar por Flag", ["Todas"] + sorted(df['tcp_flags'].unique().tolist()))
        
        # Aplicar filtros
        filtered_df = df.copy()
        if selected_ip != "Todas":
            filtered_df = filtered_df[(filtered_df['src_ip'] == selected_ip) | (filtered_df['dst_ip'] == selected_ip)]
        
        if selected_flag != "Todas":
            filtered_df = filtered_df[filtered_df['tcp_flags'] == selected_flag]
        
        # Mostrar paquetes en tarjetas
        st.subheader(f"📦 Paquetes capturados ({len(filtered_df)} de {len(packets)})")
        
        for idx, packet in filtered_df.iterrows():
            packet_title = (
                f"{get_packet_type(packet.get('tcp_flags', ''))} | "
                f"{packet.get('connection', 'N/A')}"
            )
            
            with st.expander(packet_title, expanded=False):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.markdown("**⏱️ Temporal**")
                    st.text(f"⏰ {packet.get('timestamp', 'N/A')}")
                    st.text(f"🏷️  {get_packet_type(packet.get('tcp_flags', ''))}")
                
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
                
                # Segunda fila - IP Layer
                st.markdown("---")
                st.markdown("**🔷 Capa IP (Fingerprinting)**")
                
                col4, col5, col6 = st.columns(3)
                
                with col4:
                    if 'ttl' in packet:
                        st.text(f"🔹 TTL: {packet['ttl']}")
                    if 'tos' in packet:
                        st.text(f"🔹 ToS: {packet['tos']}")
                
                with col5:
                    if 'ip_id' in packet:
                        st.text(f"🔹 IP ID: {packet['ip_id']}")
                    if 'ip_flags' in packet:
                        st.text(f"🔹 IP Flags: {packet['ip_flags']}")
                
                with col6:
                    if 'ip_length' in packet:
                        st.text(f"🔹 IP Length: {packet['ip_length']}")
                    if 'checksum' in packet:
                        st.text(f"🔹 Checksum: {packet['checksum']}")
                    if 'cksum_status' in packet:
                        st.text(f"   {packet['cksum_status']}")
                
                # Tercera fila - Opciones TCP
                st.markdown("---")
                col7, col8 = st.columns(2)
                
                with col7:
                    st.markdown("**🔧 Opciones TCP**")
                    if 'mss' in packet:
                        st.text(f"🔹 MSS: {packet['mss']}")
                    if 'wscale' in packet:
                        st.text(f"🔹 Window Scale: {packet['wscale']}")
                    if 'sack' in packet:
                        st.text(f"🔹 SACK: {packet['sack']}")
                    if 'tcp_length' in packet:
                        st.text(f"🔹 TCP Length: {packet['tcp_length']} bytes")
                
                with col8:
                    st.markdown("**⏲️ Timestamps**")
                    if 'ts_val' in packet:
                        st.text(f"🔹 TS val: {packet['ts_val']}")
                    if 'ts_ecr' in packet:
                        st.text(f"🔹 TS ecr: {packet['ts_ecr']}")
                
                # Opciones completas
                if 'options' in packet and packet['options']:
                    st.markdown("**📋 Opciones TCP completas**")
                    st.code(packet['options'], language=None)
        
        # Tabla resumen
        st.markdown("---")
        st.subheader("📋 Tabla resumen con datos de Fingerprinting")
        
        display_columns = ['timestamp', 'src_ip', 'dst_ip', 'tcp_flags', 'ttl', 'window', 'mss', 'ip_id', 'tos']
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
        st.warning("⚠️ No se detectaron paquetes TCP en el archivo. Verifica el contenido de `tcpdump.log`.")

else:
    st.info("ℹ️ **No se encontró el archivo `tcpdump.log`**")
    st.markdown("""
    ### 📝 Instrucciones para capturar paquetes:
    
    **1. Inicia tcpdump en modo verbose para capturar detalles completos:**
    ```bash
    sudo tcpdump -i lo -n -tt -vvv tcp > tcpdump.log
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
    st.info("💡 **Tip:** El flag `-vvv` es necesario para obtener todos los datos de fingerprinting (TTL, ToS, IP ID, etc.)")
