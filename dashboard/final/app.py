import streamlit as st
import subprocess
import time
import os
import re
from pathlib import Path

# -----------------------------------------------------------------------------
# Configuration & CSS
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="OStealth Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .stApp { background-color: #0e1117; color: #fafafa; }
    h1, h2, h3 { font-family: 'Inter', sans-serif; font-weight: 700; color: #ffffff !important; }
    .stButton>button {
        width: 100%; border-radius: 8px; height: 3em; font-weight: 600;
        background-color: #262730; color: white; border: 1px solid #3d3d40;
        transition: all 0.3s ease;
    }
    .stButton>button:hover { border-color: #ff4b4b; color: #ff4b4b; transform: translateY(-2px); }
    div.metric-container {
        background-color: #262730; border: 1px solid #3d3d40; border-radius: 10px;
        padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .metric-label { font-size: 0.85em; color: #9ca0a6; text-transform: uppercase; margin-bottom: 5px; }
    .metric-value { font-size: 1.2em; font-weight: 600; color: #ffffff; font-family: 'Courier New', monospace; word-break: break-all; }
</style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# Constants & Paths
# -----------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent
p0f_LOG = BASE_DIR / "p0f.log"

# OStealth paths
# User moved ostealth.py to dashboard/final/
OSTEALTH_SCRIPT = BASE_DIR / "ostealth.py"
OSTEALTH_LOG = BASE_DIR / "ostealth.log"

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

def check_sudo():
    """Checks for root/sudo privileges."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def run_command_sudo(cmd_list, log_file=None, work_dir=None):
    """
    Runs a command using 'echo kali | sudo -S ...'
    1. Optionally changes directory (cd) first.
    2. Redirects output > log_file (outside sudo to keep ownership).
    """
    cmd_str = " ".join(cmd_list)
    
    parts = []
    if work_dir:
        parts.append(f"cd '{work_dir}'")

    # Export PATH to ensure bpftool (often in /usr/sbin) is found
    # Escape single quotes in cmd_str just in case
    cmd_str_safe = cmd_str.replace("'", "'\\''")
    sudo_part = f"echo 'kali' | sudo -S sh -c 'export PATH=$PATH:/usr/sbin:/sbin; {cmd_str_safe}'"
    
    if log_file:
        # User-owned redirection
        sudo_part = f"{sudo_part} > '{log_file}' 2>&1"
        
    parts.append(sudo_part)
    full_cmd = " && ".join(parts)
    
    return subprocess.Popen(full_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)

def kill_process(name):
    """Force kills a process by name using sudo."""
    subprocess.run(f"echo 'kali' | sudo -S pkill -f {name}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_ostealth(os_name):
    """
    Executes: sudo python3 ostealth.py <OS>
    Runs in the current directory (dashboard/final).
    """
    try:
        # 1. Clean previous
        kill_process("ostealth.py")
        
        # 2. Setup paths
        log_path = str(OSTEALTH_LOG.resolve())
        work_dir = str(BASE_DIR.resolve())
        
        # 3. Run
        # Command: python3 ostealth.py OS_NAME (Relative path, since we cd first)
        cmd = ["python3", "ostealth.py", os_name]
        
        # User requested original functionality. 
        # The user's manual edit removed work_dir but kept log_file=log_path.
        # However, to be "original functional", we likely NEED work_dir if ostealth depends on being in that dir.
        # But if the user explicitly removed it, maybe they want it removed.
        # Let's restore the ORIGINAL working state. Original state likely had work_dir. 
        # But wait, lines 99-100 were commented out. So it was BROKEN original state?
        # I will uncomment them to make it work.
        run_command_sudo(cmd, log_file=log_path, work_dir=work_dir)
        
        return True, f"OStealth Launched: {os_name}"
    except Exception as e:
        return False, str(e)

def run_inspection():
    """
    Sequence:
    1. Start p0f on eth0
    2. Run curl
    3. Save to p0f.log
    """
    log_path = str(p0f_LOG.resolve())
    
    # Clean old p0f log for fresh results
    if p0f_LOG.exists():
        try:
            p0f_LOG.unlink()
        except:
             subprocess.run(f"echo 'kali' | sudo -S rm '{log_path}'", shell=True)

    # 1. Start p0f
    kill_process("p0f")
    # Request: "sudo p0f -i eth0"
    cmd_p0f = ["p0f", "-i", "eth0"] 
    
    proc = run_command_sudo(cmd_p0f, log_file=log_path)
    
    # Wait for p0f init
    time.sleep(2)
    
    # 2. Generate Traffic
    try:
        subprocess.run(["curl", "-I", "google.com"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except:
        pass
        
    # Wait for capture
    time.sleep(2)
    
    # 3. Stop p0f
    kill_process("p0f")
    return True

def parse_p0f_log(content):
    """Parses p0f.log for the LAST valid OS detection."""
    if not content: return None, None
    
    sessions = []
    current_sess = {}
    current_raw = []
    in_block = False
    
    for line in content.splitlines():
        if line.strip().startswith(".-["):
            in_block = True
            current_sess = {}
            current_raw = [line]
        elif line.strip().startswith("`----"):
            if in_block:
                current_raw.append(line)
                sessions.append({"data": current_sess, "raw": "\n".join(current_raw)})
            in_block = False
        elif in_block:
            current_raw.append(line)
            if "|" in line and "=" in line:
                parts = line.split("|", 1)[1].split("=", 1)
                if len(parts) == 2:
                    current_sess[parts[0].strip()] = parts[1].strip()

    if not sessions:
        return None, None
        
    # Prioritize the last valid session
    for session in reversed(sessions):
        if session["data"].get("os") and session["data"].get("os") != "???":
            return session["data"], session["raw"]
            
    # Fallback
    return sessions[-1]["data"], sessions[-1]["raw"]

# -----------------------------------------------------------------------------
# Main UI
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# Main UI
# -----------------------------------------------------------------------------
def main():
    st.title("🛡️ OStealth Control & Inspect")
    
    # Tabs for better organization
    tab_defense, tab_inspection, tab_live = st.tabs(["🛡️ Defense", "🔍 Inspection", "🚨 Live Detection"])
    
    # --- 1. Defense (Buttons) ---
    with tab_defense:
        st.subheader("1. Defense Layer")
        st.markdown("Select OS to spoof (Runs `ostealth.py`):")
        
        # Grid
        c1, c2, c3 = st.columns(3)
        with c1:
            if st.button("🪟 XP"): run_ostealth("WindowsXP") and st.rerun()
            if st.button("😈 FreeBSD"): run_ostealth("FreeBSD") and st.rerun()
        with c2:
            if st.button("🪟 Win 7"): run_ostealth("Windows7") and st.rerun()
            if st.button("🐡 OpenBSD"): run_ostealth("OpenBSD") and st.rerun()
        with c3:
            if st.button("🐧 Linux"): run_ostealth("Linux") and st.rerun()
            if st.button("☀️ Solaris"): run_ostealth("Solaris") and st.rerun()

    # --- 2. Inspection ---
    with tab_inspection:
        st.subheader("2. Inspection Layer")
        if st.button("🔍 Run Inspection (p0f + curl)"):
            with st.status("Running Inspection...", expanded=True) as status:
                st.write("🛑 Stopping previous p0f...")
                kill_process("p0f")
                st.write("📡 Starting `sudo p0f -i eth0`...")
                run_inspection() # Runs sequence
                st.write("✅ Capture finished!")
                status.update(label="Inspection Complete", state="complete", expanded=False)
            st.rerun()
            
        st.divider()
        
        st.subheader("📊 Network Signatures")
        if p0f_LOG.exists():
            content = p0f_LOG.read_text(errors='ignore')
            data, raw = parse_p0f_log(content)
            
            if data:
                m1, m2, m3 = st.columns(3)
                m1.markdown(f'<div class="metric-container"><div class="metric-label">Client</div><div class="metric-value">{data.get("client", "N/A")}</div></div>', unsafe_allow_html=True)
                m2.markdown(f'<div class="metric-container"><div class="metric-label">Detected OS</div><div class="metric-value" style="color:#00ff7f">{data.get("os", "Unknown")}</div></div>', unsafe_allow_html=True)
                m3.markdown(f'<div class="metric-container"><div class="metric-label">Distance</div><div class="metric-value">{data.get("dist", "N/A")}</div></div>', unsafe_allow_html=True)
                
                st.markdown(f'<div class="metric-container"><div class="metric-label">Params</div><div class="metric-value" style="font-size:0.9em">{data.get("params", "N/A")}</div></div>', unsafe_allow_html=True)
                
                with st.expander("📜 Raw p0f Output", expanded=True):
                    st.code(raw if raw else "No signature data found.")
            else:
                st.warning("No signatures captured in p0f.log yet.")
                with st.expander("Full Log Content"):
                    st.code(content)
        else:
            st.info("No log file found. Click 'Run Inspection' to start.")

    with tab_live:
        st.subheader("3. Live Fingerprinting Detection")
        st.markdown("Runs `predict.py` to detect scanning attempts in real-time.")
        
        # Initialize session state for monitoring if not exists
        if 'live_monitoring' not in st.session_state:
            st.session_state.live_monitoring = False
        
        col_run, col_stop = st.columns(2)
        
        # Define log path in dashboard/final/ as requested
        # User requested "inspection.log"
        # Using FULL PATHS as per user request/environment
        live_log_path_str = "/home/kali/OStealth/dashboard/final/inspection.log"
        live_log_path = Path(live_log_path_str) # Still use Path obj for local checks if possible, though checks might fail if path is purely remote/linux specific but runs on same machine.
        # Assuming we are running ON the kali machine, Path(str) works.
        
        # Detection Control
        with col_run:
            if st.button("▶️ RUN Detection", type="primary"):
                st.session_state.live_monitoring = True
                
                # Start process
                kill_process("predict.py") # Ensure clean start
                
                # Paths
                work_dir = "/home/kali/OStealth/modeling"
                venv_python = "/home/kali/OStealth/dashboard/final/venv/bin/python3"
                cmd_predict = [venv_python, "-u", "predict.py", "eth0"]
                
                # Clear old log
                subprocess.run(f"rm -f {live_log_path_str}", shell=True)
                
                # Launch
                full_debug_cmd = f"cd {work_dir} && sudo {cmd_predict[0]} -u predict.py eth0 > {live_log_path_str}"
                st.toast(f"Launching: {full_debug_cmd}", icon="🛠️")
                
                run_command_sudo(cmd_predict, log_file=live_log_path_str, work_dir=work_dir)
                st.rerun() # Immediate update to show "Started" state
                
        with col_stop:
            if st.button("⏹️ STOP Detection", type="secondary"):
                st.session_state.live_monitoring = False
                kill_process("predict.py")
                st.toast("Live Detection Stopped.", icon="🛑")
                st.rerun()
        
        st.divider()
        st.markdown("### 📋 Live Monitor")
        
        # Live Log Reader & Scoring
        # We check if file exists OR if we are in monitoring mode (file might be created in a split second)
        if os.path.exists(live_log_path_str):
            try:
                with open(live_log_path_str, "r") as f:
                    log_content = f.read()
            except:
                log_content = ""
                
            lines = log_content.splitlines()
            
            # --- SCORING LOGIC ---
            fingerprint_count = 0
            for line in lines:
                if "[[1 0]]" in line:
                    fingerprint_count += 1
            
            # --- UI METRICS ---
            m_score, m_status = st.columns([1, 2])
            
            with m_score:
                st.metric("Fingerprinting Score", f"{fingerprint_count}")
            
            with m_status:
                if fingerprint_count > 0:
                    st.error(f"🚨 **ATTACK DETECTED!** ({fingerprint_count} packets)", icon="⚠️")
                    st.markdown("""
                        <style>
                        div.stMetric { background-color: #3d0c0c; border: 1px solid #ff4b4b; padding: 10px; border-radius: 5px; }
                        [data-testid="stMetricValue"] { color: #ff4b4b !important; }
                        </style>
                    """, unsafe_allow_html=True)
                else:
                    if st.session_state.live_monitoring:
                        st.info("✅ Monitoring Active...", icon="📡")
                    else:
                        st.success("✅ System Safe (Idle)", icon="🛡️")
            
            # --- TERMINAL OUTPUT ---
            st.text_area("Terminal Output (Last 20 lines)", "\n".join(lines[-20:]), height=300)
            
            # --- AUTO-REFRESH LOOP ---
            if st.session_state.live_monitoring:
                time.sleep(1) # Wait 1 second
                st.rerun()     # Trigger refresh
            
        else:
            if st.session_state.live_monitoring:
                st.warning("Starting up... Waiting for logs...")
                time.sleep(1)
                st.rerun()
            else:
                st.info("Click RUN to start monitoring.")

if __name__ == "__main__":
    main()

