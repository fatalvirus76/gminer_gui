import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import threading
import os

# Global variable to track the miner process
miner_process = None

# Function to save configuration to a file
def save_config():
    config = {key: var.get() for key, var in config_vars.items()}
    save_path = filedialog.asksaveasfilename(
        defaultextension=".json", filetypes=[("JSON files", "*.json")]
    )
    if save_path:
        try:
            with open(save_path, "w") as f:
                json.dump(config, f, indent=4)
            messagebox.showinfo("Success", f"Configuration saved to {save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {e}")

# Function to load configuration from a file
def load_config():
    load_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
    if load_path:
        try:
            with open(load_path, "r") as f:
                config = json.load(f)
            for key, value in config.items():
                if key in config_vars:
                    config_vars[key].set(value)
            messagebox.showinfo("Success", f"Configuration loaded from {load_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load configuration: {e}")

# Function to send commands to Gminer (with validation)
def send_command(command):
    global miner_process
    if command == "run":
        args = ["./miner"]
        for key, var in config_vars.items():
            if var.get():
                args.append(f"--{key}")
                args.append(var.get())
        try:
            miner_process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            update_debug_window(miner_process)
            messagebox.showinfo("Success", "Miner started successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start miner: {e}")
    elif command == "stop":
        if miner_process:
            try:
                # Kill all processes named 'miner' using 'killall -9'
                subprocess.run(["killall", "-9", "miner"], check=True)
                miner_process = None
                messagebox.showinfo("Success", "Miner stopped successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to stop miner: {e}")
        else:
            messagebox.showwarning("Warning", "No miner process is running")
    else:
        print(f"Command sent: {command}")
        messagebox.showinfo("Command Sent", f"{command}")

# Helper function to update the debug window
def update_debug_window(process):
    def read_output():
        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                debug_text.insert(tk.END, output)
                debug_text.see(tk.END)

    debug_thread = threading.Thread(target=read_output, daemon=True)
    debug_thread.start()

# Helper function to validate input (e.g., for ports)
def validate_numeric(value):
    return value.isdigit() or value == ""

# Create main window
root = tk.Tk()
root.title("Gminer GUI")
root.geometry("800x600")

# Create notebook for tabs
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

# Create a dictionary to store configuration variables
config_vars = {}

# Helper function to create a labeled entry
def create_entry(parent, label, var_name, validate=None, **kwargs):
    frame = ttk.Frame(parent)
    frame.pack(fill="x", padx=5, pady=2)
    ttk.Label(frame, text=label, width=20, anchor="w").pack(side="left")
    entry_var = tk.StringVar()
    config_vars[var_name] = entry_var
    validate_cmd = (root.register(validate), "%P") if validate else None
    ttk.Entry(frame, textvariable=entry_var, validate="key", validatecommand=validate_cmd, **kwargs).pack(side="left", fill="x", expand=True)

# Helper function to create a dropdown menu
def create_dropdown(parent, label, var_name, options):
    frame = ttk.Frame(parent)
    frame.pack(fill="x", padx=5, pady=2)
    ttk.Label(frame, text=label, width=20, anchor="w").pack(side="left")
    dropdown_var = tk.StringVar()
    config_vars[var_name] = dropdown_var
    ttk.Combobox(frame, textvariable=dropdown_var, values=options, state="readonly").pack(side="left", fill="x", expand=True)

# Main tab
main_tab = ttk.Frame(notebook)
notebook.add(main_tab, text="Main")

algorithms = ["zil", "vds", "equihash144_5", "equihash125_4", "beamhash", "equihash210_9", "cuckoo29", "cuckatoo32", "eth", "etc", "cortex", "kawpow", "sero", "firo", "autolykos2", "octopus", "kheavyhash", "ethash+kheavyhash", "ethash+sha512_256d", "ethash+ironfish", "etchash+kheavyhash", "etchash+sha512_256d", "etchash+ironfish", "octopus+kheavyhash", "octopus+sha512_256d", "octopus+ironfish", "autolykos2+kheavyhash", "autolykos2+sha512_256d", "sha512_256d", "ironfish", "karlsenhash"]

create_dropdown(main_tab, "Algorithm:", "algo", algorithms)
create_entry(main_tab, "Server:", "server")
create_entry(main_tab, "Port:", "port", validate=validate_numeric)
create_entry(main_tab, "User:", "user")
create_entry(main_tab, "Password:", "password")
create_entry(main_tab, "SSL (1/0):", "ssl", validate=validate_numeric)
create_entry(main_tab, "Protocol:", "proto")
create_entry(main_tab, "Worker:", "worker")

# Dual tab
dual_tab = ttk.Frame(notebook)
notebook.add(dual_tab, text="Dual")
create_entry(dual_tab, "Dual Server:", "dserver")
create_entry(dual_tab, "Dual Port:", "dport", validate=validate_numeric)
create_entry(dual_tab, "Dual User:", "duser")
create_entry(dual_tab, "Dual Password:", "dpass")
create_entry(dual_tab, "Dual SSL (1/0):", "dssl", validate=validate_numeric)
create_entry(dual_tab, "Dual Protocol:", "dproto")
create_entry(dual_tab, "Dual Worker:", "dworker")

# Maintenance tab
maintenance_tab = ttk.Frame(notebook)
notebook.add(maintenance_tab, text="Maintenance")
create_entry(maintenance_tab, "Server:", "maintenance_server")
create_entry(maintenance_tab, "Port:", "maintenance_port", validate=validate_numeric)
create_entry(maintenance_tab, "User:", "maintenance_user")
create_entry(maintenance_tab, "Password:", "maintenance_pass")
create_entry(maintenance_tab, "Fee (%):", "maintenance_fee", validate=validate_numeric)

# Clock tab
clock_tab = ttk.Frame(notebook)
notebook.add(clock_tab, text="Clock")
create_entry(clock_tab, "Core Clock:", "cclock", validate=validate_numeric)
create_entry(clock_tab, "Memory Clock:", "mclock", validate=validate_numeric)
create_entry(clock_tab, "Locked Core Clock:", "lock_cclock", validate=validate_numeric)
create_entry(clock_tab, "Locked Memory Clock:", "lock_mclock", validate=validate_numeric)
create_entry(clock_tab, "ZIL Power Limit:", "zilpl", validate=validate_numeric)
create_entry(clock_tab, "ZIL Core Clock:", "zilcclock", validate=validate_numeric)
create_entry(clock_tab, "ZIL Memory Clock:", "zilmclock", validate=validate_numeric)

# Fan tab
fan_tab = ttk.Frame(notebook)
notebook.add(fan_tab, text="Fan")
create_entry(fan_tab, "Fan Speed:", "fan", validate=validate_numeric)
create_entry(fan_tab, "ZIL Fan Speed:", "zilfan", validate=validate_numeric)
create_entry(fan_tab, "Target Temp:", "tfan", validate=validate_numeric)
create_entry(fan_tab, "Max Fan Speed:", "fan_max", validate=validate_numeric)

# API tab
api_tab = ttk.Frame(notebook)
notebook.add(api_tab, text="API")
create_entry(api_tab, "API (ip:port):", "api")
create_entry(api_tab, "Electricity Cost:", "electricity_cost")
create_entry(api_tab, "Power Limit:", "pl", validate=validate_numeric)

# Log tab
log_tab = ttk.Frame(notebook)
notebook.add(log_tab, text="Log")
create_entry(log_tab, "Log File:", "logfile")
create_entry(log_tab, "Log Date:", "log_date")
create_entry(log_tab, "Log Stratum:", "log_stratum")
create_entry(log_tab, "Log New Job:", "log_newjob")
create_entry(log_tab, "Log Pool Efficiency:", "log_pool_efficiency")

# ZIL tab
zil_tab = ttk.Frame(notebook)
notebook.add(zil_tab, text="ZIL")
create_entry(zil_tab, "ZIL Server:", "zilserver")
create_entry(zil_tab, "ZIL Port:", "zilport", validate=validate_numeric)
create_entry(zil_tab, "ZIL User:", "ziluser")
create_entry(zil_tab, "ZIL Password:", "zilpass")
create_entry(zil_tab, "ZIL Protocol:", "zilproto")
create_entry(zil_tab, "ZIL SSL:", "zilssl")

# Debug tab
debug_tab = ttk.Frame(notebook)
notebook.add(debug_tab, text="Debug")
create_entry(debug_tab, "Enable PEC (1/0):", "pec", validate=validate_numeric)
create_entry(debug_tab, "Enable NVML (1/0):", "nvml", validate=validate_numeric)
create_entry(debug_tab, "Enable CUDA (1/0):", "cuda", validate=validate_numeric)
create_entry(debug_tab, "Enable OpenCL (1/0):", "opencl", validate=validate_numeric)

# Debug Window
debug_window = ttk.Frame(debug_tab)
debug_window.pack(fill="both", expand=True, padx=5, pady=5)
debug_text = tk.Text(debug_window, wrap="word", state="normal", height=15, width=70)
debug_text.pack(side="left", fill="both", expand=True)
debug_scrollbar = ttk.Scrollbar(debug_window, command=debug_text.yview)
debug_scrollbar.pack(side="right", fill="y")
debug_text["yscrollcommand"] = debug_scrollbar.set

# Buttons for actions
button_frame = ttk.Frame(root)
button_frame.pack(fill="x", padx=5, pady=5)

btn_save = ttk.Button(button_frame, text="Save Config", command=save_config)
btn_save.pack(side="left", padx=5)

btn_load = ttk.Button(button_frame, text="Load Config", command=load_config)
btn_load.pack(side="left", padx=5)

btn_run = ttk.Button(button_frame, text="Run", command=lambda: send_command("run"))
btn_run.pack(side="left", padx=5)

btn_stop = ttk.Button(button_frame, text="Stop", command=lambda: send_command("stop"))
btn_stop.pack(side="left", padx=5)

btn_exit = ttk.Button(button_frame, text="Exit", command=root.quit)
btn_exit.pack(side="left", padx=5)

root.mainloop()
