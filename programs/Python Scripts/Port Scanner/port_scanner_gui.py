import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import subprocess
import threading

"""
A simple GUI for running a port scanner using the python_port_scanner.py script.
New additions:
- Uses tkinter for the GUI.
- Includes a progress bar to indicate scanning status.
- Allows input of target IPs and ports in various formats.
- Displays scan results in a text area.

Author: Britton Janet
- Updates: Creation 31MAY2025
"""
def run_scan():
    # This function is called when the "Scan" button is pressed.
    def task():
        # This inner function runs the port scanning task in a separate thread. To keep the GUI responsive.
        progress.start()                                        # Start the progress bar animation
        target = entry_target.get()                             # Get the target IPs from the entry field
        ports = entry_ports.get()                               # Get the ports from the entry field
        cmd = ["python3", "python_port_scanner.py", target]     # Prepare the command to run the port scanner script
        if ports:
            cmd += ["--ports", ports]                       # Add the ports argument if provided
        output = subprocess.getoutput(" ".join(cmd))        # Run the command and capture the output
        text_output.delete(1.0, tk.END)                     # Clear the text area before displaying new results
        text_output.insert(tk.END, output)                  # Insert the output into the text area
        progress.stop()
        messagebox.showinfo("Scan Complete", "Port scan completed successfully.")

    # Start the scanning task in a separate thread to keep the GUI responsive.    
    threading.Thread(target=task).start()


# --- Below is the GUI setup using tkinter :D ---

plug = tk.Tk()                          # Create the main window
plug.title("Port Scanner GUI")              # Set the window title

tk.Label(plug, text="Target(s):").pack()            # Label for target input
tk.Label(plug, text="Enter target IP(s) or subnet (e.g. X.X.X.X, X.X.X.X/24):").pack()  # Instructions for target input
entry_target = tk.Entry(plug)                       # Entry field for target IPs  
entry_target.pack()


# Label and entry for port input, incluing instructions on how to input ports!!
tk.Label(plug, text="Port(s)").pack()
tk.Label(plug, text="single (p80), multiple (p1,p2,p3), range (p1-p100) combination (p1,p2,p4-p100):").pack()
entry_ports = tk.Entry(plug)
entry_ports.pack()

# Button to start the scan
tk.Button(plug, text="Scan", command=run_scan).pack()

progress = ttk.Progressbar(plug, orient="horizontal", mode="indeterminate")
progress.pack(fill=tk.X, expand=True)

text_output = tk.Text(plug, height=20, width=60) # Text area to display scan results
text_output.insert(tk.END, "Scan results will appear here...")
text_output.pack()

plug.mainloop()