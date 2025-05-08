import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import os
import sys
from io import StringIO
import json
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import builtins
import ast
from datetime import datetime
import math
from collections import Counter
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

root = tk.Tk()
root.title("StegoSecurity 4.0")
root.geometry("900x600")
root.configure(bg="#f0f0f0")
root.resizable(True, True)  # Make window resizable

FILES_DIR = "stego_files"
LOG_FILE = "stego_log.txt"
if not os.path.exists(FILES_DIR):
    os.makedirs(FILES_DIR)

CONFIG_FILE = "stego_config.json"
DEFAULT_CONFIG = {"max_file_size": 1024, "default_stego_method": "spaces_tabs", "dev_mode": True, "entropy_threshold": 0.9}
if not os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "w") as f:
        json.dump(DEFAULT_CONFIG, f)

with open(CONFIG_FILE, "r") as f:
    config = json.load(f)

title = tk.Label(root, text="StegoSecurity 4.0", font=("Arial", 16, "bold"), bg="#f0f0f0")
title.pack(pady=10)

left_frame = tk.Frame(root, bg="#f0f0f0")
left_frame.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.Y)
right_frame = tk.Frame(root, bg="#f0f0f0")
right_frame.pack(side=tk.RIGHT, padx=10, pady=10, fill=tk.BOTH, expand=True)

tk.Label(left_frame, text="Cover Text:", bg="#f0f0f0").pack()
cover_text = scrolledtext.ScrolledText(left_frame, width=40, height=8)
cover_text.pack(pady=5)
cover_text.insert(tk.END, "Roses are red,\nViolets are blue.")

tk.Label(left_frame, text="Malicious Code:", bg="#f0f0f0").pack()
malicious_code = scrolledtext.ScrolledText(left_frame, width=40, height=8)
malicious_code.pack(pady=5)
malicious_code.insert(tk.END, '''print("HACKED")''')

tk.Label(left_frame, text="Encryption Passphrase:", bg="#f0f0f0").pack()
passphrase_entry = tk.Entry(left_frame, width=40, show="*")
passphrase_entry.pack(pady=5)
passphrase_entry.insert(0, "secretkey123")

tk.Label(left_frame, text="Number of Files:", bg="#f0f0f0").pack()
file_count = tk.Entry(left_frame, width=10)
file_count.pack(pady=5)
file_count.insert(0, "3")

tk.Label(left_frame, text="Stego Method:", bg="#f0f0f0").pack()
stego_method = tk.StringVar(value=config["default_stego_method"])
tk.OptionMenu(left_frame, stego_method, "spaces_tabs", "zero_width").pack(pady=5)

tk.Label(left_frame, text="Obfuscate (Base64):", bg="#f0f0f0").pack()
obfuscate_var = tk.BooleanVar(value=False)
tk.Checkbutton(left_frame, variable=obfuscate_var, bg="#f0f0f0").pack(pady=5)

button_frame = tk.Frame(right_frame, bg="#f0f0f0")
button_frame.pack(pady=5)

hide_btn = tk.Button(button_frame, text="Hide in Files", command=lambda: hide_in_files(), width=15)
hide_btn.grid(row=0, column=0, padx=5)
hide_btn.bind("<Enter>", lambda e: status.config(text="Hide code in stego files"))
hide_btn.bind("<Leave>", lambda e: update_status("Ready"))

unsafe_btn = tk.Button(button_frame, text="Run Unsafe", command=lambda: run_unsafe(), width=15)
unsafe_btn.grid(row=0, column=1, padx=5)
unsafe_btn.bind("<Enter>", lambda e: status.config(text="Execute code unsafely"))
unsafe_btn.bind("<Leave>", lambda e: update_status("Ready"))

secure_btn = tk.Button(button_frame, text="Run Secure", command=lambda: run_secure(), width=15)
secure_btn.grid(row=0, column=2, padx=5)
secure_btn.bind("<Enter>", lambda e: status.config(text="Analyze code securely"))
secure_btn.bind("<Leave>", lambda e: update_status("Ready"))

detect_btn = tk.Button(button_frame, text="Detect Stego", command=lambda: detect_stego(), width=15)
detect_btn.grid(row=1, column=0, padx=5, pady=5)
detect_btn.bind("<Enter>", lambda e: status.config(text="Scan for hidden data"))
detect_btn.bind("<Leave>", lambda e: update_status("Ready"))

log_btn = tk.Button(button_frame, text="View Log", command=lambda: view_log(), width=15)
log_btn.grid(row=1, column=1, padx=5, pady=5)
log_btn.bind("<Enter>", lambda e: status.config(text="Show audit log"))
log_btn.bind("<Leave>", lambda e: update_status("Ready"))

config_btn = tk.Button(button_frame, text="Check Config", command=lambda: check_config(), width=15)
config_btn.grid(row=1, column=2, padx=5, pady=5)
config_btn.bind("<Enter>", lambda e: status.config(text="Audit security settings"))
config_btn.bind("<Leave>", lambda e: update_status("Ready"))

report_btn = tk.Button(button_frame, text="Generate Report", command=lambda: generate_report(), width=15)
report_btn.grid(row=2, column=0, padx=5, pady=5)
report_btn.bind("<Enter>", lambda e: status.config(text="Export analysis to PDF"))
report_btn.bind("<Leave>", lambda e: update_status("Ready"))

tk.Label(right_frame, text="Files in stego_files:", bg="#f0f0f0").pack()
file_list = tk.Listbox(right_frame, width=50, height=10)
file_list.pack(pady=5)
def update_file_list():
    file_list.delete(0, tk.END)
    for f in os.listdir(FILES_DIR):
        if f.endswith(".txt"):
            file_list.insert(tk.END, f)
update_file_list()

tk.Label(right_frame, text="Output:", bg="#f0f0f0").pack()
output = scrolledtext.ScrolledText(right_frame, width=60, height=15)
output.pack(pady=5)
output.tag_config("threat", foreground="red")
output.tag_config("score", foreground="blue")
output.tag_config("mitigated", foreground="green")
output.tag_config("error", foreground="orange")
output.tag_config("success", foreground="darkgreen")

status = tk.Label(root, text="Ready", bg="#e0e0e0", relief=tk.SUNKEN, anchor=tk.W)
status.pack(side=tk.BOTTOM, fill=tk.X)

def update_status(text):
    status.config(text=text)

def log_action(action, details=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {action}: {details}\n")

def view_log():
    output.delete("1.0", tk.END)
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            output.insert(tk.END, f.read())
        update_status("Log viewed")
        log_action("Viewed log")
    except FileNotFoundError:
        output.insert(tk.END, "No log file found yet.\n", "error")
        update_status("No log file")

def validate_inputs():
    try:
        count = int(file_count.get())
        if count < 1:
            raise ValueError("Number must be positive")
        if not cover_text.get("1.0", tk.END).strip():
            raise ValueError("Cover text cannot be empty")
        malicious = malicious_code.get("1.0", tk.END).strip()
        if not malicious:
            raise ValueError("Malicious code cannot be empty")
        passphrase = passphrase_entry.get()
        if len(passphrase) < 8:
            raise ValueError("Passphrase must be at least 8 characters")
        if not config["dev_mode"]:
            injection_chars = {"|", "&", "`", "$"}
            if any(char in malicious for char in injection_chars):
                raise ValueError("Malicious code contains injection risks (e.g., |, &)")
        return True
    except ValueError as e:
        output.delete("1.0", tk.END)
        output.insert(tk.END, f"Input Error: {str(e)}\n", "error")
        update_status("Validation failed")
        log_action("Validation failed", str(e))
        return False

def sanitize_code(code):
    allowed = set("\n\t ") | set(map(chr, range(32, 127)))
    sanitized = "".join(c for c in code if c in allowed)
    return sanitized

def encrypt_code(code, passphrase):
    key = passphrase.encode().ljust(16)[:16]
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_code = pad(code.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_code)
    return iv + encrypted

def decrypt_code(encrypted, passphrase):
    key = passphrase.encode().ljust(16)[:16]
    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode()

def hide_in_files():
    if not validate_inputs():
        return
    
    cover = cover_text.get("1.0", tk.END).strip()
    malicious = malicious_code.get("1.0", tk.END).rstrip()
    count = int(file_count.get())
    method = stego_method.get()
    passphrase = passphrase_entry.get()
    obfuscate = obfuscate_var.get()
    
    sanitized_malicious = sanitize_code(malicious)
    if sanitized_malicious != malicious:
        output.delete("1.0", tk.END)
        output.insert(tk.END, f"Warning: Malicious code sanitized\nOriginal: {repr(malicious)}\nSanitized: {repr(sanitized_malicious)}\n", "error")
        malicious = sanitized_malicious
    else:
        output.delete("1.0", tk.END)
        output.insert(tk.END, "No sanitization needed\n", "success")
    
    if obfuscate:
        malicious = base64.b64encode(malicious.encode()).decode()
        output.insert(tk.END, "Code obfuscated with base64\n", "success")
    
    encrypted = encrypt_code(malicious, passphrase)
    binary = "".join(format(byte, "08b") for byte in encrypted)
    if method == "spaces_tabs":
        hidden = "".join(" " if bit == "0" else "\t" for bit in binary)
    else:
        hidden = "".join("\u200B" if bit == "0" else "\u200C" for bit in binary)
    
    full_content = f"{cover}\n---\n{hidden}\n"
    if len(full_content) > config["max_file_size"]:
        output.insert(tk.END, f"Error: Content exceeds max file size ({config['max_file_size']} bytes)\n", "error")
        log_action("Hide failed", "File size exceeded")
        return
    
    for i in range(count):
        filename = os.path.join(FILES_DIR, f"stego_file_{i+1}.txt")
        with open(filename, "w", encoding="utf-8") as f:
            f.write(full_content)
        output.insert(tk.END, f"Created: stego_file_{i+1}.txt (Method: {method}, Encrypted)\n", "success")
        log_action("File created", f"{filename}")
    
    update_file_list()
    update_status(f"Created {count} files with hidden code")

def dummy_import(*args, **kwargs):
    raise ImportError("Imports are disabled in unsafe mode")

def run_unsafe():
    files = filedialog.askopenfilenames(initialdir=FILES_DIR, filetypes=[("Text files", "*.txt")])
    if not files:
        output.delete("1.0", tk.END)
        output.insert(tk.END, "No files selected\n", "error")
        update_status("No files selected")
        log_action("Run unsafe failed", "No files selected")
        return
    
    output.delete("1.0", tk.END)
    method = stego_method.get()
    passphrase = passphrase_entry.get()
    obfuscate = obfuscate_var.get()
    
    allowed_builtins = {
        "print": print,
        "open": open,
        "range": range,
        "len": len,
        "str": str,
        "int": int,
        "__builtins__": {
            k: v for k, v in vars(builtins).items()
            if k not in ["eval", "exec", "os", "sys", "subprocess"]
        }
    }
    allowed_builtins["__builtins__"]["__import__"] = dummy_import
    
    for filename in files:
        try:
            with open(filename, "r", encoding="utf-8") as f:
                content = f.read()
            if not content:
                output.insert(tk.END, f"{os.path.basename(filename)}: File is empty\n", "error")
                continue
            
            parts = content.split("---", 1)
            if len(parts) < 2:
                output.insert(tk.END, f"{os.path.basename(filename)}: No hidden code found\n", "error")
                continue
            
            cover = parts[0].strip()
            hidden = parts[1]
            if method == "spaces_tabs":
                if not any(c in " \t" for c in hidden):
                    output.insert(tk.END, f"{os.path.basename(filename)}: Hidden section has no spaces/tabs\n", "error")
                    continue
                binary = "".join("0" if char == " " else "1" for char in hidden if char in " \t")
            else:
                if not any(c in "\u200B\u200C" for c in hidden):
                    output.insert(tk.END, f"{os.path.basename(filename)}: Hidden section has no zero-width chars\n", "error")
                    continue
                binary = "".join("0" if char == "\u200B" else "1" for char in hidden if char in "\u200B\u200C")
            
            if not binary or len(binary) % 8 != 0:
                output.insert(tk.END, f"{os.path.basename(filename)}: Invalid hidden code length ({len(binary)} bits)\n", "error")
                continue
            
            encrypted = bytes(int(binary[i:i+8], 2) for i in range(0, len(binary), 8))
            malicious = decrypt_code(encrypted, passphrase)
            if obfuscate:
                malicious = base64.b64decode(malicious).decode()
            
            stdout_buffer = StringIO()
            old_stdout = sys.stdout
            sys.stdout = stdout_buffer
            try:
                exec(malicious, allowed_builtins, {})
                result = stdout_buffer.getvalue()
            except Exception as e:
                result = f"Execution failed: {str(e)}"
            finally:
                sys.stdout = old_stdout
                stdout_buffer.close()
            
            output.insert(tk.END, f"Unsafe Run ({os.path.basename(filename)}):\n{result}\n", "success")
            log_action("Ran unsafe", f"{filename} - Result: {result}")
        except Exception as e:
            output.insert(tk.END, f"Error in {os.path.basename(filename)}: {str(e)}\n", "error")
            log_action("Run unsafe error", f"{filename} - {str(e)}")
    
    update_status(f"Ran {len(files)} files unsafely")

class ThreatVisitor(ast.NodeVisitor):
    def __init__(self):
        self.threats = []
        self.score = 0
    
    def visit_Import(self, node):
        for name in node.names:
            self.threats.append(f"Import: {name.name}")
            self.score += 20
        self.generic_visit(node)
    
    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute):
            func_name = f"{node.func.value.id}.{node.func.attr}"
            if func_name in {"os.system", "subprocess.run"}:
                self.threats.append(f"Dangerous call: {func_name}")
                self.score += 30
        elif isinstance(node.func, ast.Name):
            if node.func.id in {"eval", "exec"}:
                self.threats.append(f"Dynamic execution: {node.func.id}")
                self.score += 40
        self.generic_visit(node)

def calculate_threat_score(code):
    try:
        tree = ast.parse(code)
        visitor = ThreatVisitor()
        visitor.visit(tree)
        complexity = len(code.splitlines()) * 2
        visitor.score += min(complexity, 30)
        return min(visitor.score, 100), visitor.threats
    except SyntaxError:
        return 0, ["Syntax error in code"]

def rewrite_code(code):
    lines = code.splitlines()
    mitigated = []
    for line in lines:
        if "import" in line or "from" in line or "os" in line or "sys" in line or "subprocess" in line or "eval" in line or "exec" in line:
            mitigated.append(f"# Mitigated: {line}")
        else:
            mitigated.append(line)
    return "\n".join(mitigated)

def calculate_entropy(text, method="spaces_tabs"):
    if not text:
        return 0.0
    if method == "spaces_tabs":
        filtered = "".join(c for c in text if c in " \t")
    else:
        filtered = "".join(c for c in text if c in "\u200B\u200C")
    if not filtered:
        return 0.0
    length = len(filtered)
    freq = Counter(filtered)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return entropy

def detect_stego():
    files = filedialog.askopenfilenames(initialdir=FILES_DIR, filetypes=[("Text files", "*.txt")])
    if not files:
        output.delete("1.0", tk.END)
        output.insert(tk.END, "No files selected\n", "error")
        update_status("No files selected")
        log_action("Detect stego failed", "No files selected")
        return
    
    output.delete("1.0", tk.END)
    method = stego_method.get()
    passphrase = passphrase_entry.get()
    obfuscate = obfuscate_var.get()
    
    for filename in files:
        try:
            with open(filename, "r", encoding="utf-8") as f:
                content = f.read()
            if not content:
                output.insert(tk.END, f"{os.path.basename(filename)}: File is empty\n", "error")
                continue
            
            parts = content.split("---", 1)
            cover = parts[0].strip() if parts else ""
            hidden = parts[1] if len(parts) > 1 else ""
            
            entropy = calculate_entropy(hidden, method)
            stego_chars = len([c for c in hidden if c in " \t"]) if method == "spaces_tabs" else len([c for c in hidden if c in "\u200B\u200C"])
            output.insert(tk.END, f"Stego Detection ({os.path.basename(filename)}):\nHidden length: {len(hidden)}\nStego chars: {stego_chars}\nEntropy: {entropy:.2f} (Threshold: {config['entropy_threshold']})\n")
            if entropy > float(config["entropy_threshold"]) or (stego_chars > 100 and entropy > 0.5):
                output.insert(tk.END, "Potential steganography detected\n", "threat")
                if hidden:
                    if method == "spaces_tabs":
                        binary = "".join("0" if char == " " else "1" for char in hidden if char in " \t")
                    else:
                        binary = "".join("0" if char == "\u200B" else "1" for char in hidden if char in "\u200B\u200C")
                    if binary and len(binary) % 8 == 0:
                        encrypted = bytes(int(binary[i:i+8], 2) for i in range(0, len(binary), 8))
                        try:
                            malicious = decrypt_code(encrypted, passphrase)
                            if obfuscate:
                                malicious = base64.b64decode(malicious).decode()
                            output.insert(tk.END, f"Decoded Code:\n{malicious}\n")
                            mitigated = rewrite_code(malicious)
                            output.insert(tk.END, f"Mitigated Code:\n{mitigated}\n", "mitigated")
                        except Exception as e:
                            output.insert(tk.END, f"Decoding failed: {str(e)}\n", "error")
                    else:
                        output.insert(tk.END, f"Invalid binary length for decoding ({len(binary)} bits)\n", "error")
            else:
                output.insert(tk.END, "No steganography detected\n", "success")
            output.insert(tk.END, "\n")
            log_action("Stego detection", f"{filename} - Entropy: {entropy:.2f}, Stego chars: {stego_chars}")
        except Exception as e:
            output.insert(tk.END, f"Error in {os.path.basename(filename)}: {str(e)}\n", "error")
            log_action("Detect stego error", f"{filename} - {str(e)}")
    
    update_status(f"Scanned {len(files)} files for stego")

def check_config():
    output.delete("1.0", tk.END)
    issues = []
    if config["dev_mode"]:
        issues.append("Development mode is enabled (insecure for production)")
    if config["max_file_size"] > 2048:
        issues.append(f"Max file size ({config['max_file_size']} bytes) exceeds recommended 2048 bytes")
    if config["entropy_threshold"] < 0.8:
        issues.append(f"Entropy threshold ({config['entropy_threshold']}) is too low, may miss stego")
    
    output.insert(tk.END, "Configuration Check:\n")
    if issues:
        output.insert(tk.END, "Issues found:\n- " + "\n- ".join(issues) + "\n", "error")
    else:
        output.insert(tk.END, "No configuration issues detected\n", "success")
    update_status("Config checked")
    log_action("Config checked", f"Issues: {len(issues)}")

def run_secure():
    files = filedialog.askopenfilenames(initialdir=FILES_DIR, filetypes=[("Text files", "*.txt")])
    if not files:
        output.delete("1.0", tk.END)
        output.insert(tk.END, "No files selected\n", "error")
        update_status("No files selected")
        log_action("Run secure failed", "No files selected")
        return
    
    output.delete("1.0", tk.END)
    method = stego_method.get()
    passphrase = passphrase_entry.get()
    obfuscate = obfuscate_var.get()
    vulnerable_libs = {"requests": "2.25.0", "urllib3": "1.26.0"}
    
    for filename in files:
        try:
            with open(filename, "r", encoding="utf-8") as f:
                content = f.read()
            if not content:
                output.insert(tk.END, f"{os.path.basename(filename)}: File is empty\n", "error")
                continue
            
            parts = content.split("---", 1)
            if len(parts) < 2:
                output.insert(tk.END, f"{os.path.basename(filename)}: No hidden code found\n", "error")
                continue
            
            cover = parts[0].strip()
            hidden = parts[1]
            if method == "spaces_tabs":
                if not any(c in " \t" for c in hidden):
                    output.insert(tk.END, f"{os.path.basename(filename)}: Hidden section has no spaces/tabs\n", "error")
                    continue
                binary = "".join("0" if char == " " else "1" for char in hidden if char in " \t")
            else:
                if not any(c in "\u200B\u200C" for c in hidden):
                    output.insert(tk.END, f"{os.path.basename(filename)}: Hidden section has no zero-width chars\n", "error")
                    continue
                binary = "".join("0" if char == "\u200B" else "1" for char in hidden if char in "\u200B\u200C")
            
            if not binary or len(binary) % 8 != 0:
                output.insert(tk.END, f"{os.path.basename(filename)}: Invalid hidden code length ({len(binary)} bits)\n", "error")
                continue
            
            encrypted = bytes(int(binary[i:i+8], 2) for i in range(0, len(binary), 8))
            malicious = decrypt_code(encrypted, passphrase)
            if obfuscate:
                malicious = base64.b64decode(malicious).decode()
            
            output.insert(tk.END, f"Secure Analysis ({os.path.basename(filename)}):\nDecoded Code:\n{malicious}\n")
            score, threats = calculate_threat_score(malicious)
            if threats:
                output.insert(tk.END, f"Threats Detected:\n- " + "\n- ".join(threats) + "\n", "threat")
            for lib in vulnerable_libs:
                if f"import {lib}" in malicious or f"from {lib}" in malicious:
                    output.insert(tk.END, f"Vulnerable Component Detected: {lib} (known issues in versions < {vulnerable_libs[lib]})\n", "threat")
                    score += 20
            output.insert(tk.END, f"Threat Score: {min(score, 100)}/100\n", "score")
            mitigated = rewrite_code(malicious)
            output.insert(tk.END, f"Mitigated Code:\n{mitigated}\n\n", "mitigated")
            log_action("Ran secure", f"{filename} - Score: {score}, Threats: {threats}")
        except Exception as e:
            output.insert(tk.END, f"Error in {os.path.basename(filename)}: {str(e)}\n", "error")
            log_action("Run secure error", f"{filename} - {str(e)}")
    
    update_status(f"Securely analyzed {len(files)} files")

def generate_report():
    output.delete("1.0", tk.END)
    try:
        pdf_file = "StegoSecurity_Report.pdf"
        doc = SimpleDocTemplate(pdf_file, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        story.append(Paragraph("StegoSecurity 4.0 Report", styles["Title"]))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("Configuration:", styles["Heading2"]))
        config_str = "<br/>".join(f"{k}: {v}" for k, v in config.items())
        story.append(Paragraph(config_str, styles["Normal"]))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("Log Entries:", styles["Heading2"]))
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                log_content = f.read().replace("\n", "<br/>")
            story.append(Paragraph(log_content, styles["Normal"]))
        except FileNotFoundError:
            story.append(Paragraph("No log file available.", styles["Normal"]))
        
        doc.build(story)
        output.insert(tk.END, f"Report generated: {pdf_file}\n", "success")
        log_action("Report generated", pdf_file)
        update_status("Report created")
    except Exception as e:
        output.insert(tk.END, f"Report generation failed: {str(e)}\n", "error")
        log_action("Report generation error", str(e))

update_status("Application initialized")
log_action("Application started")
root.mainloop()