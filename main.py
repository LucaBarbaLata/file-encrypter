import customtkinter as ctk
import tkinter.filedialog as filedialog
import tkinter.messagebox as messagebox
import os
import threading
import struct  # For writing/reading chunk lengths
import time
from cryptography.fernet import Fernet
import PyTaskbar  # Add the PyTaskbar import

# Global variables for progress and cancellation
progress_info = {"start_time": None, "processed": 0, "total": 0}
cancel_event = threading.Event()

def log_message(msg):
    """Append a message with a timestamp to the log window."""
    timestamp = time.strftime("%H:%M:%S")
    message = f"[{timestamp}] {msg}\n"
    logs_text.insert("end", message)
    logs_text.yview("end")
    print(message, end="")

def update_eta_label():
    if progress_info["start_time"] is None or progress_info["total"] == 0:
        eta_label.configure(text="")
        return
    processed = progress_info["processed"]
    total = progress_info["total"]
    if processed == 0:
        eta_label.configure(text="ETA: calculating...")
    else:
        elapsed = time.time() - progress_info["start_time"]
        rate = processed / elapsed if elapsed > 0 else 0
        remaining = total - processed
        if rate > 0:
            eta_sec = int(remaining / rate)
            if eta_sec < 60:
                eta_label.configure(text=f"ETA: {eta_sec} sec")
            else:
                minutes = eta_sec // 60
                seconds = eta_sec % 60
                if seconds == 0:
                    eta_label.configure(text=f"ETA: {minutes} min")
                else:
                    eta_label.configure(text=f"ETA: {minutes} min {seconds} sec")
        else:
            eta_label.configure(text="ETA: calculating...")
    if processed < total and not cancel_event.is_set():
        root.after(500, update_eta_label)
    else:
        root.after(1000, lambda: eta_label.configure(text=""))

def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
    messagebox.showinfo("Key Generated", "Encryption key has been saved as 'key.key'.")
    log_message("Key generated and saved as 'key.key'.")

def load_key():
    if os.path.exists("key.key"):
        return open("key.key", "rb").read()
    else:
        messagebox.showerror("Error", "No key found! Generate one first.")
        log_message("Error: No key found.")
        return None

def encrypt_file_thread():
    taskbar_progress = PyTaskbar.Progress(root.winfo_id())  # Instantiate a new progress object for taskbar progress
    taskbar_progress.init()  # Initialize the progress bar
    taskbar_progress.setState("loading")  # Set the taskbar progress state to normal
    key = load_key()
    if key is None:
        taskbar_progress.setState("normal")
        return
    f = Fernet(key)
    file_path = filedialog.askopenfilename(title="Select File to Encrypt")
    if not file_path:
        taskbar_progress.setState("normal")
        return
    file_size = os.path.getsize(file_path)
    progress_bar.set(0)
    progress_info["start_time"] = time.time()
    progress_info["processed"] = 0
    progress_info["total"] = file_size
    cancel_event.clear()
    root.after(500, update_eta_label)
    chunk_size = 1024 * 1024  # 1MB chunks
    log_message(f"Encrypting file: {file_path}, size: {file_size} bytes")
    enc_file_path = file_path + ".lucariki"
    try:
        with open(file_path, "rb") as file, open(enc_file_path, "wb") as enc_file:
            total_size = 0
            while True:
                if cancel_event.is_set():
                    log_message("Encryption cancelled by user.")
                    taskbar_progress.setState("normal")
                    break
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                encrypted_chunk = f.encrypt(chunk)
                enc_file.write(struct.pack('>I', len(encrypted_chunk)))
                enc_file.write(encrypted_chunk)
                total_size += len(chunk)
                progress_info["processed"] = total_size
                progress_bar.set(total_size / file_size)  # Update GUI progress
                taskbar_progress.setProgress(int(total_size / file_size * 100))  # Update taskbar progress
                root.update_idletasks()
                log_message(f"Encrypted chunk of size {len(chunk)} bytes.")
        if cancel_event.is_set():
            progress_bar.set(0)
            taskbar_progress.setProgress(0)  # Reset taskbar progress
            messagebox.showinfo("Cancelled", "Encryption cancelled.")
            if os.path.exists(enc_file_path):
                if messagebox.askyesno("Delete Incomplete File?", "Do you want to delete the incomplete file?"):
                    try:
                        os.remove(enc_file_path)
                        log_message("Incomplete file deleted.")
                    except Exception as e:
                        log_message(f"Failed to delete incomplete file: {e}")
            return
        else:
            progress_bar.set(1)
            taskbar_progress.setProgress(100)  # Set taskbar progress to 100%
            log_message(f"Encryption successful: {enc_file_path}")
            messagebox.showinfo("Success", f"File encrypted and saved as {enc_file_path}")
            if messagebox.askyesno("Delete Original?", "Do you want to delete the original file?"):
                os.remove(file_path)
                log_message("Original file deleted.")
                taskbar_progress.setState("normal")
    except Exception as e:
        log_message(f"Error during encryption: {e}")
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt_file_thread():
    taskbar_progress = PyTaskbar.Progress(root.winfo_id())  # Instantiate a new progress object for taskbar progress
    taskbar_progress.init()  # Initialize the progress bar
    taskbar_progress.setState("loading")  # Set the taskbar progress state to normal
    key = load_key()
    if key is None:
        taskbar_progress.setState("normal")
        return
    f = Fernet(key)
    file_path = filedialog.askopenfilename(title="Select File to Decrypt", filetypes=[("Encrypted Files", "*.lucariki")])
    if not file_path:
        taskbar_progress.setState("normal")
        return
    file_size = os.path.getsize(file_path)
    progress_bar.set(0)
    progress_info["start_time"] = time.time()
    progress_info["processed"] = 0
    progress_info["total"] = file_size
    cancel_event.clear()
    root.after(500, update_eta_label)
    log_message(f"Decrypting file: {file_path}, size: {file_size} bytes")
    dec_file_path = file_path.replace(".lucariki", "")
    try:
        with open(file_path, "rb") as file, open(dec_file_path, "wb") as dec_file:
            total_size = 0
            while True:
                if cancel_event.is_set():
                    log_message("Decryption cancelled by user.")
                    break
                header = file.read(4)
                if not header:
                    break
                (chunk_len,) = struct.unpack('>I', header)
                encrypted_chunk = file.read(chunk_len)
                if len(encrypted_chunk) != chunk_len:
                    raise ValueError("Incomplete encrypted chunk read")
                decrypted_chunk = f.decrypt(encrypted_chunk)
                dec_file.write(decrypted_chunk)
                total_size += len(decrypted_chunk)
                progress_info["processed"] = total_size
                progress_bar.set(total_size / progress_info["total"])  # Update GUI progress
                taskbar_progress.setProgress(int(total_size / progress_info["total"] * 100))  # Update taskbar progress
                root.update_idletasks()
                log_message(f"Decrypted chunk, recovered {len(decrypted_chunk)} bytes.")
        if cancel_event.is_set():
            progress_bar.set(0)
            taskbar_progress.setProgress(0)  # Reset taskbar progress
            messagebox.showinfo("Cancelled", "Decryption cancelled.")
            if os.path.exists(dec_file_path):
                if messagebox.askyesno("Delete Incomplete File?", "Do you want to delete the incomplete file?"):
                    try:
                        os.remove(dec_file_path)
                        log_message("Incomplete file deleted.")
                    except Exception as e:
                        log_message(f"Failed to delete incomplete file: {e}")
            return
        else:
            progress_bar.set(1)
            taskbar_progress.setProgress(100)  # Set taskbar progress to 100%
            log_message(f"Decryption successful: {dec_file_path}")
            messagebox.showinfo("Success", f"File decrypted and saved as {dec_file_path}")
            if messagebox.askyesno("Delete Encrypted File?", "Do you want to delete the encrypted file?"):
                os.remove(file_path)
                log_message("Encrypted file deleted.")
                taskbar_progress.setState("normal")
    except Exception as e:
        log_message(f"Error during decryption: {e}")
        messagebox.showerror("Error", f"Decryption failed: {e}")

def encrypt_file():
    threading.Thread(target=encrypt_file_thread, daemon=True).start()

def decrypt_file():
    threading.Thread(target=decrypt_file_thread, daemon=True).start()

def cancel_operation():
    cancel_event.set()
    log_message("Cancel requested by user.")

# ---------------------------
# Set up CustomTkinter window with dark mode
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
root = ctk.CTk()
root.title("File Encryptor & Decryptor")
root.geometry("900x550")

# Attempt to load stop icon; if not available, use text.
if os.path.exists("stop_icon.png"):
    from PIL import Image
    stop_image = Image.open("stop_icon.png")
    stop_icon = ctk.CTkImage(stop_image, size=(20,20))
    cancel_btn_config = {"text": "", "image": stop_icon}
else:
    cancel_btn_config = {"text": "STOP"}

# Main container with two columns: left for buttons, right for logs/progress/controls.
main_frame = ctk.CTkFrame(root)
main_frame.pack(fill="both", expand=True, padx=20, pady=20)
main_frame.grid_columnconfigure(1, weight=1)

# Left panel for buttons
left_frame = ctk.CTkFrame(main_frame)
left_frame.grid(row=0, column=0, sticky="ns", padx=(0,20))
left_frame.grid_rowconfigure(4, weight=1)

gen_key_btn = ctk.CTkButton(left_frame, text="Generate Key", command=generate_key, corner_radius=10)
gen_key_btn.grid(row=0, column=0, pady=5, padx=10, sticky="ew")

encrypt_btn = ctk.CTkButton(left_frame, text="Encrypt File", command=encrypt_file, corner_radius=10)
encrypt_btn.grid(row=1, column=0, pady=5, padx=10, sticky="ew")

decrypt_btn = ctk.CTkButton(left_frame, text="Decrypt File", command=decrypt_file, corner_radius=10)
decrypt_btn.grid(row=2, column=0, pady=5, padx=10, sticky="ew")

exit_btn = ctk.CTkButton(left_frame, text="Exit", command=root.destroy, corner_radius=10)
exit_btn.grid(row=3, column=0, pady=5, padx=10, sticky="ew")

# Right panel for logs, progress, and bottom controls
right_frame = ctk.CTkFrame(main_frame)
right_frame.grid(row=0, column=1, sticky="nsew")
right_frame.grid_columnconfigure(0, weight=1)
right_frame.grid_rowconfigure(0, weight=1)

# Logs text widget at the top
logs_text = ctk.CTkTextbox(right_frame, corner_radius=10)
logs_text.grid(row=0, column=0, padx=10, pady=(10,5), sticky="nsew")

# Progress bar below the logs
progress_bar = ctk.CTkProgressBar(right_frame, orientation="horizontal")
progress_bar.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
progress_bar.set(0)

# Bottom frame to hold the ETA label (left) and the red cancel button (right)
bottom_frame = ctk.CTkFrame(right_frame)
bottom_frame.grid(row=2, column=0, padx=10, pady=(5,10), sticky="ew")
bottom_frame.grid_columnconfigure(0, weight=1)
bottom_frame.grid_columnconfigure(1, weight=0)

eta_label = ctk.CTkLabel(bottom_frame, text="", anchor="w")
eta_label.grid(row=0, column=0, sticky="w")

cancel_btn = ctk.CTkButton(bottom_frame, **cancel_btn_config, command=cancel_operation, corner_radius=10)
cancel_btn.grid(row=0, column=1, padx=(10, 0), sticky="e")

root.mainloop()
