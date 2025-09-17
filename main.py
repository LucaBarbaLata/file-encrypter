import customtkinter as ctk
import tkinter.filedialog as filedialog
import tkinter.messagebox as messagebox
import os
import threading
import struct
import time
from cryptography.fernet import Fernet
import PyTaskbar


progress_info = {"start_time": None, "processed": 0, "total": 0}
cancel_event = threading.Event()


def log_message(msg):
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
                eta_label.configure(text=f"ETA: {minutes} min {seconds} sec" if seconds else f"ETA: {minutes} min")
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


def encrypt_file_thread(file_path):
    taskbar_progress = PyTaskbar.Progress(root.winfo_id())
    taskbar_progress.init()
    taskbar_progress.setState("loading")
    key = load_key()
    if key is None: taskbar_progress.setState("normal"); return
    f = Fernet(key)

    file_size = os.path.getsize(file_path)
    progress_info.update({"start_time": time.time(), "processed": 0, "total": file_size})
    cancel_event.clear()
    root.after(500, update_eta_label)

    chunk_size = 1024*1024
    log_message(f"Encrypting file: {file_path}, size: {file_size} bytes")
    enc_file_path = file_path + ".lucariki"
    try:
        with open(file_path, "rb") as file, open(enc_file_path, "wb") as enc_file:
            total_size = 0
            while True:
                if cancel_event.is_set(): break
                chunk = file.read(chunk_size)
                if not chunk: break
                enc_chunk = f.encrypt(chunk)
                enc_file.write(struct.pack('>I', len(enc_chunk)))
                enc_file.write(enc_chunk)
                total_size += len(chunk)
                progress_info["processed"] = total_size
                progress_bar.set(total_size / file_size)
                taskbar_progress.setProgress(int(total_size/file_size*100))
                root.update_idletasks()
                log_message(f"Encrypted chunk of size {len(chunk)} bytes.")
        if cancel_event.is_set():
            progress_bar.set(0); taskbar_progress.setProgress(0)
            messagebox.showinfo("Cancelled", "Encryption cancelled.")
            if os.path.exists(enc_file_path) and messagebox.askyesno("Delete Incomplete?", "Delete incomplete file?"): os.remove(enc_file_path)
            return
        progress_bar.set(1); taskbar_progress.setProgress(100)
        log_message(f"Encryption successful: {enc_file_path}")
        messagebox.showinfo("Success", f"File encrypted: {enc_file_path}")
        if messagebox.askyesno("Delete Original?", "Delete original file?"): os.remove(file_path); log_message("Original file deleted.")
        taskbar_progress.setState("normal")
    except Exception as e:
        log_message(f"Error: {e}")
        messagebox.showerror("Error", f"Encryption failed: {e}")

def encrypt_folder_thread():
    taskbar_progress = PyTaskbar.Progress(root.winfo_id()); taskbar_progress.init(); taskbar_progress.setState("loading")
    key = load_key()
    if key is None: taskbar_progress.setState("normal"); return
    f = Fernet(key)
    folder_path = filedialog.askdirectory(title="Select Folder to Encrypt")
    if not folder_path: taskbar_progress.setState("normal"); return

    files_to_encrypt, total_size = [], 0
    for root_dir, _, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root_dir, file)
            if full_path.endswith(".lucariki"):
                log_message(f"Skipping already encrypted file: {file}")
                continue
            files_to_encrypt.append(full_path)
            total_size += os.path.getsize(full_path)
    if total_size==0: messagebox.showinfo("No Files","No files found."); taskbar_progress.setState("normal"); return

    progress_info.update({"start_time": time.time(), "processed":0, "total":total_size})
    cancel_event.clear()
    root.after(500, update_eta_label)
    chunk_size = 1024*1024
    log_message(f"Encrypting folder: {folder_path}, total size: {total_size} bytes")
    encrypted_files = []

    try:
        for file_path in files_to_encrypt:
            if cancel_event.is_set(): log_message("Cancelled"); break
            enc_file_path = file_path + ".lucariki"
            with open(file_path,"rb") as file, open(enc_file_path,"wb") as enc_file:
                while True:
                    if cancel_event.is_set(): break
                    chunk = file.read(chunk_size)
                    if not chunk: break
                    enc_chunk = f.encrypt(chunk)
                    enc_file.write(struct.pack('>I',len(enc_chunk)))
                    enc_file.write(enc_chunk)
                    progress_info["processed"] += len(chunk)
                    progress_bar.set(progress_info["processed"]/total_size)
                    taskbar_progress.setProgress(int(progress_info["processed"]/total_size*100))
                    root.update_idletasks()
                    log_message(f"Encrypted chunk from {os.path.basename(file_path)}, {len(chunk)} bytes")
            if not cancel_event.is_set(): encrypted_files.append(file_path)

        if cancel_event.is_set(): progress_bar.set(0); taskbar_progress.setProgress(0); messagebox.showinfo("Cancelled","Folder encryption cancelled")
        else:
            progress_bar.set(1); taskbar_progress.setProgress(100)
            log_message(f"Folder encryption completed: {folder_path}")
            messagebox.showinfo("Success","All files in folder encrypted successfully")
            if encrypted_files and messagebox.askyesno("Delete Originals?","Delete all original files?"):
                for orig_file in encrypted_files:
                    try: os.remove(orig_file); log_message(f"Deleted: {os.path.basename(orig_file)}")
                    except Exception as e: log_message(f"Failed to delete {os.path.basename(orig_file)}: {e}")
        taskbar_progress.setState("normal")
    except Exception as e:
        log_message(f"Error: {e}")
        messagebox.showerror("Error",f"Folder encryption failed: {e}")


def decrypt_file_thread():
    taskbar_progress = PyTaskbar.Progress(root.winfo_id()); taskbar_progress.init(); taskbar_progress.setState("loading")
    key = load_key()
    if key is None: taskbar_progress.setState("normal"); return
    f = Fernet(key)
    file_path = filedialog.askopenfilename(title="Select File to Decrypt", filetypes=[("Encrypted Files","*.lucariki")])
    if not file_path: taskbar_progress.setState("normal"); return

    file_size = os.path.getsize(file_path)
    progress_info.update({"start_time": time.time(), "processed":0, "total":file_size})
    cancel_event.clear()
    root.after(500, update_eta_label)
    dec_file_path = file_path.replace(".lucariki","")
    log_message(f"Decrypting file: {file_path}, size: {file_size} bytes")

    try:
        with open(file_path,"rb") as file, open(dec_file_path,"wb") as dec_file:
            total_size=0
            while True:
                if cancel_event.is_set(): break
                header = file.read(4)
                if not header: break
                (chunk_len,) = struct.unpack('>I', header)
                enc_chunk = file.read(chunk_len)
                if len(enc_chunk)!=chunk_len: raise ValueError("Incomplete chunk")
                dec_chunk = f.decrypt(enc_chunk)
                dec_file.write(dec_chunk)
                total_size += len(dec_chunk)
                progress_info["processed"] = total_size
                progress_bar.set(total_size/file_size)
                taskbar_progress.setProgress(int(total_size/file_size*100))
                root.update_idletasks()
                log_message(f"Decrypted chunk {len(dec_chunk)} bytes")
        if cancel_event.is_set(): progress_bar.set(0); taskbar_progress.setProgress(0); messagebox.showinfo("Cancelled","Decryption cancelled")
        else:
            progress_bar.set(1); taskbar_progress.setProgress(100)
            log_message(f"Decryption successful: {dec_file_path}")
            messagebox.showinfo("Success", f"File decrypted: {dec_file_path}")
            if messagebox.askyesno("Delete Encrypted?","Delete encrypted file?"): os.remove(file_path); log_message("Encrypted file deleted.")
        taskbar_progress.setState("normal")
    except Exception as e:
        log_message(f"Error: {e}"); messagebox.showerror("Error",f"Decryption failed: {e}")

def decrypt_folder_thread():
    taskbar_progress = PyTaskbar.Progress(root.winfo_id()); taskbar_progress.init(); taskbar_progress.setState("loading")
    key = load_key()
    if key is None: taskbar_progress.setState("normal"); return
    f = Fernet(key)
    folder_path = filedialog.askdirectory(title="Select Folder to Decrypt")
    if not folder_path: taskbar_progress.setState("normal"); return

    files_to_decrypt, total_size = [],0
    for root_dir, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".lucariki"):
                full_path = os.path.join(root_dir, file)
                files_to_decrypt.append(full_path)
                total_size += os.path.getsize(full_path)
    if total_size==0: messagebox.showinfo("No Files","No encrypted files found."); taskbar_progress.setState("normal"); return

    progress_info.update({"start_time": time.time(),"processed":0,"total":total_size})
    cancel_event.clear()
    root.after(500, update_eta_label)
    chunk_size=1024*1024
    log_message(f"Decrypting folder: {folder_path}, total size: {total_size} bytes")
    decrypted_files = []

    try:
        for file_path in files_to_decrypt:
            if cancel_event.is_set(): log_message("Cancelled"); break
            dec_file_path = file_path.replace(".lucariki","")
            with open(file_path,"rb") as file, open(dec_file_path,"wb") as dec_file:
                while True:
                    if cancel_event.is_set(): break
                    header=file.read(4)
                    if not header: break
                    (chunk_len,)=struct.unpack('>I',header)
                    enc_chunk=file.read(chunk_len)
                    if len(enc_chunk)!=chunk_len: raise ValueError("Incomplete chunk")
                    dec_chunk=f.decrypt(enc_chunk)
                    dec_file.write(dec_chunk)
                    progress_info["processed"]+=len(dec_chunk)
                    progress_bar.set(progress_info["processed"]/total_size)
                    taskbar_progress.setProgress(int(progress_info["processed"]/total_size*100))
                    root.update_idletasks()
                    log_message(f"Decrypted chunk from {os.path.basename(file_path)}, {len(dec_chunk)} bytes")
            if not cancel_event.is_set(): decrypted_files.append(file_path)

        if cancel_event.is_set(): progress_bar.set(0); taskbar_progress.setProgress(0); messagebox.showinfo("Cancelled","Folder decryption cancelled")
        else:
            progress_bar.set(1); taskbar_progress.setProgress(100)
            log_message(f"Folder decryption completed: {folder_path}")
            messagebox.showinfo("Success","All files in folder decrypted successfully")
            if decrypted_files and messagebox.askyesno("Delete Encrypted?","Delete all encrypted files?"):
                for enc_file in decrypted_files:
                    try: os.remove(enc_file); log_message(f"Deleted: {os.path.basename(enc_file)}")
                    except Exception as e: log_message(f"Failed to delete {os.path.basename(enc_file)}: {e}")
        taskbar_progress.setState("normal")
    except Exception as e:
        log_message(f"Error: {e}"); messagebox.showerror("Error",f"Folder decryption failed: {e}")


def encrypt_file():
    f = filedialog.askopenfilename(title="Select File to Encrypt")
    if f:
        if f.endswith(".lucariki"):
            messagebox.showwarning("Already Encrypted","This file is already encrypted!")
            log_message(f"Skipped already encrypted file: {f}")
            return
        threading.Thread(target=encrypt_file_thread,args=(f,),daemon=True).start()

def encrypt_folder(): threading.Thread(target=encrypt_folder_thread,daemon=True).start()
def decrypt_file(): threading.Thread(target=decrypt_file_thread,daemon=True).start()
def decrypt_folder(): threading.Thread(target=decrypt_folder_thread,daemon=True).start()
def cancel_operation(): cancel_event.set(); log_message("Cancel requested by user.")


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
root=ctk.CTk()
root.title("File-Encrypter")
root.geometry("900x550")


if os.path.exists("stop_icon.png"):
    from PIL import Image
    stop_image=Image.open("stop_icon.png")
    stop_icon=ctk.CTkImage(stop_image,size=(20,20))
    cancel_btn_config={"text":"","image":stop_icon}
else: cancel_btn_config={"text":"STOP"}

main_frame=ctk.CTkFrame(root); main_frame.pack(fill="both",expand=True,padx=20,pady=20); main_frame.grid_columnconfigure(1,weight=1)
left_frame=ctk.CTkFrame(main_frame); left_frame.grid(row=0,column=0,sticky="ns",padx=(0,20)); left_frame.grid_rowconfigure(7,weight=1)

ctk.CTkButton(left_frame,text="Generate Key",command=generate_key,corner_radius=10).grid(row=0,column=0,pady=5,padx=10,sticky="ew")
ctk.CTkButton(left_frame,text="Encrypt File",command=encrypt_file,corner_radius=10).grid(row=1,column=0,pady=5,padx=10,sticky="ew")
ctk.CTkButton(left_frame,text="Encrypt Folder",command=encrypt_folder,corner_radius=10).grid(row=2,column=0,pady=5,padx=10,sticky="ew")
ctk.CTkButton(left_frame,text="Decrypt File",command=decrypt_file,corner_radius=10).grid(row=3,column=0,pady=5,padx=10,sticky="ew")
ctk.CTkButton(left_frame,text="Decrypt Folder",command=decrypt_folder,corner_radius=10).grid(row=4,column=0,pady=5,padx=10,sticky="ew")
ctk.CTkButton(left_frame,text="Exit",command=root.destroy,corner_radius=10).grid(row=5,column=0,pady=5,padx=10,sticky="ew")

right_frame=ctk.CTkFrame(main_frame); right_frame.grid(row=0,column=1,sticky="nsew"); right_frame.grid_columnconfigure(0,weight=1); right_frame.grid_rowconfigure(0,weight=1)
logs_text=ctk.CTkTextbox(right_frame,corner_radius=10); logs_text.grid(row=0,column=0,padx=10,pady=(10,5),sticky="nsew")
progress_bar=ctk.CTkProgressBar(right_frame,orientation="horizontal"); progress_bar.grid(row=1,column=0,padx=10,pady=5,sticky="ew"); progress_bar.set(0)
bottom_frame=ctk.CTkFrame(right_frame); bottom_frame.grid(row=2,column=0,padx=10,pady=(5,10),sticky="ew"); bottom_frame.grid_columnconfigure(0,weight=1); bottom_frame.grid_columnconfigure(1,weight=0)
eta_label=ctk.CTkLabel(bottom_frame,text="",anchor="w"); eta_label.grid(row=0,column=0,sticky="w")
cancel_btn=ctk.CTkButton(bottom_frame,**cancel_btn_config,command=cancel_operation,corner_radius=10); cancel_btn.grid(row=0,column=1,padx=(10,0),sticky="e")

root.mainloop()
