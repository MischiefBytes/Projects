from tkinter import *
from tkinter import filedialog
import os
from cryptography.fernet import Fernet
import base64
from PIL import Image, ImageOps, JpegImagePlugin

root = Tk()
root.geometry("600x500")
root.title("Guarded Pixels")
root.configure(bg="#f0f0f0")

title_label = Label(root, text="Guarded Pixels", font=("Helvetica", 16), fg="blue")
title_label.pack(expand=True, fill='both')

file_name = ""
file_obj = None
image_data = None
encrypted_data = None
exif_removed_image_path = None
decrypted_image_path = None

def open_file():
    global file_name
    global file_obj
    global image_data
    global exif_removed_image_path
    global decrypted_image_path
    file_path = filedialog.askopenfilename(filetypes=[
        ('JPEG Files', '*.jpg'),
        ('PNG Files', '*.png'),
        ('GIF Files', '*.gif'),
        ('Encrypted Files', '*.enc'),  # Include .enc files
        ('All Files', '*.*')
    ])

    if file_path:
        file_name = file_path
        file_label.config(text=f"selected file : {file_name}")
        with open(file_path, 'rb') as file_obj:
            image_data = file_obj.read()
        exif_removed_image_path = None
        decrypted_image_path = None
        update_decrypt_button_state()  # Update Decrypt button state when a new file is selected

def remove_exif(input_image_path):
    global exif_removed_image_path
    try:
        image = Image.open(input_image_path)
        if isinstance(image, JpegImagePlugin.JpegImageFile):
            image_without_exif = ImageOps.exif_transpose(image)
            exif_removed_image_path = input_image_path.replace(".jpg", "_no_exif.jpg")
            image_without_exif.save(exif_removed_image_path)
            status_label.config(text="Exif data removed successfully.")
        else:
            status_label.config(text="Exif data is not present in this image format.")
    except Exception as e:
        status_label.config(text=f"Error: {str(e)}")

def fn_encrypt():
    global encrypted_data
    key_str = key_entry.get()
    if len(key_str) < 32:
        key_str = key_str.ljust(32)
    elif len(key_str) > 32:
        key_str = key_str[:32]

    key = base64.urlsafe_b64encode(key_str.encode())
    cipher_suite = Fernet(key)
    if exif_removed_image_path:
        with open(exif_removed_image_path, 'rb') as file_obj:
            image_data = file_obj.read()
            encrypted_data = cipher_suite.encrypt(image_data)
            save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[('Encrypted Files', '*.enc'), ('All Files', '*.*')])
            if save_path:
                with open(save_path, 'wb') as encrypted_file:
                    encrypted_file.write(encrypted_data)
                status_label.config(text="Image encrypted and saved as " + save_path)
                clear_image_data()
                update_decrypt_button_state()

def fn_save_image():
    global exif_removed_image_path
    global encrypted_data
    if exif_removed_image_path:
        save_path = filedialog.asksaveasfilename(defaultextension=".jpg", filetypes=[('JPEG Files', '*.jpg'), ('All Files', '*.*')])
        if save_path:
            os.rename(exif_removed_image_path, save_path)
            status_label.config(text="Image with Exif data removed saved as " + save_path)
            clear_image_data()

def fn_decrypt():
    global decrypted_image_path
    key_str = key_entry.get()
    if len(key_str) < 32:
        key_str = key_str.ljust(32)
    elif len(key_str) > 32:
        key_str = key_str[:32]

    key = base64.urlsafe_b64encode(key_str.encode())
    cipher_suite = Fernet(key)

    if image_data:
        decrypted_data = cipher_suite.decrypt(image_data)
        save_path = filedialog.asksaveasfilename(defaultextension=".jpg", filetypes=[('JPEG Files', '*.jpg'), ('All Files', '*.*')])
        if save_path:
            with open(save_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
                decrypted_image_path = save_path
                status_label.config(text="Image decrypted and saved as " + save_path)
                clear_image_data()

def update_decrypt_button_state():
    global image_data
    if image_data and file_name.lower().endswith(".enc"):
        decrypt_btn['state'] = 'normal'
    else:
        decrypt_btn['state'] = 'disabled'

def clear_image_data():
    global image_data
    global exif_removed_image_path
    global encrypted_data
    global decrypted_image_path

    image_data = None
    exif_removed_image_path = None
    encrypted_data = None
    decrypted_image_path = None

select_btn = Button(root, text="Select Image", bg="lightyellow", command=open_file)
select_btn.pack(pady=20)
file_label = Label(root, text="", wraplength=400)
file_label.pack(pady=4)

key_label = Label(root, text="Enter value of Key", fg="white", bg="black")
key_label.pack(pady=1)
key_entry = Entry(root, show="*")
key_entry.pack(pady=5)

remove_exif_btn = Button(root, text="Remove Exif", bg="lightyellow", fg="blue", command=lambda: remove_exif(file_name))
remove_exif_btn.place(x=340, y=220)

encrypt_btn = Button(root, text="Encrypt", bg="lightyellow", fg="blue", command=fn_encrypt)
encrypt_btn.place(x=190, y=220)

save_btn = Button(root, text="Save", fg="Purple", bg="lightyellow", command=fn_save_image)
save_btn.pack(pady=60)
#save_btn.place(x=345,y=290)


decrypt_btn = Button(root, text="Decrypt", bg="lightyellow", fg="blue", command=fn_decrypt)
decrypt_btn.place(x=270, y=220)
decrypt_btn['state'] = 'disabled'

status_label = Label(root, text="", wraplength=400)
status_label.pack()

exit_btn = Button(root, text="Exit", command=root.destroy, fg="red")
exit_btn.pack(pady=50)

root.mainloop()
