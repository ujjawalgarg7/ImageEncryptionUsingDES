from flask import Flask, request, render_template, send_file
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

app = Flask(__name__)

# Function to generate a 3DES key
def generate_key():
    while True:
        key = get_random_bytes(24)  # 3DES requires a 24-byte key
        try:
            DES3.new(key, DES3.MODE_ECB)
            return key
        except ValueError:
            continue

# Encrypt image
def encrypt_image(file_path, output_path, key):
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    cipher = DES3.new(key, DES3.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))
    with open(output_path, 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)
    return output_path

# Decrypt image
def decrypt_image(file_path, output_path, key):
    with open(file_path, 'rb') as f:
        iv = f.read(8)
        ciphertext = f.read()
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    return output_path

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'image' not in request.files:
        return "No file uploaded", 400
    file = request.files['image']
    if file.filename == '':
        return "No selected file", 400

    key = generate_key()
    file_path = os.path.join('uploads', file.filename)
    encrypted_path = os.path.join('uploads', 'encrypted_' + file.filename)

    os.makedirs('uploads', exist_ok=True)
    file.save(file_path)

    encrypt_image(file_path, encrypted_path, key)

    return render_template('result.html', 
                           key=key.hex(),
                           file_path=encrypted_path,
                           download_path=f'/download/{os.path.basename(encrypted_path)}')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files or 'key' not in request.form:
        return "File or key missing", 400
    file = request.files['file']
    key_hex = request.form['key']

    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        return "Invalid key format", 400

    file_path = os.path.join('uploads', file.filename)
    decrypted_path = os.path.join('uploads', 'decrypted_' + file.filename)

    os.makedirs('uploads', exist_ok=True)
    file.save(file_path)

    try:
        decrypt_image(file_path, decrypted_path, key)
    except Exception as e:
        return f"Decryption failed: {e}", 400

    return render_template('result.html', 
                           file_path=decrypted_path,
                           download_path=f'/download/{os.path.basename(decrypted_path)}')

@app.route('/download/<filename>')
def download(filename):
    file_path = os.path.join('uploads', filename)
    return send_file(file_path, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
