import hashlib
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii

def to_hex(data): return binascii.hexlify(data).decode()
def from_hex(hex_str): return binascii.unhexlify(hex_str)

# --- 1. MÃ HÓA ĐỐI XỨNG ---
def symmetric_encryption():
    print("\n--- MÃ HÓA ĐỐI XỨNG ---")
    algo_choice = input("Chọn thuật toán (1: DES, 2: 3DES, 3: AES): ")
    mode_input = input("Chọn chế độ (ECB/CBC): ").upper()
    action = input("1. Mã hóa | 2. Giải mã: ")
    
    config = {'1': (DES, 8), '2': (DES3, 24), '3': (AES, 16)}
    algo, key_size = config.get(algo_choice, (AES, 16))
    
    key_choice = input("1. Nhập khóa thủ công | 2. Tạo ngẫu nhiên: ")
    if key_choice == '2':
        key = get_random_bytes(key_size)
        print(f"Khóa ngẫu nhiên (Hex): {to_hex(key)}")
    else:
        key_input = input(f"Nhập khóa ({key_size} ký tự): ").encode()
        key = key_input[:key_size].ljust(key_size, b'\0')

    cipher_mode = algo.MODE_CBC if mode_input == "CBC" else algo.MODE_ECB
    
    try:
        if action == '1':
            plaintext = input("Nhập văn bản: ").encode()
            cipher = algo.new(key, cipher_mode)
            iv = cipher.iv if mode_input == "CBC" else b''
            ciphertext = cipher.encrypt(pad(plaintext, algo.block_size))
            print(f"Kết quả (Ciphertext Hex): {to_hex(iv + ciphertext)}")
        else:
            raw_data = from_hex(input("Nhập Ciphertext (Hex): "))
            if mode_input == "CBC":
                iv, ct = raw_data[:algo.block_size], raw_data[algo.block_size:]
                cipher = algo.new(key, cipher_mode, iv=iv)
            else:
                cipher = algo.new(key, cipher_mode)
            print(f"Kết quả (Plaintext): {unpad(cipher.decrypt(raw_data if mode_input != 'CBC' else ct), algo.block_size).decode()}")
    except Exception as e:
        print(f"Lỗi: Dữ liệu hoặc khóa không hợp lệ! ({e})")

# --- 2. MÃ HÓA BẤT ĐỐI XỨNG ---
def asymmetric_encryption():
    print("\n--- MÃ HÓA BẤT ĐỐI XỨNG (RSA) ---")
    choice = input("1. Tạo khóa | 2. Mã hóa | 3. Giải mã: ")
    if choice == '1':
        key = RSA.generate(2048)
        print(f"Public Key:\n{key.publickey().export_key().decode()}")
        print(f"Private Key:\n{key.export_key().decode()}")
    elif choice == '2':
        pub_key = RSA.import_key(input("Nhập Public Key: "))
        cipher = PKCS1_OAEP.new(pub_key)
        print(f"Ciphertext (Hex): {to_hex(cipher.encrypt(input('Nhập văn bản: ').encode()))}")
    elif choice == '3':
        priv_key = RSA.import_key(input("Nhập Private Key: "))
        cipher = PKCS1_OAEP.new(priv_key)
        print(f"Plaintext: {cipher.decrypt(from_hex(input('Nhập Ciphertext Hex: '))).decode()}")

# --- 3. HÀM BĂM ---
def hash_functions():
    print("\n--- HÀM BĂM ---")
    text = input("Nhập chuỗi: ").encode()
    print(f"MD5: {hashlib.md5(text).hexdigest()}")
    print(f"SHA-256: {hashlib.sha256(text).hexdigest()}")

# --- MENU CHÍNH ---
if __name__ == "__main__":
    while True:
        print("\n=== CRYPTO TOOLKIT ===")
        choice = input("1. Đối xứng | 2. Bất đối xứng | 3. Băm | 0. Thoát: ")
        if choice == '1': symmetric_encryption()
        elif choice == '2': asymmetric_encryption()
        elif choice == '3': hash_functions()
        elif choice == '0': break
        input("\nNhấn Enter để tiếp tục...")