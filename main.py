import hashlib
import binascii
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# --- CÁC HÀM TIỆN ÍCH CHỐNG LỖI ---
def to_hex(data): 
    return binascii.hexlify(data).decode()

def from_hex(hex_str): 
    try:
        # Xóa mọi khoảng trắng hoặc ký tự thừa nếu lỡ copy dính
        clean_hex = hex_str.strip().replace(" ", "").replace("\n", "")
        return binascii.unhexlify(clean_hex)
    except Exception:
        return None

def read_multiline_rsa_key(prompt):
    """Hàm đặc biệt để đọc khóa RSA nhiều dòng mà không bị lỗi khi Paste"""
    print(prompt)
    print("(Hãy dán khóa vào đây, sau đó nhấn Enter thêm 1 lần nữa ở dòng trống để xác nhận):")
    lines = []
    while True:
        line = input()
        if line.strip() == "":
            break
        lines.append(line)
    return "\n".join(lines)

# --- 1. MÃ HÓA ĐỐI XỨNG ---
def symmetric_encryption():
    print("\n" + "-"*30)
    print("      MÃ HÓA ĐỐI XỨNG      ")
    print("-"*30)
    algo_choice = input("Chọn thuật toán (1: DES, 2: 3DES, 3: AES): ").strip()
    
    config = {'1': (DES, 8, "DES"), '2': (DES3, 24, "3DES"), '3': (AES, 16, "AES")}
    if algo_choice not in config:
        print("[-] Thuật toán không hợp lệ, mặc định chọn AES.")
        algo_choice = '3'
        
    algo, key_size, algo_name = config[algo_choice]
    mode_input = input("Chọn chế độ (ECB / CBC): ").strip().upper()
    cipher_mode = algo.MODE_CBC if mode_input == "CBC" else algo.MODE_ECB
    
    action = input("1. Mã hóa | 2. Giải mã: ").strip()
    if action not in ['1', '2']:
        print("[-] Lựa chọn không hợp lệ!")
        return

    key_choice = input("1. Nhập khóa thủ công | 2. Tạo ngẫu nhiên: ").strip()
    if key_choice == '2':
        key = get_random_bytes(key_size)
        print(f"\n[+] Khóa ngẫu nhiên (Hex): {to_hex(key)}")
    else:
        key_input_str = input(f"Nhập khóa (Text hoặc Hex dài {key_size*2} ký tự): ").strip()
        key_hex_decoded = from_hex(key_input_str)
        if key_hex_decoded and len(key_hex_decoded) == key_size:
            key = key_hex_decoded
        else:
            key = key_input_str.encode()[:key_size].ljust(key_size, b'\0')

    try:
        if action == '1':
            plaintext = input("Nhập văn bản gốc: ").encode('utf-8')
            cipher = algo.new(key, cipher_mode)
            iv = cipher.iv if mode_input == "CBC" else b''
            ciphertext = cipher.encrypt(pad(plaintext, algo.block_size))
            print(f"\n[+] Kết quả (Ciphertext Hex):\n{to_hex(iv + ciphertext)}")
            
        elif action == '2':
            hex_input = input("Nhập Ciphertext (Hex): ")
            raw_data = from_hex(hex_input)
            
            if not raw_data:
                print("\n[-] Lỗi: Ciphertext không phải là chuỗi Hex hợp lệ!")
                return
                
            if mode_input == "CBC":
                iv, ct = raw_data[:algo.block_size], raw_data[algo.block_size:]
                cipher = algo.new(key, cipher_mode, iv=iv)
            else:
                ct = raw_data
                cipher = algo.new(key, cipher_mode)
                
            decrypted_data = unpad(cipher.decrypt(ct), algo.block_size)
            print(f"\n[+] Kết quả (Plaintext): {decrypted_data.decode('utf-8')}")
            
    except ValueError:
        print("\n[-] Lỗi bảo mật: Sai khóa, sai chế độ hoặc dữ liệu đã bị thay đổi! (Padding is incorrect)")
    except Exception as e:
        print(f"\n[-] Lỗi hệ thống: {e}")

# --- 2. MÃ HÓA BẤT ĐỐI XỨNG (RSA) ---
def asymmetric_encryption():
    print("\n" + "-"*30)
    print("   MÃ HÓA BẤT ĐỐI XỨNG (RSA)   ")
    print("-"*30)
    choice = input("1. Tạo khóa | 2. Mã hóa | 3. Giải mã: ").strip()
    
    try:
        if choice == '1':
            key = RSA.generate(2048)
            print("\n[+] Public Key (Dùng để mã hóa):")
            print(key.publickey().export_key().decode())
            print("\n[+] Private Key (Dùng để giải mã):")
            print(key.export_key().decode())
            
        elif choice == '2':
            pub_key_input = read_multiline_rsa_key("\nNhập Public Key (Bắt đầu bằng -----BEGIN PUBLIC KEY-----):")
            if "BEGIN" not in pub_key_input:
                print("[-] Lỗi: Key không đúng định dạng!")
                return
            pub_key = RSA.import_key(pub_key_input)
            cipher = PKCS1_OAEP.new(pub_key)
            plaintext = input("Nhập văn bản cần mã hóa: ").encode('utf-8')
            print(f"\n[+] Ciphertext (Hex):\n{to_hex(cipher.encrypt(plaintext))}")
            
        elif choice == '3':
            priv_key_input = read_multiline_rsa_key("\nNhập Private Key (Bắt đầu bằng -----BEGIN RSA PRIVATE KEY-----):")
            if "BEGIN" not in priv_key_input:
                print("[-] Lỗi: Key không đúng định dạng!")
                return
            priv_key = RSA.import_key(priv_key_input)
            cipher = PKCS1_OAEP.new(priv_key)
            hex_input = input("Nhập Ciphertext (Hex): ")
            ciphertext = from_hex(hex_input)
            if not ciphertext:
                print("[-] Lỗi: Ciphertext không hợp lệ!")
                return
            print(f"\n[+] Plaintext giải mã được:\n{cipher.decrypt(ciphertext).decode('utf-8')}")
            
    except ValueError:
        print("\n[-] Lỗi: Giải mã thất bại! Có thể sai Private Key hoặc Ciphertext bị hỏng.")
    except Exception as e:
        print(f"\n[-] Lỗi: {e}")

# --- 3. HÀM BĂM ---
def hash_functions():
    print("\n" + "-"*30)
    print("           HÀM BĂM           ")
    print("-"*30)
    text = input("Nhập chuỗi văn bản cần băm: ").encode('utf-8')
    print(f"\n[+] MD5:     {hashlib.md5(text).hexdigest()}")
    print(f"[+] SHA-256: {hashlib.sha256(text).hexdigest()}")

# --- MENU CHÍNH ---
if __name__ == "__main__":
    while True:
        print("\n" + "="*35)
        print("       CRYPTOGRAPHY TOOLKIT      ")
        print("="*35)
        choice = input("1. Đối xứng | 2. Bất đối xứng | 3. Băm | 0. Thoát\nChọn tính năng: ").strip()
        
        if choice == '1': 
            symmetric_encryption()
        elif choice == '2': 
            asymmetric_encryption()
        elif choice == '3': 
            hash_functions()
        elif choice == '0': 
            print("Đã thoát chương trình.")
            break
        else:
            print("[-] Lựa chọn không hợp lệ, vui lòng chọn lại!")