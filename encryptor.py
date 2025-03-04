from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import base64

# AES 키 생성 (256비트)
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# 파일 암호화
def encrypt_file(file_path: str, password: str):
    salt = os.urandom(16)  # 랜덤 솔트 생성
    key = generate_key(password, salt)  # AES 키 생성
    iv = os.urandom(16)  # 초기화 벡터 생성
    
    # 암호화 알고리즘 준비
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 전달받은 파일 읽어오기
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # 패딩 (AES는 16바이트 블록 단위 암호화)
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length] * padding_length)

    # 평문을 암호화
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # 암호화된 파일 저장 (.kkamack 확장자로 변경)
    enc_file_path = file_path + ".kkamack"
    with open(enc_file_path, 'wb') as f:
        f.write(salt + iv + ciphertext)  # salt + iv + 암호문 저장

    os.remove(file_path)  # 원본 파일 삭제
    print(f"Encrypted: {file_path} -> {enc_file_path}")

# 파일 복호화
def decrypt_file(enc_file_path: str, password: str):
    with open(enc_file_path, 'rb') as f:
        data = f.read()

    salt = data[:16]  # 저장된 salt 읽기
    iv = data[16:32]  # 저장된 IV 읽기
    ciphertext = data[32:]  # 암호문 읽기

    key = generate_key(password, salt)  # 복호화 키 생성
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # 패딩 제거
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]

    # 원래 파일 이름 복원
    original_file_path = enc_file_path.replace(".kkamack", "")
    with open(original_file_path, 'wb') as f:
        f.write(plaintext)

    os.remove(enc_file_path)  # 암호화된 파일 삭제
    print(f"Decrypted: {enc_file_path} -> {original_file_path}")

# 테스트 실행
if __name__ == "__main__":
    test_file = "Ransomware_Simulator/test_files/test.txt"
    password = "securepassword123"

    # 테스트용 파일 생성
    #with open(test_file, "w") as f:
    #    f.write("This is a test file for encryption.")

    # 파일 암호화 & 복호화 실행
    encrypt_file(test_file, password)
    #decrypt_file(test_file + ".kkamack", password)
