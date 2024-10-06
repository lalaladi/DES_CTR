import os

def int_to_bytes(n, length):
    return n.to_bytes(length, byteorder='big')

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def xor_bytes(block1, block2):    # Operasi XOR antara dua blok byte
    return bytes([b1 ^ b2 for b1, b2 in zip(block1, block2)])

def des_encrypt_block(block, key):
    return xor_bytes(block, key)

def ctr_mode(data, key, iv, encrypt=True):
    block_size = 8
    counter = bytes_to_int(iv)
    result = bytearray()
    
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        encrypted_counter = des_encrypt_block(int_to_bytes(counter, block_size), key)
        result_block = xor_bytes(block, encrypted_counter)
        result.extend(result_block)
        counter += 1

    return bytes(result)

def bytes_to_binary_string(b):
    return ''.join(format(byte, '08b') for byte in b)  # Ubah byte ke biner

def generate_key():
    return os.urandom(8)  # Menghasilkan kunci 8 byte secara acak

def main():
    sKey = generate_key()  # Menghasilkan kunci baru
    iv = bytes([0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01])

    plaintext = input("Masukkan teks yang ingin dienkripsi: ")
    print("Plaintext :", plaintext)
    plaintext_bytes = plaintext.encode('utf-8')
    

    ciphertext_bytes = ctr_mode(plaintext_bytes, sKey, iv, encrypt=True)
    print("Ciphertext :", ciphertext_bytes)
    print("Ciphertext (Biner):", bytes_to_binary_string(ciphertext_bytes))

    decrypted_bytes = ctr_mode(ciphertext_bytes, sKey, iv, encrypt=False)
    decrypted_text = decrypted_bytes.decode('utf-8')
    print("Decrypted (Text):", decrypted_text)

if __name__ == "__main__":
    main()
