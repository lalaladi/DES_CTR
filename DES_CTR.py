# Tabel dan konstanta untuk DES
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

def permute(bits, table):
    """Melakukan permutasi bit berdasarkan tabel tertentu"""
    return [bits[x - 1] for x in table]

def xor(bits1, bits2):
    """Operasi XOR antara dua list bit"""
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def feistel_function(right, subkey):
    # Contoh fungsi Feistel sederhana yang hanya menggunakan XOR
    return xor(right, subkey)

def des_encrypt_block(block, key):
    """Enkripsi satu blok (64-bit) menggunakan kunci 64-bit"""
    # Permutasi awal
    block = permute(block, IP)

    # Membagi blok menjadi dua bagian 32-bit
    left, right = block[:32], block[32:]

    # 16 putaran DES
    for _ in range(16):
        new_right = xor(left, feistel_function(right, key))
        left = right
        right = new_right

    # Gabungkan kembali dan permutasi akhir
    combined = right + left
    return permute(combined, IP_INV)

def des_decrypt_block(block, key):
    """Dekripsi satu blok (64-bit) menggunakan kunci 64-bit"""
    # Sama seperti enkripsi, tapi urutan subkunci dibalik
    return des_encrypt_block(block, key)  # Karena operasi simetris

def str_to_bits(s):
    """Mengonversi string ke bit list"""
    return [int(bit) for byte in s.encode('utf-8') for bit in format(byte, '08b')]

def bits_to_str(bits):
    """Mengonversi bit list kembali ke string"""
    return ''.join(chr(int(''.join(str(x) for x in bits[i:i + 8]), 2)) for i in range(0, len(bits), 8))

def pad_data(data):
    """Menambahkan padding agar panjangnya kelipatan 64 bit"""
    padding_len = 64 - len(data) % 64
    return data + [0] * padding_len

def bits_to_binary_string(bits):
    """Mengonversi list bit ke string biner"""
    return ''.join(str(b) for b in bits)

def main():
    key = [0] * 64 
    plaintext = input("Masukkan teks yang ingin dienkripsi: ")
    plaintext_bits = str_to_bits(plaintext)
    plaintext_bits = pad_data(plaintext_bits)

    # Enkripsi
    ciphertext_bits = []
    for i in range(0, len(plaintext_bits), 64):
        block = plaintext_bits[i:i + 64]
        encrypted_block = des_encrypt_block(block, key)
        ciphertext_bits.extend(encrypted_block)

    # Mengonversi kembali ke teks untuk ditampilkan
    ciphertext_binary = bits_to_binary_string(ciphertext_bits)
    # print(f"Ciphertext (Biner): {ciphertext_binary}")

    # Dekripsi
    decrypted_bits = []
    for i in range(0, len(ciphertext_bits), 64):
        block = ciphertext_bits[i:i + 64]
        decrypted_block = des_decrypt_block(block, key)
        decrypted_bits.extend(decrypted_block)

    decrypted_text = bits_to_str(decrypted_bits)
    print(f"Decrypted: {decrypted_text}")

if __name__ == "__main__":
    main()
