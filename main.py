import struct
import sys

# Константы для SHA-256
K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa11, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Константы для SHA-512
K512 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa11, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    0x6ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
    0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb,
    0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
    0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa11,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
    0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb,
    0xbef9a3f7, 0xc67178f2
]


# циклический сдвиг вправо для 32-битного значения.
def right_rotate(value, amount):
    return ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF


def sha256(message):
    # Инициализация хеш-значений
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    # Обработка сообщения
    message_byte_len = len(message)
    message_bit_len = message_byte_len * 8 #вычисляем длину входного сообщения в байтах и переводим её в биты
    message += b'\x80' #добавляем бит 1 (в виде байта 0x80)
    message += b'\x00' * ((56 - (message_byte_len + 1) % 64) % 64) #добавляем нули, чтобы длина сообщения стала кратной 512 битам
    message += struct.pack('>Q', message_bit_len)

    for i in range(0, len(message), 64): # разбиваем сообщение на блоки по 512 бит
        chunk = message[i:i + 64] # извлекаем блок для проверки
        w = list(struct.unpack('>16L', chunk)) + [0] * 48 #массив,торый содержит 64 значения.

        for j in range(16, 64):
            s0 = right_rotate(w[j - 15], 7) ^ right_rotate(w[j - 15], 18) ^ (w[j - 15] >> 3) #сдвиг
            s1 = right_rotate(w[j - 2], 17) ^ right_rotate(w[j - 2], 19) ^ (w[j - 2] >> 10) #сдвиг
            w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h0 = h

        for j in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25) #сдвиг
            ch = (e & f) ^ (~e & g)
            temp1 = (h0 + S1 + ch + K256[j] + w[j]) & 0xFFFFFFFF
            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22) #сдвиг
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h0 = (temp1 + temp2) & 0xFFFFFFFF
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, h0])] # обновляем массив хеш-значений

    return b''.join(struct.pack('>L', i) for i in h) #объединяем все хеш значения в байтовую строку


def sha512(message):
    # Инициализация хеш-значений
    h = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    ]

    # Обработка сообщения
    message_byte_len = len(message)
    message_bit_len = message_byte_len * 8
    message += b'\x80'
    message += b'\x00' * ((112 - (message_byte_len + 1) % 128) % 128)
    message += struct.pack('>Q', message_bit_len >> 32)
    message += struct.pack('>Q', message_bit_len & 0xFFFFFFFF)

    for i in range(0, len(message), 128):
        chunk = message[i:i + 128]
        w = list(struct.unpack('>16Q', chunk)) + [0] * 112

        for j in range(16, 80):
            s0 = right_rotate(w[j - 15], 1) ^ right_rotate(w[j - 15], 8) ^ (w[j - 15] >> 7)
            s1 = right_rotate(w[j - 2], 19) ^ right_rotate(w[j - 2], 61) ^ (w[j - 2] >> 6)
            w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & 0xFFFFFFFFFFFFFFFF

        a, b, c, d, e, f, g, h0 = h

        for j in range(80):
            S1 = right_rotate(e, 14) ^ right_rotate(e, 18) ^ right_rotate(e, 41)
            ch = (e & f) ^ (~e & g)
            temp1 = (h0 + S1 + ch + K512[j] + w[j]) & 0xFFFFFFFFFFFFFFFF
            S0 = right_rotate(a, 28) ^ right_rotate(a, 34) ^ right_rotate(a, 39)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFFFFFFFFFF

            h0 = (temp1 + temp2) & 0xFFFFFFFFFFFFFFFF
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFFFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFFFFFFFFFF

        h = [(x + y) & 0xFFFFFFFFFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, h0])]

    return b''.join(struct.pack('>Q', i) for i in h)


def main():
    choice = input("Выберите алгоритм (1 - SHA-256, 2 - SHA-512): ")
    input_source = input("Выберите источник данных (1 - Консоль, 2 - Файл): ")

    if input_source == '1':
        data = input("Введите строку для хеширования: ").encode('utf-8')
    elif input_source == '2':
        filename = input("Введите имя файла: ")
        with open(filename, 'rb') as f:
            data = f.read()
    else:
        print("Неверный выбор источника данных.")
        return

    if choice == '1':
        hash_result = sha256(data)
    elif choice == '2':
        hash_result = sha512(data)
    else:
        print("Неверный выбор алгоритма.")
        return

    print("Хеш:", hash_result.hex())


if __name__ == "__main__":
    main()
