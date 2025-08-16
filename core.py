import hashlib
import hmac
import binascii

from Crypto.Cipher import AES


def decrypt_db_file_v3(path: str, pkey: str) -> bytes:
    IV_SIZE = 16
    HMAC_SHA1_SIZE = 20
    KEY_SIZE = 32
    ROUND_COUNT = 64000
    PAGE_SIZE = 4096
    SALT_SIZE = 16
    SQLITE_HEADER = b"SQLite format 3"

    with open(path, "rb") as f:
        buf = f.read()

    # 如果开头是 SQLite Header，说明不需要解密
    if buf.startswith(SQLITE_HEADER):
        return buf

    decrypted_buf = bytearray()

    # 读取 salt
    salt = buf[:SALT_SIZE]
    mac_salt = bytes([b ^ 0x3a for b in salt])

    # 生成 key
    pass_bytes = binascii.unhexlify(pkey)
    key = hashlib.pbkdf2_hmac("sha1", pass_bytes, salt, ROUND_COUNT, dklen=KEY_SIZE)

    # 生成 mac_key
    mac_key = hashlib.pbkdf2_hmac("sha1", key, mac_salt, 2, dklen=KEY_SIZE)

    # 写入 sqlite header + 0x00
    decrypted_buf.extend(SQLITE_HEADER)
    decrypted_buf.append(0x00)

    # 计算每页保留字节长度
    reserve = IV_SIZE + HMAC_SHA1_SIZE
    if reserve % AES.block_size != 0:
        reserve = ((reserve // AES.block_size) + 1) * AES.block_size

    total_page = len(buf) // PAGE_SIZE

    for cur_page in range(total_page):
        offset = SALT_SIZE if cur_page == 0 else 0
        start = cur_page * PAGE_SIZE
        end = start + PAGE_SIZE

        if all(b == 0 for b in buf[start:end]):
            decrypted_buf.extend(buf[start:end])
            break

        # HMAC-SHA1 校验
        mac = hmac.new(mac_key, digestmod=hashlib.sha1)
        mac.update(buf[start + offset:end - reserve + IV_SIZE])
        mac.update((cur_page + 1).to_bytes(4, byteorder="little"))
        hash_mac = mac.digest()

        hash_mac_start_offset = end - reserve + IV_SIZE
        hash_mac_end_offset = hash_mac_start_offset + len(hash_mac)
        if hash_mac != buf[hash_mac_start_offset:hash_mac_end_offset]:
            raise ValueError("Hash verification failed")

        # AES-256-CBC 解密
        iv = buf[end - reserve:end - reserve + IV_SIZE]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_page = cipher.decrypt(buf[start + offset:end - reserve])
        decrypted_buf.extend(decrypted_page)
        decrypted_buf.extend(buf[end - reserve:end])  # 保留 reserve 部分

    return bytes(decrypted_buf)


def decrypt_db_file_v4(path: str, pkey: str) -> bytes:
    IV_SIZE = 16
    HMAC_SHA256_SIZE = 64
    KEY_SIZE = 32
    AES_BLOCK_SIZE = 16
    ROUND_COUNT = 256000
    PAGE_SIZE = 4096
    SALT_SIZE = 16
    SQLITE_HEADER = b"SQLite format 3"

    with open(path, "rb") as f:
        buf = f.read()

    # 如果开头是 SQLITE_HEADER，说明不需要解密
    if buf.startswith(SQLITE_HEADER):
        return buf

    decrypted_buf = bytearray()
    salt = buf[:SALT_SIZE]
    mac_salt = bytes([b ^ 0x3a for b in salt])

    pass_bytes = bytes.fromhex(pkey)

    key = hashlib.pbkdf2_hmac("sha512", pass_bytes, salt, ROUND_COUNT, KEY_SIZE)
    mac_key = hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, KEY_SIZE)

    # 写入 SQLite 头
    decrypted_buf.extend(SQLITE_HEADER)
    decrypted_buf.append(0x00)

    reserve = IV_SIZE + HMAC_SHA256_SIZE
    if reserve % AES_BLOCK_SIZE != 0:
        reserve = ((reserve // AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE

    total_page = len(buf) // PAGE_SIZE

    for cur_page in range(total_page):
        offset = SALT_SIZE if cur_page == 0 else 0
        start = cur_page * PAGE_SIZE
        end = start + PAGE_SIZE

        # 计算 HMAC-SHA512
        mac_data = buf[start + offset:end - reserve + IV_SIZE]
        page_num_bytes = (cur_page + 1).to_bytes(4, byteorder='little')
        mac = hmac.new(mac_key, mac_data + page_num_bytes, hashlib.sha512).digest()

        hash_mac_start_offset = end - reserve + IV_SIZE
        hash_mac_end_offset = hash_mac_start_offset + len(mac)
        if mac != buf[hash_mac_start_offset:hash_mac_end_offset]:
            raise ValueError(f"Hash verification failed on page {cur_page + 1}")

        iv = buf[end - reserve:end - reserve + IV_SIZE]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_page = cipher.decrypt(buf[start + offset:end - reserve])

        decrypted_buf.extend(decrypted_page)
        decrypted_buf.extend(buf[end - reserve:end])

    return bytes(decrypted_buf)


def get_db_key(pkey: str, path: str, version: str) -> str:
    KEY_SIZE = 32
    ROUND_COUNT_V4 = 256000
    ROUND_COUNT_V3 = 64000
    SALT_SIZE = 16

    # 读取数据库文件的前 16 个字节作为 salt
    with open(path, "rb") as f:
        salt = f.read(SALT_SIZE)

    # 将十六进制的 pkey 解码为 bytes
    pass_bytes = binascii.unhexlify(pkey)

    # 根据版本选择哈希算法和迭代次数
    if version == "v3":
        key = hashlib.pbkdf2_hmac("sha1", pass_bytes, salt, ROUND_COUNT_V3, dklen=KEY_SIZE)
    elif version == "v4":
        key = hashlib.pbkdf2_hmac("sha512", pass_bytes, salt, ROUND_COUNT_V4, dklen=KEY_SIZE)
    else:
        raise ValueError(f"Not support version: {version}")

    # 拼接 key 和 salt
    rawkey = key + salt

    # 返回十六进制字符串，前面加 0x
    return "0x" + binascii.hexlify(rawkey).decode()


if __name__ == '__main__':
    key = "b2a1c68323c14ebbb18ce6be0b91b12ccef961d15e504e3eb1d1b58bf9b058f0"
    MSG1_DB = r"C:\Users\69012\Documents\WeChat Files\<wxid>\Msg\Multi\MSG1.db"
    data = decrypt_db_file_v3(MSG1_DB, key)
    with open("MSG1.db", "wb") as f:
        f.write(data)
