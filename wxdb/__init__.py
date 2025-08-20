import binascii
import os
import re
import subprocess
import hashlib
import hmac

from Crypto.Cipher import AES
from typing import Dict

from sqlcipher3 import dbapi2 as sqlite

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
wechat_dump_rs = os.path.join(BASE_DIR, "wechat-dump-rs.exe")


def get_wx_info(version: str = "v3") -> Dict:
    if version == "v3":
        result = subprocess.run([wechat_dump_rs, "--vv", "3"], capture_output=True)
    elif version == "v4":
        result = subprocess.run([wechat_dump_rs, "--vv", "4"], capture_output=True)
    else:
        raise ValueError(f"Not support version: {version}")

    stdout = result.stdout.decode()
    if not stdout:
        raise Exception("Please login wechat.")
    else:
        stderr = result.stderr.decode()
        if "panicked" in stderr:
            raise Exception(stderr)

        pid = int(re.findall("ProcessId: (.*?)\n", stdout)[0])
        version = re.findall("WechatVersion: (.*?)\n", stdout)[0]
        account = re.findall("AccountName: (.*?)\n", stdout)[0]
        data_dir = re.findall("DataDir: (.*?)\n", stdout)[0]
        key = re.findall("key: (.*?)\n", stdout)[0]
        return {
            "pid": pid,
            "version": version,
            "account": account,
            "data_dir": data_dir,
            "key": key
        }


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
        page_num_bytes = (cur_page + 1).to_bytes(4, byteorder="little")
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
    if version.startswith("3"):
        key = hashlib.pbkdf2_hmac("sha1", pass_bytes, salt, ROUND_COUNT_V3, dklen=KEY_SIZE)
    elif version.startswith("4"):
        key = hashlib.pbkdf2_hmac("sha512", pass_bytes, salt, ROUND_COUNT_V4, dklen=KEY_SIZE)
    else:
        raise ValueError(f"Not support version: {version}")

    return binascii.hexlify(key + salt).decode()


class WXDB:
    def __init__(self, pid, account, key, data_dir, version):
        self.pid = pid
        self.account = account
        self.key = key
        self.data_dir = data_dir[:-1]
        self.version = version
        if not self.version.startswith("3") and not self.version.startswith("4"):
            raise ValueError(f"Not support version: {self.version}")

    def get_db_path(self, db_name):
        return os.path.join(self.data_dir, db_name)

    def get_current_msg_db_name(self):
        with open(os.path.join(self.data_dir, r"Msg\Multi\config.ini"), "r", encoding="utf-8") as f:
            return f.read()

    def create_connection(self, db_name):
        conn = sqlite.connect(self.get_db_path(db_name))
        db_key = get_db_key(self.key, self.get_db_path(db_name), self.version)
        conn.execute(f"PRAGMA key = \"x'{db_key}'\";")
        conn.execute(f"PRAGMA cipher_page_size = 4096;")
        if self.version.startswith("3"):
            conn.execute(f"PRAGMA kdf_iter = 64000;")
            conn.execute(f"PRAGMA cipher_hmac_algorithm = HMAC_SHA1;")
            conn.execute(f"PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1;")
        elif self.version.startswith("4"):
            conn.execute(f"PRAGMA kdf_iter = 256000;")
            conn.execute(f"PRAGMA cipher_hmac_algorithm = HMAC_SHA256;")
            conn.execute(f"PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA256;")
        return conn

    def __repr__(self):
        return f"WXDB(pid={repr(self.pid)}, account={repr(self.account)}, key={repr(self.key)}, data_dir={repr(self.data_dir)}, version={repr(self.version)})"

    __str__ = __repr__


def get_wx_db(version="v3"):
    wx_info = get_wx_info(version)
    return WXDB(**wx_info)


if __name__ == '__main__':
    wx_db = get_wx_db()
    print(wx_db)
    msg_db_name = wx_db.get_current_msg_db_name()
    conn = wx_db.create_connection(rf"Msg\Multi\{msg_db_name}")
    with conn:
        print(conn.execute("SELECT * FROM sqlite_master;").fetchall())
