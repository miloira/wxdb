# wxdb

## 项目介绍

wxdb是一个微信数据库管理工具，可以查询微信数据库数据，解密微信数据库文件。

## 安装

```bash
pip install wxdb
```

## 代码示例

### 查询微信数据库

```python
from wxdb import get_wx_db

try:
    wx_db = get_wx_db("v3")
    msg_db_name = wx_db.get_current_msg_db_name()
    conn = wx_db.create_connection(rf"Msg\Multi\{msg_db_name}")
    with conn:
        print(conn.execute("SELECT * FROM sqlite_master;").fetchall())
except Exception as e:
    wx_db = get_wx_db("v4")
    msg_db_name = wx_db.get_current_msg_db_name()
    conn = wx_db.create_connection(rf"db_storage\message\{msg_db_name}")
    with conn:
        print(conn.execute("SELECT * FROM sqlite_master;").fetchall())
```

### 解密微信数据库文件

```python
import os

from wxdb import decrypt_db_file_v3, decrypt_db_file_v4, get_wx_info

decrypt_db_file = decrypt_db_file_v3

wx_info = get_wx_info()

with open("MSG0.db", "wb") as f:
    data = decrypt_db_file(
        path=os.path.join(wx_info["data_dir"], r"Msg\Multi\MSG0.db"),
        pkey=wx_info["key"]
    )
    f.write(data)
```
