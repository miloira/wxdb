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

wx_db = get_wx_db()
conn = wx_db.connect(r"Msg\Multi\MSG0.db")
with conn:
    print(conn.execute("SELECT * FROM sqlite_master;").fetchall())
# 输出
# [('table', 'MSG', 'MSG', 2, 'CREATE TABLE MSG (localId INTEGER PRIMARY KEY AUTOINCREMENT,TalkerId INT DEFAULT 0,MsgSvrID INT,Type INT,SubType INT,IsSender INT,CreateTime INT,Sequence INT DEFAULT 0,StatusEx INT DEFAULT 0,FlagEx INT,Status INT,MsgServerSeq INT,MsgSequence INT,StrTalker TEXT,StrContent TEXT,DisplayContent TEXT,Reserved0 INT DEFAULT 0,Reserved1 INT DEFAULT 0,Reserved2 INT DEFAULT 0,Reserved3 INT DEFAULT 0,Reserved4 TEXT,Reserved5 TEXT,Reserved6 TEXT,CompressContent BLOB,BytesExtra BLOB,BytesTrans BLOB)'), ('table', 'sqlite_sequence', 'sqlite_sequence', 3, 'CREATE TABLE sqlite_sequence(name,seq)'), ('table', 'MSGTrans', 'MSGTrans', 4, 'CREATE TABLE MSGTrans(msgLocalId INTEGER PRIMARY KEY, talkerId INT)'), ('index', 'talkerIDIdx', 'MSGTrans', 5, 'CREATE INDEX talkerIDIdx ON MSGTrans(talkerId)'), ('index', 'MsgTalkerIdSeqIndex', 'MSG', 6, 'CREATE INDEX MsgTalkerIdSeqIndex ON MSG(talkerId,sequence DESC)'), ('index', 'MsgTalkerIdTypeSeqIndex', 'MSG', 7, 'CREATE INDEX MsgTalkerIdTypeSeqIndex ON MSG(talkerId,type,sequence DESC)'), ('index', 'SvrIdIndex', 'MSG', 8, 'CREATE INDEX SvrIdIndex ON MSG(MsgSvrID)'), ('table', 'Name2ID', 'Name2ID', 9, 'CREATE TABLE Name2ID(UsrName TEXT PRIMARY KEY)'), ('index', 'sqlite_autoindex_Name2ID_1', 'Name2ID', 10, None), ('table', 'DBInfo', 'DBInfo', 11, 'CREATE TABLE DBInfo (\t\t\t\t\t\t\ttableIndex INTEGER PRIMARY KEY,\t\t\t\t\t\t\ttableVersion INTERGER,\t\t\t\t\t\t\ttableDesc TEXT)'), ('index', 'versionIdx', 'DBInfo', 12, 'CREATE INDEX versionIdx ON DBInfo(tableIndex)')]
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