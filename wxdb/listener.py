import time
from typing import Callable, Dict, List, Any, Optional, Tuple, Union

import blackboxprotobuf
import xmltodict
import lz4.block

from pyee.executor import ExecutorEventEmitter

from wxdb import get_wx_db, events
from wxdb.logger import logger


def parse_xml(xml: str) -> Dict[str, Any]:
    return xmltodict.parse(xml)


def deserialize_bytes_extra(bytes_extra: Optional[bytes]) -> Dict[str, Any]:
    bytes_extra_message_type = {
        "1": {
            "type": "message",
            "message_typedef": {
                "1": {
                    "type": "int",
                    "name": ""
                },
                "2": {
                    "type": "int",
                    "name": ""
                }
            },
            "name": "1"
        },
        "3": {
            "type": "message",
            "message_typedef": {
                "1": {
                    "type": "int",
                    "name": ""
                },
                "2": {
                    "type": "str",
                    "name": ""
                }
            },
            "name": "3",
            "alt_typedefs": {
                "1": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {},
                        "name": ""
                    }
                },
                "2": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "13": {
                                "type": "fixed32",
                                "name": ""
                            },
                            "12": {
                                "type": "fixed32",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "3": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "15": {
                                "type": "fixed64",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "4": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "15": {
                                "type": "int",
                                "name": ""
                            },
                            "14": {
                                "type": "fixed32",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "5": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "12": {
                                "type": "fixed32",
                                "name": ""
                            },
                            "7": {
                                "type": "fixed64",
                                "name": ""
                            },
                            "6": {
                                "type": "fixed64",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "6": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "7": {
                                "type": "fixed64",
                                "name": ""
                            },
                            "6": {
                                "type": "fixed32",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "7": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "12": {
                                "type": "fixed64",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "8": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "6": {
                                "type": "fixed64",
                                "name": ""
                            },
                            "12": {
                                "type": "fixed32",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "9": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "15": {
                                "type": "int",
                                "name": ""
                            },
                            "12": {
                                "type": "fixed64",
                                "name": ""
                            },
                            "6": {
                                "type": "int",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
                "10": {
                    "1": {
                        "type": "int",
                        "name": ""
                    },
                    "2": {
                        "type": "message",
                        "message_typedef": {
                            "6": {
                                "type": "fixed32",
                                "name": ""
                            },
                            "12": {
                                "type": "fixed64",
                                "name": ""
                            }
                        },
                        "name": ""
                    }
                },
            }
        }
    }
    if bytes_extra is None or not isinstance(bytes_extra, bytes):
        raise TypeError("BytesExtra must be bytes")

    deserialize_data, message_type = blackboxprotobuf.decode_message(bytes_extra, bytes_extra_message_type)
    return deserialize_data


def decompress_compress_content(data: Optional[bytes]) -> str:
    if data is None or not isinstance(data, bytes):
        raise TypeError("Data must be bytes")
    try:
        dst = lz4.block.decompress(data, uncompressed_size=len(data) << 8)
        dst = dst.replace(b"\x00", b"")
        uncompressed_data = dst.decode("utf-8", errors="ignore")
        return uncompressed_data
    except Exception:
        return data.decode("utf-8", errors="ignore")


def get_room_member_wxid(bytes_extra: Dict[str, Any]) -> str:
    try:
        return bytes_extra["3"][0]["2"]
    except Exception:
        return ""


def get_message(row: Tuple[Any, ...]) -> Dict[str, Any]:
    return {
        "local_id": row[0],
        "talker_id": row[1],
        "msg_svr_id": row[2],
        "type": row[3],
        "sub_type": row[4],
        "is_sender": row[5],
        "create_time": row[6],
        "sequence": row[7],
        "status_ex": row[8],
        "flag_ex": row[9],
        "status": row[10],
        "msg_server_seq": row[11],
        "msg_sequence": row[12],
        "str_talker": row[13],
        "str_content": row[14],
        "display_content": row[15],
        "reserved_0": row[16],
        "reserved_1": row[17],
        "reserved_2": row[18],
        "reserved_3": row[19],
        "reserved_4": row[20],
        "reserved_5": row[21],
        "reserved_6": row[22],
        "compress_content": row[23],
        "bytes_extra": row[24],
        "bytes_trans": row[25]
    }


class WeChatDBListener:

    def __init__(self, pid: Optional[int] = None) -> None:
        self.wx_db = get_wx_db("v3", pid)
        self.pid = self.wx_db.pid
        self.msg_db_name = self.wx_db.get_current_msg_db_name()
        self.conn = self.wx_db.create_connection(rf"Msg\Multi\{self.msg_db_name}")
        self.self_wxid = self.wx_db.data_dir.split("\\")[-1]
        self.event_emitter = ExecutorEventEmitter()

    def get_event(self, row: Optional[Tuple[Any, ...]]) -> Optional[Dict[str, Any]]:
        if not row:
            return row

        message = get_message(row)
        data = {
            "id": message["local_id"],
            "msg_id": message["msg_svr_id"],
            "sequence": message["sequence"],
            "type": message["type"],
            "sub_type": message["sub_type"],
            "is_sender": message["is_sender"],
            "create_time": message["create_time"],
            "msg": message["str_content"],
            "raw_msg": None,
            "at_user_list": [],
            "room_wxid": None,
            "from_wxid": None,
            "to_wxid": None,
            "extra": None
        }

        bytes_extra = deserialize_bytes_extra(message["bytes_extra"])
        data["extra"] = bytes_extra

        if message["compress_content"] is not None:
            data["raw_msg"] = decompress_compress_content(message["compress_content"])

        if message["is_sender"] == 1:
            data["from_wxid"] = self.self_wxid
        else:
            data["from_wxid"] = message["str_talker"]

        if message["str_talker"].endswith("@chatroom"):
            data["room_wxid"] = message["str_talker"]
        else:
            if data["is_sender"] == 1:
                data["to_wxid"] = message["str_talker"]
            else:
                data["to_wxid"] = self.self_wxid

        if data.get("room_wxid"):
            if isinstance(bytes_extra, dict) and data["is_sender"] == 0:
                data["from_wxid"] = get_room_member_wxid(bytes_extra)
            try:
                if isinstance(bytes_extra, dict):
                    idx = 0 if message["is_sender"] == 1 else 1
                    xml_data = parse_xml(bytes_extra["3"][idx]["2"])
                    data["at_user_list"] = [
                        x for x in xml_data["msgsource"].get("atuserlist", "").split(",") if x
                    ]
            except Exception:
                pass

        return data

    def get_recently_messages(self, count: int = 10, order: str = "DESC") -> List[Optional[Dict[str, Any]]]:
        with self.conn:
            rows = self.conn.execute("SELECT * FROM MSG ORDER BY localId {} LIMIT ?;".format(order),
                                     (count,)).fetchall()
            return [self.get_event(row) for row in rows]

    def get_latest_revoke_message(self) -> Optional[Dict[str, Any]]:
        with self.conn:
            row = self.conn.execute(
                "SELECT * FROM MSG WHERE Type = 10000 AND SubType = 0 ORDER BY localId DESC LIMIT 1;").fetchone()
            return self.get_event(row)

    def handle(self, events: Union[tuple, list] = (0, 0), once: bool = False) -> Callable[[Callable[..., Any]], None]:
        def wrapper(func: Callable[..., Any]) -> None:
            listen = self.event_emitter.on if not once else self.event_emitter.once
            if isinstance(events, tuple):
                type, sub_type = events
                listen(f"{type}:{sub_type}", func)
            elif isinstance(events, list):
                for event in events:
                    type, sub_type = event
                    listen(f"{type}:{sub_type}", func)
            else:
                raise TypeError("events must be tuple or list.")

        return wrapper

    def run(self, period: float = 0.1) -> None:
        recently_messages = self.get_recently_messages(1)
        current_local_id = recently_messages[0]["id"] if recently_messages and recently_messages[0] else 0
        revoke_message = self.get_latest_revoke_message()
        current_revoke_local_id = revoke_message["id"] if revoke_message else 0
        logger.info(self.wx_db)
        logger.info("Start listening...")
        while True:

            with self.conn:
                rows = self.conn.execute("SELECT * FROM MSG where localId > ? ORDER BY localId;",
                                         (current_local_id,)).fetchall()
                for row in rows:
                    event = self.get_event(row)
                    logger.debug(event)
                    if event:
                        current_local_id = event["id"]
                        self.event_emitter.emit(f"0:0", self, event)
                        self.event_emitter.emit(f"{event['type']}:{event['sub_type']}", self, event)

            with self.conn:
                rows = self.conn.execute(
                    "SELECT * FROM MSG WHERE localId > ? AND Type = 10000 AND SubType = 0 ORDER BY localId LIMIT 1;",
                    (current_revoke_local_id,)).fetchall()
                for row in rows:
                    event = self.get_event(row)
                    logger.debug(event)
                    if event:
                        current_revoke_local_id = event["id"]
                        self.event_emitter.emit(f"0:0", self, event)
                        self.event_emitter.emit(f"{event['type']}:{event['sub_type']}", self, event)

            time.sleep(period)

    def __str__(self) -> str:
        return f"<WeChatDB pid={repr(self.pid)} wxid={repr(self.self_wxid)} msg_db={repr(self.msg_db_name)}>"


if __name__ == "__main__":
    wechat_db_listener = WeChatDBListener()


    @wechat_db_listener.handle(events.TEXT_MESSAGE)
    def on_message(wechat_db_listener: WeChatDBListener, event: Dict[str, Any]) -> None:
        print(wechat_db_listener, event)


    wechat_db_listener.run()
