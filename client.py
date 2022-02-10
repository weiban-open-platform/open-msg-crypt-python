import random
from datetime import datetime
import requests
import json
from urllib.parse import quote

from WBMsgCrypt import WBMsgCrypt


def http_get():
    """
    Http Get请求验证URL有效性
    """
    crypt = WBMsgCrypt(sToken="hJqcu3uJ9Tn2gXPmxx2w9kkCkCE2EPYo",
                          sEncodingAESKey="6qkdMrq68nTKduznJYO1A37W2oEgpkMUvkttRToqhUt", sReceiveId="1654076894948099073")

    msg = str(int(random.random() * 1000000000))
    timestamp = str(int(datetime.now().timestamp()))
    nonce = str(int(random.random() * 1000000000))

    # 1.加密与签名
    ret, sEncryptMsg = crypt.EncryptMsg(msg, timestamp, nonce)
    if ret != 0 or not sEncryptMsg:
        return "error"
    # 2.url中的encrypt进行编码
    encrypt = json.loads(sEncryptMsg).get("encrypt")
    signature = json.loads(sEncryptMsg).get("msgsignature")
    encrypt = quote(encrypt)

    url = f"http://127.0.0.1:4001/receive_weiban_message?msg_signature={signature}&timestamp={timestamp}&nonce={nonce}&echostr={encrypt}"
    resp = requests.get(url)
    print(resp, resp.content)


def http_post():
    """
    Http Post请求接收业务数据
    """
    crypt = WBMsgCrypt(sToken="hJqcu3uJ9Tn2gXPmxx2w9kkCkCE2EPYo",
                          sEncodingAESKey="6qkdMrq68nTKduznJYO1A37W2oEgpkMUvkttRToqhUt", sReceiveId="1654076894948099073")

    data = {
        "id": "81fcf78e-ae1a-4c6a-9e14-f11883e6359e",
        "corp_id": "1704174310933890049",
        "create_time": 1409659813.111,
        "type": "event",
        "event": "meeting_change",
        "status": "create",
        "retry_count": 0,
        "seq": 1,
        "msg_data": {
            "meeting": {
                "id": 1,
                "from_ai": False,
                "staff_id": "wuyajun",
                "members": {
                    "staff_list": ['wuyajun', 'zhangsan'],
                    "external_user_list": ['xxxxxx']
                },
                "title": "会议标题",
                "start_time": 1145141919,
                "end_time": 1145141981,
                "reminder_on": True,
                "remind_minutes_before_start": 5,
                "address": "会议地点"
            }
        }
    }
    data = json.dumps(data)
    timestamp = str(int(datetime.now().timestamp()))
    nonce = str(int(random.random() * 1000000000))

    # 加密与签名
    ret, sEncryptMsg = crypt.EncryptMsg(data, timestamp, nonce)
    if ret != 0 or not sEncryptMsg:
        print(False)
        return
    sEncryptMsg = json.loads(sEncryptMsg)
    signature = sEncryptMsg.get("msgsignature")
    url = f"http://127.0.0.1:4001/receive_weiban_message?msg_signature={signature}&timestamp={timestamp}&nonce={nonce}"
    headers = {
        "Content-Type": "application/json; charset=UTF-8"
    }
    data = {
        "corp_id": "111111111",
        "app_id": "app-114514",
        "encrypt": sEncryptMsg.get("encrypt")
    }
    resp = requests.post(url, data=json.dumps(data), headers=headers)
    # 解密resp
    print(resp, resp.content)


http_get()
http_post()
