import json
from urllib.parse import unquote

from flask import Flask, request, jsonify

from WBMsgCrypt import WBMsgCrypt
import ierror

app = Flask(__name__)

crypt = WBMsgCrypt(sToken="hJqcu3uJ9Tn2gXPmxx2w9kkCkCE2EPYo",
                          sEncodingAESKey="6qkdMrq68nTKduznJYO1A37W2oEgpkMUvkttRToqhUt", sReceiveId="1654076894948099073")


@app.route("/")
def hello():
    return "hello"


@app.route("/receive_weiban_message", methods=["GET"])
def receive_weiban_message_get():
    """
    支持Http Get请求验证URL有效性
    """
    msg_signature = request.args.get("msg_signature")
    timestamp = request.args.get("timestamp")
    nonce = request.args.get("nonce")
    echostr = request.args.get("echostr")
    if not (echostr and msg_signature and nonce and timestamp):
        return "error"
    # 1.对url中的echostr进行decode
    echostr = unquote(echostr)

    # 2.验证签名msg_signature、解密echostr得到reply_echostr明文消息内容
    errcode, reply_echostr = crypt.VerifyURL(
        msg_signature, timestamp, nonce, echostr)

    if errcode != ierror.WBMsgCrypt_OK or not reply_echostr:
        return "error"
    # 3.响应GET请求，响应内容为上一步得到的明文消息内容
    return reply_echostr


@app.route("/receive_weiban_message", methods=["POST"])
def receive_weiban_message_post():
    """
    支持Http Post请求接收业务数据
    """
    msg_signature = request.args.get("msg_signature")
    timestamp = request.args.get("timestamp")
    nonce = request.args.get("nonce")
    try:
        data = request.get_data()
    except:
        return "error, json格式错误"
    if not (data and msg_signature and nonce and timestamp):
        return "error, 请求参数错误"

    # 1.对msg_signature进行校验; 解密Encrypt，得到明文的消息结构体
    errcode, msg_dict = crypt.DecryptMsg(data.decode('utf-8'), msg_signature, timestamp, nonce)
    if errcode != ierror.WBMsgCrypt_OK or not msg_dict:
        if errcode == ierror.WBMsgCrypt_ValidateSignature_Error:
            return "error, 签名计算错误"
    msg_dict = json.loads(msg_dict.decode())
    print(msg_dict)

    # 2.正确响应本次请求
    return jsonify(errcode=0)


if __name__ == "__main__":
    app.run(port=4001)
