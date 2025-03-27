#!/usr/bin/python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def aes_encrypt(plain_text, key):
    """
    AES加密函数
    :param plain_text: 明文，需要是bytes类型
    :param key: 密钥，需要是16(AES-128), 24(AES-192), 或 32(AES-256) bytes长
    :return: 加密后的密文，base64编码的字符串
    """
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(pad(plain_text, AES.block_size))
    # 将nonce, ciphertext, tag打包并base64编码
    ct_bytes = nonce + ciphertext + tag
    return base64.b64encode(ct_bytes).decode('utf-8')

def aes_decrypt(cipher_text, key):
    """
    AES解密函数
    :param cipher_text: 密文，base64编码的字符串
    :param key: 密钥，需要是16(AES-128), 24(AES-192), 或 32(AES-256) bytes长
    :return: 解密后的明文，bytes类型
    """
    # base64解码
    ct_bytes = base64.b64decode(cipher_text.encode('utf-8'))
    nonce = ct_bytes[:AES.block_size]
    ciphertext = ct_bytes[AES.block_size:-AES.block_size]
    tag = ct_bytes[-AES.block_size:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    plain_text = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
    return plain_text.decode('utf-8')

def main():
    key = b'k9yh8j6tf9hr4h7d'  # 生成一个随机的16字节AES密钥
    print("加密工具 v1.0")
    while True:
        print("[1] 加密\n[2] 解密\n[3] 退出")
        user_input = input("请输入对应序号：")
        if user_input == '1':
            text = input("请输入需要加密的文本：")
            ciphertext = aes_encrypt(text.encode(), key)
            print(f"已加密:\n{ciphertext}")
        elif user_input == '2':
            try:
                text = input("请输入密文：")
                plaintext = aes_decrypt(text, key)
                print(f"解密结果:\n{plaintext}", )
            except Exception as e:
                print(f"解密出错：{e}")
        elif user_input == '3':
            break
        else:
            print("输入序号正确，请重新输入")

if __name__ == '__main__':

    main()

