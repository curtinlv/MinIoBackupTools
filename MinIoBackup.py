#!/usr/bin/python3
# -*- coding: utf-8 -*-
'''
minio备份工具
Date : 2024-05-27
Auther :Curtin

'''
import os, sys
from io import BytesIO
import zipfile
from datetime import datetime, timedelta
from minio import Minio
import time
from configparser import RawConfigParser
import glob
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

print(f"minio备份工具，版本v20240530_1.0")
key = b'k9yh8j6tf9hr4h7d'  # 生成一个随机的16字节AES密钥

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

def exitCodeFun(code):
    try:
        if sys.platform == 'win32' or sys.platform == 'cygwin':
            print("连按回车键即可退出窗口！", flush=True)
            exitCode = input()
        sys.exit(code)
    except:
        time.sleep(3)
        sys.exit(code)

def prints(message):
    # 获取当前时间
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # 打印带有时间戳的消息
    print(f"{now}: {message}", flush=True)

def read_config():

    ### 获取用户参数
    minio_config= {}
    backup_config= {}
    try:
        configinfo = RawConfigParser()
        try:
            configinfo.read("minio_backup_config.ini", encoding="UTF-8")
        except Exception as e:
            with open("minio_backup_config.ini", "r", encoding="UTF-8") as config:
                getConfig = config.read().encode('utf-8').decode('utf-8-sig')
            with open("minio_backup_config.ini", "w", encoding="UTF-8") as config:
                config.write(getConfig)
            try:
                configinfo.read("minio_backup_config.ini", encoding="UTF-8")
            except:
                configinfo.read("minio_backup_config.ini", encoding="gbk")
        config = configinfo
        minio_config = {
            'endpoint': config.get('minio', 'endpoint'),
            'access_key': config.get('minio', 'access_key'),
            'secret_key': aes_decrypt(config.get('minio', 'secret_key'), key),
            'secure': config.getboolean('minio', 'secure')
        }
        backup_config = {
            'buckets': config.get('backup', 'buckets').split(',') if config.get('backup', 'buckets') else None,
            'backup_dir': config.get('backup', 'backup_dir'),
            'restore_bucket': config.get('backup', 'restore_bucket'),
            'restore_backup_zip': config.get('backup', 'restore_backup_zip'),
            'backup_enable': config.getboolean('backup', 'backup_enable'),
            'restore_enable': config.getboolean('backup', 'restore_enable'),
            'delete_enable': config.getboolean('backup', 'delete_enable'),
            'logs_enable': config.getboolean('backup', 'logs_enable'),
            'days_before': config.getint('backup', 'days_before')
        }
    except Exception as e:
        prints(f"参数配置有误，minio_backup_config.ini\nError:{e}")


    return minio_config, backup_config


def backup_bucket_to_zip(client, bucket_name, backup_dir, backup_date):
    zip_filename = f"{bucket_name}_{backup_date}.zip"
    zip_path = os.path.join(backup_dir, zip_filename)

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for obj in client.list_objects(bucket_name, recursive=True):
            # 下载对象到内存中，然后添加到ZIP文件
            with client.get_object(bucket_name, obj.object_name) as data:
                zipf.writestr(obj.object_name, data.read())
                if backup_config['logs_enable']:
                    prints(f"【成功】备份 {bucket_name}/{obj.object_name} 到 ZIP 文件")

    return zip_path


def restore_minio(minio_config, restore_config):
    client = Minio(
        minio_config['endpoint'],
        access_key=minio_config['access_key'],
        secret_key=minio_config['secret_key'],
        secure=minio_config.get('secure', False)
    )

    backup_file = restore_config['restore_backup_zip']
    bucket_name = restore_config['restore_bucket']

    try:
        if not client.bucket_exists(bucket_name):
            client.make_bucket(bucket_name)

        with zipfile.ZipFile(backup_file, 'r') as zipf:
            for file_name in zipf.namelist():
                # obj_name = os.path.basename(file_name)
                # dst = f"{obj_name}"
                with zipf.open(file_name) as f:
                    data = f.read()  # 读取zip文件中的数据到bytes对象
                    data_stream = BytesIO(data)  # 创建一个BytesIO对象来包装bytes数据
                    length = data_stream.getbuffer().nbytes  # 获取BytesIO对象中的数据长度
                # 注意：大多数SDKs不需要手动设置length，因为BytesIO对象知道它的长度
                    client.put_object(bucket_name, file_name, data_stream, length)
                if backup_config['logs_enable']:
                    prints(f"【成功】还原 {file_name} to 【{bucket_name}】:{file_name}")

        prints(f"【成功】还原bucket:{bucket_name}")
    except Exception as e:
        prints(f"【失败】还原过程中出现错误：{e}")



def backup_minio(minio_config, backup_config):
    client = Minio(
        minio_config['endpoint'],
        access_key=minio_config['access_key'],
        secret_key=minio_config['secret_key'],
        secure=minio_config['secure']
    )

    backup_dir = backup_config['backup_dir']
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)

    backup_date = datetime.now().strftime('%Y-%m-%d')  # 修改日期格式为YYYY-MM-DD

    # 处理指定的buckets列表
    if backup_config['buckets']:
        for bucket in backup_config['buckets']:
            if bucket in client.list_buckets():
                zip_path = backup_bucket_to_zip(client, bucket, backup_dir, backup_date)
                prints(f"Bucket 【{bucket}】 已备份到 {zip_path}")
            else:
                prints(f"Bucket 【{bucket}】 不存在，请重新配置")
    else:
        for bucket in client.list_buckets():
            bucket_name = bucket.name
            zip_path = backup_bucket_to_zip(client, bucket_name, backup_dir, backup_date)
            prints(f"Bucket {bucket_name} 已备份到 {zip_path}")

# 删除过期文件
def delete_old_files(directory, days_before, extension):
    # 获取当前日期
    now = datetime.now()
    # 计算要清理的日期
    before_dt = now - timedelta(days=days_before)

    # 拼接目录和文件模式
    pattern = os.path.join(directory, f'**/*.{extension}')

    # 遍历目录下的所有文件（递归）
    for filename in glob.iglob(pattern, recursive=True):
        # 获取文件的修改时间
        file_mtime = datetime.fromtimestamp(os.path.getmtime(filename))

        # 如果文件的修改时间早于指定的日期
        if file_mtime < before_dt:
            # 删除文件
            try:
                os.remove(filename)
                prints(f"Deleted file: {filename}")
            except OSError as e:
                prints(f"Error: {e.strerror} : {filename}")

if __name__ == "__main__":
    minio_config, backup_config = read_config()
    # print(minio_config, flush=True)
    # print(backup_config, flush=True)
    # 调用备份函数
    try:
        if backup_config["backup_enable"]:
            # 记录开始时间
            start_time = time.time()
            prints(f"备份模式--已启用-buckets:{backup_config['buckets'] if backup_config['buckets'] else '[全部bucket]'}，开始备份...")
            backup_minio(minio_config, backup_config)
            # 记录结束时间
            end_time = time.time()
            # 计算并打印总耗时
            total_time = end_time - start_time
            prints(f"备份总耗时: {total_time:.2f} seconds")
        else:
            prints("备份模式--未启用")

        # 示例用法：还原bucket
        if backup_config["restore_enable"]:
            # 记录开始时间
            start_time = time.time()
            prints(f"还原模式-已启用-【{backup_config['restore_bucket']}】，开始还原...")
            restore_minio(minio_config, backup_config)
            # 记录结束时间
            end_time = time.time()

            # 计算并打印总耗时
            total_time = end_time - start_time
            prints(f"还原总耗时: {total_time:.2f} seconds")

        else:
            prints("还原模式--未启用")

        # 删除旧的备份文件，使用示例
        if backup_config["delete_enable"]:
            prints(f"清理旧备份文件--已启用：清理{backup_config['days_before']}天前文件")
            extension = "zip"                      # 指定后缀
            delete_old_files(backup_config['backup_dir'], backup_config['days_before'], extension)
        else:
            prints("清理旧备份文件--未启用")
    except Exception as e:
        prints(f"出错：{e}")
    finally:
        exitCodeFun(0)
