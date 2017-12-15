# -*- coding: utf8 -*-
# author：  咚咚呛
# 对系统主要文件夹进行监控，并把修改、创建的文件进行日志打印，
# 当修改或者创建高危文件时，进行日志打印，但并不覆写hash库，至到人工干预为止。
# 当修改或者创建非高危文件时，进行日志打印，并把当前文件hash覆盖原有文件。
# 排除prelink服务对二进制文件修改对结果进行干扰，每次排查都会排除prelink的操作

import os, sys, logging, time

# 文件完整性检测目录，并递归子目录
CHECK_DIR = ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/local/sbin/', '/usr/local/bin/']
# 重要高危告警文件名称
HEIGH_FILE_ALARM = ['login', 'ls', 'ps', 'ifconfig', 'du', 'find', 'netstat', 'bash']
# hash文件存储名称
HASH_DB = sys.path[0] + '/hash_db.txt'
# 日志告警文件存储位置
ALARM_LOG = '/var/log/filecheck.log'
# prelink服务会修改二进制文件，此处保存prelink服务的相关日志路径
PRELINK_LOG_PATH = ['/var/log/prelink/prelink.log', '/var/log/prelink.log']


# 计算一个文件的hash值
# 返回hash值字符串
def file_hash(file_path):
    import hashlib
    md5obj = hashlib.md5()
    size = 102400
    fp = open(file_path, 'rb')
    while True:
        content = fp.read(size)
        if not content:
            break
        md5obj.update(content)
    fp.close()
    return md5obj.hexdigest()


# 获取一个目录下的所有文件HASH值
# 返回内容hash_list_content，包含[[文件路径，hash值],[文件路径，hash值]]
def dir_hash(path):
    hash_list_content = []
    for root, dirs, files in os.walk(path, topdown=True):
        for filename in files:
            # 存在软链指向真实文件不存在现象
            if os.path.exists(os.path.join(root, filename)):
                hash_list = []
                hash_list.append(os.path.join(root, filename))  # 保存文件绝对路径
                hash_list.append(file_hash(os.path.join(root, filename)))  # 保存文件hash
                hash_list_content.append(hash_list)
    return hash_list_content


# 获取存储的hash值文件
# 返回内容history_hash_list_content，包含[[],[]]
def get_history_hash_list():
    if not os.path.exists(HASH_DB):
        write_hash_db("Initialization")
        return "", ""
    if os.path.getsize(HASH_DB) == 0:
        write_hash_db("Initialization")
        return "", ""
    # 获取hash文件内容到数据组中
    history_hash_list_content = []
    # 获取文件路绝对路径到数组中
    history_file_path_list = []
    for line in open(HASH_DB):
        if line != "" or line != None:
            tmp_hash = []
            tmp_hash.append(line.split('||')[0].split('\n')[0])  # 文件绝对路径
            tmp_hash.append(line.split('||')[1].split('\n')[0])  # 文件hash
            history_hash_list_content.append(tmp_hash)
            history_file_path_list.append(line.split('||')[0].split('\n')[0])
    return history_hash_list_content, history_file_path_list


# 写hash数据文件
# 传入参数为操作类型，
# Initialization为初始化hash文件，
# Coverage为非高危文件变动时，覆盖原hash文件
def write_hash_db(type):
    time_string = time.time()
    if type == "Initialization":
        if not os.path.exists(HASH_DB):
            os.mknod(HASH_DB)
        if os.path.getsize(HASH_DB) == 0:
            f = open(HASH_DB, 'w')
            for check_dir in CHECK_DIR:
                for hash_list in dir_hash(check_dir):
                    f.write(hash_list[0] + "||" + hash_list[1] + "||" + str(time_string) + "\n")
            f.close()
    if type == "Coverage":
        if os.path.exists(HASH_DB):
            os.remove(HASH_DB)
            os.mknod(HASH_DB)
        f = open(HASH_DB, 'w')
        for check_dir in CHECK_DIR:
            for hash_list in dir_hash(check_dir):
                f.write(hash_list[0] + "||" + hash_list[1] + "||" + str(time_string) + "\n")
        f.close()


# 检测操作类型，判断出现文件变动时，是修改还是创建
# True为修改
# Flase为创建
def check_operation_type(file_path, history_file_path_list):
    if file_path in history_file_path_list:
        return True
    else:
        return False


# 检测是否存在prelink服务
# 返回服务真假，和日志内容
def check_prelink_server():
    for path in PRELINK_LOG_PATH:
        if os.path.exists(path):
            file_object = open(path)
            try:
                all_the_text = file_object.read()
            finally:
                file_object.close()
            return True, all_the_text
    return False, ""


# 检测相对应目录的hash是否进行了变化
def check_dir_hash():
    # 判断是否出现文件变动
    HASH_FILE_TYPE = False
    # 判断是否出现了高危文件变动
    HIGH_OPERATION_ALARM = False
    # 最新hash文件列表
    current_hash_list_content = []

    # 初始化日志接口
    logger = loging()
    # 获取HASH库文件列表
    history_hash_list_content, history_file_path_list = get_history_hash_list()
    if len(history_hash_list_content) == 0 or len(history_file_path_list) == 0:
        return

    # 判断是否存在prelink服务，并返回内容
    PRELINK_SERVER, prelingk_log = check_prelink_server()

    # 开始针对监控目录进行检测
    for check_dir in CHECK_DIR:
        try:
            current_hash_list_content = dir_hash(check_dir)
            for hash_list in current_hash_list_content:
                # 判断是否存在hash记录
                if not hash_list in history_hash_list_content:
                    HASH_FILE_TYPE = True
                    # 判断是否是prelink服务更新
                    if PRELINK_SERVER:
                        if len(prelingk_log) > 0:
                            # 判断是否存在prelink此条日志
                            if prelingk_log.find(hash_list[0]) > 0:
                                continue
                    # 判断是否为高危，高危的话不执行覆盖操作
                    if hash_list[0].split('/')[-1].lower() in HEIGH_FILE_ALARM:
                        HIGH_OPERATION_ALARM = False
                        if check_operation_type(hash_list[0], history_file_path_list):
                            logger.info("文件:%s, 操作:Edit, 风险等级:High, MD5为：%s" % (hash_list[0], hash_list[1]))
                        else:
                            logger.info("文件:%s, 操作:Create, 风险等级:High, MD5为：%s" % (hash_list[0], hash_list[1]))
                    else:
                        if check_operation_type(hash_list[0], history_file_path_list):
                            logger.info("文件:%s, 操作:Edit, 风险等级:Medium, MD5为：%s" % (hash_list[0], hash_list[1]))
                        else:
                            logger.info("文件:%s, 操作:Create, 风险等级:Medium, MD5为：%s" % (hash_list[0], hash_list[1]))
        except:
            continue
    if HASH_FILE_TYPE and (not HIGH_OPERATION_ALARM):
        write_hash_db("Coverage")

    #打一条垃圾日志为了兼容syslog-ng最后一条日志会及时更新到splunk
    if HASH_FILE_TYPE:
        logger.info("文件:无, 操作:无, 风险等级:Info, MD5为:无")



# 日志输出到指定文件，用于syslog打印
def loging():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('FileCheck')
    fh = logging.FileHandler(ALARM_LOG)
    fh.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    return logger


if __name__ == '__main__':
    if sys.version_info < (2, 5):
        print "python version low"
        sys.exit()
    check_dir_hash()
