"""
作者：周雪松
邮箱：hjdxm@outlook.com
定稿日期：2025/1/10 15:33

模块：日志模块，需要传递一个配置文件，根据配置文件调整日志输出方式。日志分为两个级别：[系统日志 | 用户日志]
用户日志：用户的日志应当在各自的日志文件中进行查看，在终端上仅显示提示信息，某某用户在什么时候发生了什么日志级别的记录。
"""


import toml
import logging
import logging.handlers
import os
from copy import deepcopy
from functools import wraps
from typing import Union


class Zxs_log():

    class LogFilter(logging.Filter):
        def __init__(self, filters: list):
            '''
            filters: 那些 level 的信息允许通过，错误 levelname，将没有警告报错
            '''
            self.filters = [getattr(logging, x.upper(), -1) for x in filters]

        def filter(self, record):
            return (record.levelno in self.filters)

    class Notice_formatter(logging.Formatter):
        def format(self, record):
            return f"[{record.asctime}] {record.name} 发生了一条 {record.levelname} 日志！请进入相应日志查看明细。"

    def __init__(self, config: Union[str, dict] = "log_zxs.toml"):
        if isinstance(config, dict):
            self.config = config
        else:
            self.read_config(config)
        self.logs = dict()

    def read_config(self, config: str):
        '''
        str: 只接受文件路径
        '''
        with open(config, "r", encoding="utf-8") as f:
            self.config = toml.load(f)

    def setup_formatter(self, *args, **kwargs):
        return logging.Formatter(*args, **kwargs)

    def addFilters_setLevel_Formatter(func):
        @wraps(func)
        def wrapper_addFilters_setLevel_Formatter(self, level_filters: list[str] = None, level: str = None, formatter: str = None, notice_formatter=False, *args, **kwargs):
            '''
            level_filters: 那些 level 的信息允许通过，错误 levelname，将没有警告报错
            level: setLevel 的值
            formatter: formatter 配置的 key
            '''
            result = func(self, *args, **kwargs)
            if level_filters:
                result.addFilter(self.LogFilter(level_filters))
            if level:
                result.setLevel(level)
            if formatter:
                result.setFormatter(self.setup_formatter(**self.config[formatter]))
            if notice_formatter:
                result.setFormatter(self.Notice_formatter())
            return result
        return wrapper_addFilters_setLevel_Formatter

    @addFilters_setLevel_Formatter
    def setup_handler(self, handlerType: str = "", *args, **kwargs):
        '''
        handlerType: logging 中的 handler 类型
        '''
        if not ((handlerClass := getattr(logging, handlerType, False)) or (handlerClass := getattr(logging.handlers, handlerType, False))):
            raise ValueError(f"There is No such {handlerType} handler in logging!")

        if (filename := kwargs.get("filename", None)):
            os.makedirs(os.path.dirname(filename), exist_ok=True)
        handler = handlerClass(*args, **kwargs)
        return handler

    @addFilters_setLevel_Formatter
    def setup_logger(self, dirname: str = "./", handlers: list[str] = None, *args, **kwargs):
        '''
        dirname: log 存放的文件夹路径
        handlers: 哪些 handler 加入这个 logger？列表项为 handler 配置的 key
        '''
        if self.user_name != "main":
            dirname = dirname.replace("<name>", self.user_name)
            kwargs["name"] = kwargs["name"].replace("<name>", self.user_name)
        logger = logging.getLogger(*args, **kwargs)
        for handler in handlers:
            if "filename" in (temp_config := deepcopy(self.config[handler])):
                temp_config["filename"] = temp_config["filename"].replace("<name>", self.user_name)
                temp_config["filename"] = os.path.join(
                    dirname, temp_config["filename"])
            logger.addHandler(self.setup_handler(**temp_config))
        return logger

    def getLogger(self, log_config_key: str, user_name: str = "main"):
        '''
        log_config_key: 配置文件中 logger 配置的 key
        '''
        if (log := self.logs.get(user_name, None)):
            pass
        else:
            self.user_name = user_name
            log = self.setup_logger(**self.config[log_config_key])
            self.logs[user_name] = log
        return log


if __name__ == "__main__":
    logs = Zxs_log()
    logger = logs.getLogger("log_user", "huhan")
    # logger = logs.getLogger("log_system")
    logger.debug("This is debug!")
    logger.info("This is info!")
    logger.warning("This is warning!")
    logger.error("This is error!")
    logger.critical("This is critical!")
    logger = logs.getLogger("log_user", "ruirui")
    # logger = logs.getLogger("log_system")
    logger.debug("This is debug!")
    logger.info("This is info!")
    logger.warning("This is warning!")
    logger.error("This is error!")
    logger.critical("This is critical!")
    logger = logs.getLogger("log_user", "huhan")
    # logger = logs.getLogger("log_system")
    logger.debug("This is debug!")
    logger.info("This is info!")
    logger.warning("This is warning!")
    logger.error("This is error!")
    logger.critical("This is critical!")
    logger = logs.getLogger("log_system")
    logger.debug("This is debug!")
    logger.info("This is info!")
    logger.warning("This is warning!")
    logger.error("This is error!")
    logger.critical("This is critical!")
    print(logs.logs.keys())
