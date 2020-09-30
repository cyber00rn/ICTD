import logging

class Printer():
    def __init__(self, setting_level=logging.INFO):
        logging.basicConfig(level=setting_level,
                    format='%(asctime)s.%(msecs)03d {%(filename)s:%(lineno)d} %(levelname)s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

    def debug(self, *args, **kwargs):
        logging.debug(" ".join(map(str,args)), **kwargs)

    def info(self, *args, **kwargs):
        logging.info(" ".join(map(str,args)), **kwargs)

    def warning(self, *args, **kwargs):
        logging.warning(" ".join(map(str,args)), **kwargs)

    def error(self, *args, **kwargs):
        logging.error(" ".join(map(str,args)), **kwargs)

    def critical(self, *args, **kwargs):
        logging.critical(" ".join(map(str,args)), **kwargs)