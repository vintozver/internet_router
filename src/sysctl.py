import os.path
import typing
import logging


class SysctlControllerException(Exception):
    pass


class SysctlController(object):
    def __init__(self):
        self.cache = dict()

    def get_sysctl(self, name: typing.Iterable[str]) -> str:
        name_path = os.path.join(*name)
        logging.debug('Reading sysctl:%s' % name)
        try:
            return open(os.path.join('/proc/sys', name_path), 'r').read()
        except OSError:
            logging.warning('Could not get sysctl:%s' % name)
            raise SysctlControllerException('get', name)

    def set_sysctl(self, name: typing.Iterable[str], value: str) -> None:
        name_path = os.path.join(*name)
        self.cache[name_path] = self.get_sysctl(name)
        logging.debug('Writing sysctl:%s value:%s' % (name, value))
        try:
            open(os.path.join('/proc/sys', name_path), 'w').write(value)
        except OSError:
            logging.info('Could not set sysctl:%s to value:%s' % (name, value))
            raise SysctlControllerException('set', name, value)

    def restore_sysctl(self, name: typing.Iterable[str]) -> None:
        name_path = os.path.join(*name)
        try:
            value = self.cache[name_path]
        except KeyError:
            pass
        else:
            try:
                open(os.path.join('/proc/sys', name_path), 'w').write(value)
            except OSError:
                logging.info('Could not restore sysctl:%s to value:%s' % (name, value))
