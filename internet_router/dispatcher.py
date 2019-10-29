from threading import Lock


class Dispatcher(object):
    # Every <net>/64 subnet will have by default
    # <net>.1 - default gateway
    # <net>.2 - service address for the NAT64 translator

    def __init__(self, state_dir: str):
        self.state_dir = state_dir

        # instance is thread safe
        # lock is necessary, only once interface method may be running at the same time
        self.lock = Lock()

    def add_interface(self, index: int, name: str) -> None:
        raise NotImplemented

    def remove_interface(self, index: int, name: str) -> None:
        raise NotImplemented

    def shutdown(self) -> None:
        raise NotImplemented

    def status(self) -> None:
        raise NotImplemented
