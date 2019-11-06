from threading import Lock, Event


class Dispatcher(object):
    def __init__(self, state_dir: str):
        self.state_dir = state_dir

        # instance is thread safe
        # lock is necessary, only one interface method may be running at the same time
        self.lock = Lock()

        # shutdown even, exit ASAP
        self.shutdown_event = Event()

    def add_interface(self, index: int, name: str) -> None:
        raise NotImplemented

    def remove_interface(self, index: int, name: str) -> None:
        raise NotImplemented

    def shutdown(self) -> None:
        self.shutdown_event.set()

    def status(self) -> None:
        raise NotImplemented

    def lock_acquire(self) -> bool:
        """Acquire the lock. True if succeeded. False if shutdown is in progress."""

        while True:
            # nasty way to acquire the lock, wish Python had a better way to wait on multiple objects
            if self.lock.acquire(timeout=1):
                return True
            else:
                if self.shutdown_event.is_set():
                    return False

    def lock_release(self) -> None:
        self.lock.release()
