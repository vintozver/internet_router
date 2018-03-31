import sys


def std_stream_dup(prefix: str, process_stream) -> None:
    """polling thread function"""

    system_stdout = sys.stdout
    while True:
        try:
            line = process_stream.readline()
        except OSError:
            break
        if not line:
            break
        system_stdout.write(prefix)
        system_stdout.write(line.decode('utf-8'))
