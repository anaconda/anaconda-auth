from typing import Any


class SimpleConsole:
    """
    A very simple console class to mimic the necessary methods we use from rich,
    in case anaconda_cloud_cli is unavailable.
    """

    @staticmethod
    def print(*args: Any, **kwargs: Any) -> None:
        print(*args, **kwargs)

    @staticmethod
    def input(*args: Any, **kwargs: Any) -> Any:
        return input(args[0])


try:
    from anaconda_cloud_cli import console  # type: ignore

except ImportError:
    console = SimpleConsole()
