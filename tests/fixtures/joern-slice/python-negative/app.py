from urllib.request import urlopen


def show_remote_text(url: str) -> None:
    text = urlopen(url).read().decode("utf-8")
    print(text)


def run_fixed_code() -> None:
    exec("print('fixed and local')")
