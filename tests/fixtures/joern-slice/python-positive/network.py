from urllib.request import urlopen


def download(url: str) -> str:
    return urlopen(url).read().decode("utf-8")
