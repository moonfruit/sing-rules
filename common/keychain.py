import functools

import keyring

from .common import SimpleObject


@functools.cache
def get_password(service: str = "ENV", password: str = "proxy") -> str:
    proxy = keyring.get_password(service, password)
    if not proxy:
        raise ValueError("No password for `proxy` in `ENV`")
    return proxy


def get_proxy_user() -> SimpleObject:
    proxy = get_password()
    user = proxy.split(":", 1)
    return {"username": user[0], "password": user[1] if len(user) > 1 else user[0]}
