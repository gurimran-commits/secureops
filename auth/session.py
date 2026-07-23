_authenticated = False
_current_user = None


def login(user: str):
    global _authenticated, _current_user
    _authenticated = True
    _current_user = user


def logout():
    global _authenticated, _current_user
    _authenticated = False
    _current_user = None


def is_authenticated() -> bool:
    return _authenticated


def current_user():
    return _current_user
