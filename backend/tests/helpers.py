PW = "correct-horse-battery"


def register(c, email, password=PW):
    return c.post("/auth/register", json={"email": email, "password": password})


def login(c, email, password=PW):
    return c.post("/auth/login", data={"username": email, "password": password})


def headers(c, email, password=PW):
    return {"Authorization": f"Bearer {login(c, email, password).json()['access_token']}"}
