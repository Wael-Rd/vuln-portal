from fastapi import Request, HTTPException, status


def require_login(request: Request):
    if not request.session.get("username"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Login required.")
    return request.session["username"]