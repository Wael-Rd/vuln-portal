from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import RedirectResponse
from starlette.status import HTTP_302_FOUND

router = APIRouter()


@router.get("/login")
def login_page(request: Request):
    return request.app.state.templates.TemplateResponse("login.html", {"request": request})


@router.post("/login")
def login_submit(request: Request, username: str = Form(...)):
    request.session["username"] = username.strip() or "guest"
    return RedirectResponse(url="/", status_code=HTTP_302_FOUND)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)