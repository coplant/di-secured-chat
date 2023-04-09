import uvicorn
from fastapi import FastAPI
from fastapi.routing import APIRouter
from src.auth.router import router as auth_router
from src.utils import setup_keys, get_keys

# keys setup
public_key, private_key = get_keys()
if not public_key or not private_key:
    public_key, private_key = setup_keys()

app = FastAPI()
route = APIRouter(prefix="/api", tags=[])

route.include_router(auth_router)
app.include_router(route)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
