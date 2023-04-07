import uvicorn
from fastapi import FastAPI
from fastapi.routing import APIRouter

app = FastAPI()
route = APIRouter(prefix="/api")


@route.get("/")
async def handle():
    return {"api": "v1"}


app.include_router(route)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
