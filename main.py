from fastapi import FastAPI, Form, Request
from fastapi.middleware.cors import CORSMiddleware

from integrations.hubspot import (
    authorize_hubspot,
    get_hubspot_credentials,
    get_items_hubspot,
    oauth2callback_hubspot,
)

app = FastAPI()

origins = [
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"Ping": "Pong"}


@app.post("/integrations/hubspot/authorize")
async def authorize_hubspot_integration(
    user_id: str = Form(...), org_id: str = Form(...)
):
    return await authorize_hubspot(user_id, org_id)


@app.get("/integrations/hubspot/oauth2callback")
async def oauth2callback_hubspot_integration(request: Request):
    return await oauth2callback_hubspot(request)


@app.post("/integrations/hubspot/credentials")
async def get_hubspot_credentials_integration(
    user_id: str = Form(...), org_id: str = Form(...)
):
    return await get_hubspot_credentials(user_id, org_id)


@app.post("/integrations/hubspot/load")
async def load_slack_data_integration(credentials: str = Form(...)):
    return await get_items_hubspot(credentials)
