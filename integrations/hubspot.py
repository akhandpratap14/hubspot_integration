import base64
from urllib.parse import urlencode
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import secrets
import json
from integrations.integration_item import IntegrationItem
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

BASE_AUTH_URL = "https://app.hubspot.com/oauth/authorize"
REDIRECT_URI = "http://localhost:8000/integrations/hubspot/oauth2callback"

CLIENT_ID = "43a8e4be-fbab-4804-aaa0-b24ac1038504"
CLIENT_SECRET = "27cecbfd-80d7-4422-8522-0a5ae1fe09e8"
SCOPES = " ".join(
    [
        "crm.objects.contacts.read",
        "crm.objects.companies.read",
        "crm.objects.deals.read",
        "content",
        "crm.schemas.custom.read",
        "oauth",
    ]
)


async def authorize_hubspot(user_id, org_id):
    state_data = {
        "state": secrets.token_urlsafe(32),
        "user_id": user_id,
        "org_id": org_id,
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

    await add_key_value_redis(
        f"hubspot_state:{org_id}:{user_id}", encoded_state, expire=600
    )

    query_params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": encoded_state,
    }

    authorization_url = f"{BASE_AUTH_URL}?{urlencode(query_params)}"
    return authorization_url


async def oauth2callback_hubspot(request: Request):
    if request.query_params.get("error"):
        raise HTTPException(status_code=400, detail=request.query_params.get("error"))

    code = request.query_params.get("code")
    received_state = request.query_params.get("state")

    if not received_state:
        raise HTTPException(status_code=400, detail="Missing state parameter")

    try:
        decoded_state = base64.urlsafe_b64decode(received_state).decode()
        state_data = json.loads(decoded_state)
    except (json.JSONDecodeError, base64.binascii.Error):
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    original_state = state_data.get("state")
    user_id = state_data.get("user_id")
    org_id = state_data.get("org_id")

    if not user_id or not org_id:
        raise HTTPException(
            status_code=400, detail="Invalid user_id or org_id in state"
        )

    saved_state = await get_value_redis(f"hubspot_state:{org_id}:{user_id}")
    if not saved_state:
        raise HTTPException(status_code=400, detail="State not found in Redis")

    try:
        saved_state_data = json.loads(base64.urlsafe_b64decode(saved_state).decode())
    except (json.JSONDecodeError, base64.binascii.Error):
        raise HTTPException(status_code=400, detail="Invalid state data in Redis")

    if original_state != saved_state_data.get("state"):
        raise HTTPException(status_code=400, detail="State does not match")

    token_url = "https://api.hubapi.com/oauth/v1/token"
    async with httpx.AsyncClient() as client:
        response = await client.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        delete_key_redis(f"notion_state:{org_id}:{user_id}"),

    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code, detail="Failed to retrieve tokens"
        )

    tokens = response.json()

    print(tokens)

    await add_key_value_redis(
        f"hubspot_credentials:{org_id}:{user_id}", json.dumps(tokens), expire=3600
    )

    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)


async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f"hubspot_credentials:{org_id}:{user_id}")
    if not credentials:
        raise HTTPException(status_code=400, detail="No credentials found.")

    try:
        credentials = json.loads(credentials)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid credentials format.")

    if "access_token" not in credentials:
        raise HTTPException(status_code=400, detail="Access token missing.")

    return credentials


from datetime import datetime


async def create_integration_item_metadata_object(response_json):
    properties = response_json.get("properties", {})

    item_id = response_json.get("id")
    name = f"{properties.get('firstname', 'Unnamed')} {properties.get('lastname', '')}".strip()
    email = properties.get("email")
    created_time = properties.get("createdate")
    last_modified_time = properties.get("lastmodifieddate")

    creation_time = datetime.fromisoformat(created_time[:-1]) if created_time else None
    last_modified_time = (
        datetime.fromisoformat(last_modified_time[:-1]) if last_modified_time else None
    )

    return IntegrationItem(
        id=item_id,
        type="contact",
        directory=False,
        parent_path_or_name=email,
        parent_id=None,
        name=name,
        creation_time=creation_time,
        last_modified_time=last_modified_time,
        url=None,
        children=None,
        mime_type=None,
        delta=None,
        drive_id=None,
        visibility=True,
    )


async def get_items_hubspot(credentials):
    credentials = json.loads(credentials)

    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.hubapi.com/crm/v3/objects/contacts",
            headers={
                "Authorization": f'Bearer {credentials.get("access_token")}',
            },
        )

    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code,
            detail="Failed to fetch items from HubSpot.",
        )

    items = response.json().get("results", [])
    print(items)
    integration_items = [
        await create_integration_item_metadata_object(item) for item in items
    ]
    return integration_items
