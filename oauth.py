from pydantic import BaseModel

class oauth_clients(BaseModel):
    client_id: str
    client_secret_hash: str
    redirect_uris: str
    allowed_scopes: str

class authorization_codes(BaseModel):
    code: str
    client_id: str
    user: str
    scope: Optional[str] = None
    expires_at: Optional[int] = None 
    redirect_uri: str
    used: Optional[bool] = False

class authorizationRequest(BaseModel):
    client_id:str
    redirect_uri: str
    
class TokenRequest(BaseModel):
    authorization_code: str
    client_secret: str
    client_id: str
    redirect_uri: str

@app.get("/oauth/authorize")
async def authorize(...):
    # 1. Validate client_id exists
    # 2. Validate redirect_uri is registered
    # 3. Validate requested scopes are allowed
    # 4. Check if user is logged in (reuse your Stage 2 auth!)
    # 5. Show consent page (for now, auto-approve)
    # 6. Generate authorization code
    # 7. Store code with expiration
    # 8. Redirect to redirect_uri with code
    pass

@app.post("/oauth/token")
async def token(authorization_code: str):
    # 1. Validate authorization code
    # 2. validate client_secret
    # 3. redirect to app and allow access
    pass
@app.post("/oauth/register_client")
async def register_client(client_id: str ):
    # 1. Validate client_id
    # 2. authenticate client_secret
    pass