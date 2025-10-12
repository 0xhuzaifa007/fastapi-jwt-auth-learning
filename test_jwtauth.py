"""
Stage 2: Simple Authentication System
Learn the basics of authentication before adding OAuth

This stage Implementing:
- Password hashing (why we never store plain passwords)
- Token creation (using JWT)
- Protected endpoints (routes that require authentication)
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from typing import Optional

# ============================================================================
# CONFIGURATION - Settings for our app
# ============================================================================

# This is a SECRET key used to sign tokens. In production, this should be:
# - Very random and complex
# - Stored in environment variables (never in code!)
# - Never shared or committed to git
SECRET_KEY = "mcpauth2.0"
ALGORITHM = "HS256"  # The algorithm to sign tokens
ACCESS_TOKEN_EXPIRE_MINUTES = 1  # Tokens expire after 30 minutes

# ============================================================================
# INITIALIZE APP
# ============================================================================

app = FastAPI(title="Stage 2: Simple Authentication")

# This handles password hashing using bcrypt
# bcrypt is slow on purpose - this makes it hard for attackers to crack passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# This tells FastAPI to look for tokens in the Authorization header
security = HTTPBearer()

# ============================================================================
# DATA MODELS - Define the structure of our data
# ============================================================================

class User(BaseModel):
    """What a user looks like"""
    username: str
    email: str
    full_name: Optional[str] = None
    age: int

class UserInDB(User):
    """User as stored in database (includes hashed password)"""
    hashed_password: str

class UserCreate(BaseModel):
    """Data needed to create a new user"""
    username: str
    email: str
    password: str
    full_name: Optional[str] = None
    age: int

class Token(BaseModel):
    """What we return when someone logs in"""
    access_token: str
    token_type: str

class LoginRequest(BaseModel):
    """Data needed to log in"""
    username: str
    password: str

# ============================================================================
# FAKE DATABASE - In real app, this would be PostgreSQL/Supabase
# ============================================================================

# For learning, we'll store users in memory (lost when app restarts)
fake_users_db = {}

# ============================================================================
# HELPER FUNCTIONS - Reusable code
# ============================================================================

def hash_password(password: str) -> str:
    """
    Convert a plain password into a hash
    
    Why hash? If someone steals our database, they can't see real passwords.
    Example: "mypassword123" becomes "$2b$12$eAx..." (this is one-way!)
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Check if a password matches its hash
    
    We can't "decrypt" the hash, but we can hash the input and compare!
    """
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(username: str) -> str:
    """
    Create a JWT (JSON Web Token)
    
    A JWT contains:
    1. Header: Type of token and algorithm
    2. Payload: The data (username, expiration time)
    3. Signature: Proof it hasn't been tampered with
    
    Format: xxxxx.yyyyy.zzzzz (header.payload.signature)
    """
    # Data to put in the token
    payload = {
        "sub": username,  # "sub" is standard for "subject" (who this token is for)
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": datetime.utcnow()  # "iat" = issued at
    }
    
    # Sign the token with our secret key
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

def verify_token(token: str) -> Optional[str]:
    """
    Verify a token and extract the username
    
    Returns username if valid, None if invalid/expired
    """
    try:
        # Decode and verify the token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        if username is None:
            return None
            
        return username
        
    except JWTError:
        # Token is invalid, expired, or tampered with
        return None

def get_user(username: str) -> Optional[UserInDB]:
    """Get a user from our database"""
    if username in fake_users_db:
        user_dict = fake_users_db[username]
        return UserInDB(**user_dict)
    return None

def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """
    Authenticate a user
    
    Steps:
    1. Find the user in database
    2. Check if password matches
    3. Return user if valid, None if not
    """
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

# ============================================================================
# DEPENDENCY - Gets current user from token
# ============================================================================

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    """
    This is a FastAPI dependency that:
    1. Extracts the token from the request
    2. Verifies it's valid
    3. Returns the current user
    
    If anything fails, it raises an HTTP 401 Unauthorized error
    """
    token = credentials.credentials
    username = verify_token(token)
    
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = get_user(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    # Return user without password
    return User(username=user.username, email=user.email, full_name=user.full_name, age=user.age)

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Welcome endpoint - no authentication needed"""
    return {
        "message": "Welcome to Stage 2: Simple Authentication!",
        "endpoints": {
            "register": "POST /register - Create a new account",
            "login": "POST /login - Get an access token",
            "profile": "GET /profile - View your profile (requires token)",
            "protected": "GET /protected - Test protected endpoint"
        },
        "tutorial": "Try registering, logging in, then accessing /profile with your token!"
    }

@app.post("/register", response_model=User)
async def register(user_data: UserCreate):
    """
    Register a new user
    
    Exercise: Read this code and answer:
    1. What happens if username already exists?
    2. Why do we hash the password before storing?
    3. Why don't we return the password in the response?
    """
    # Check if username already taken
    if user_data.username in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Create user with hashed password
    hashed_password = hash_password(user_data.password)
    user_in_db = UserInDB(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        age=user_data.age,
        hashed_password=hashed_password
    )
    
    # Save to "database"
    fake_users_db[user_data.username] = user_in_db.dict()
    
    # Return user info (without password!)
    return User(
        username=user_in_db.username,
        email=user_in_db.email,
        full_name=user_in_db.full_name,
        age= user_in_db.age
    )

@app.post("/login", response_model=Token)
async def login(login_data: LoginRequest):
    """
    Login and get an access token
    
    Exercise: 
    1. What would happen if we didn't verify the password?
    2. Why do we return a token instead of storing login state on the server?
    3. What is the token_type "bearer" and why do we use it?
    """
    # Verify credentials
    user = authenticate_user(login_data.username, login_data.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token = create_access_token(user.username)
    
    return Token(access_token=access_token, token_type="bearer")

@app.get("/profile", response_model=User)
async def get_profile(current_user: User = Depends(get_current_user)):
    """
    Get current user's profile
    
    This endpoint is PROTECTED - it requires a valid token!
    
    Notice: We use Depends(get_current_user)
    - FastAPI automatically calls get_current_user
    - It extracts and verifies the token
    - If valid, we get the user; if not, user gets 401 error
    
    Exercise: Try calling this endpoint without a token. What happens?
    """
    return current_user

@app.get("/protected")
async def protected_route(current_user: User = Depends(get_current_user)):
    """
    Example protected endpoint
    
    Any endpoint with Depends(get_current_user) requires authentication
    """
    return {
        "message": f"Hello {current_user.username}! You successfully accessed a protected route.",
        "your_data": {
            "username": current_user.username,
            "email": current_user.email,
            "full_name": current_user.full_name
        }
    }
@app.get("/admin")
async def admin_route(current_user: User = Depends(get_current_user)):
    if current_user.username != 'admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN ,
            detail="Administrator Only",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {
        "message": f"Hello {current_user.username}! You successfully accessed admin page.",
        "data" :{
            "username": current_user.username,
            "email": current_user.email,
            "full_name": current_user.full_name
        }
    }

@app.get("/public")
async def public_route():
    """
    Example public endpoint - no authentication required
    
    Notice: No Depends(get_current_user) here!
    """
    return {
        "message": "This is a public endpoint. Anyone can access this!",
        "authentication_required": False
    }

# ============================================================================
# RUN THE APP
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Stage 2: Simple Authentication")
    print("📖 Go to http://localhost:8000/docs to test the API")
    print("\n💡 Try this flow:")
    print("   1. POST /register - Create an account")
    print("   2. POST /login - Get your token")
    print("   3. GET /profile - Use your token (click 'Authorize' button in docs)")
    uvicorn.run(app, host="0.0.0.0", port=8000)


# ============================================================================
# LEARNING EXERCISES
# ============================================================================

"""
🎓 EXERCISES FOR STAGE 2:

BEGINNER:
1. Run the server and use the /docs interface to:
   - Register a new user
   - Login with that user
   - Access the /profile endpoint using your token
   
2. Try to access /profile WITHOUT a token. What error do you get?

3. Look at a JWT token you received. Copy it and paste it into https://jwt.io
   What data do you see? Can you find the username and expiration time?

INTERMEDIATE:
4. Add a new field to the User model (like "age" or "country")
   Update the register endpoint to accept this new field

5. Create a new protected endpoint /admin that only allows access if the 
   username is "admin"

6. Modify the token to expire after 5 minutes instead of 30. Test that it 
   actually expires.

ADVANCED:
7. Add a "refresh token" system where access tokens expire quickly but 
   refresh tokens last longer

8. Implement a "logout" feature using a token blacklist

9. Add rate limiting to prevent brute force attacks on the login endpoint

UNDERSTANDING CHECK:
- Can you explain to someone else how JWT tokens work?
- Why is bcrypt better than simple hashing like MD5?
- What's the difference between authentication and authorization?
"""