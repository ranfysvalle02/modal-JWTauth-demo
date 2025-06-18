# modal-JWTauth-demo


---

# Building a Secure Authentication System with MongoDB, JWT, and Modal
   
In today's digital landscape, secure authentication mechanisms are paramount. Whether you're building a web application, a mobile app, or even a browser extension, ensuring that only authorized users can access certain resources is a critical concern. In this blog post, we'll explore how to create a secure authentication system using **MongoDB**, **JSON Web Tokens (JWT)**, and **Modal**.
   
## Introduction  
   
We'll walk through the process of building a secure API with user registration and authentication, leveraging MongoDB for data storage and JWT for token-based authentication. We'll also create a page (index.html) that interacts with our API, allowing users to register, log in, and access protected resources.  
   
But first, let's get acquainted with the technologies we'll be using.  
   
## Technologies Used  
   
- **MongoDB**: A NoSQL database renowned for its flexibility and scalability, ideal for storing user data and tokens securely.  
    
- **JSON Web Tokens (JWT)**: An open standard for creating tokens that assert some number of claims, commonly used for authentication and secure data exchange.  
    
- **FastAPI**: A modern, fast (high-performance) web framework for building APIs with Python 3.7+ based on standard Python type hints.  
    
- **Modal**: A cloud function platform that simplifies the deployment and scaling of applications, removing the need to manage underlying infrastructure.  
    
   
## Prerequisites  
   
Before diving in, ensure you have the following set up:  
   
- A **Modal** account. Sign up at [modal.com](https://modal.com) if you haven't already.  
- Basic knowledge of Python and JavaScript.  
- Familiarity with concepts like APIs, JWT, and web development in general.  
   
## Setting Up the Backend with FastAPI and MongoDB  
   
### 1. Setting Up the Project Structure  
   
Create a new directory for your project and initialize a Python environment.  
   
```bash  
mkdir jwt-auth-api  
cd jwt-auth-api  
python -m venv venv  
source venv/bin/activate  # On Windows use `venv\Scripts\activate`  
```  
   
### 2. Installing Dependencies  
   
Install the necessary Python packages:  
   
```bash  
pip install fastapi[standard]==0.115.4 pymongo==4.7.2 pydantic==2.7.1 passlib==1.7.4 PyJWT==2.8.0 modal  
```  
   
### 3. The `modal-app.py` File  
   
Create a `modal-app.py` file and paste the following code:  
   
```python  
# modal-app.py  
  
import os  
import jwt  
import datetime  
from typing import Dict, Optional, List  
  
from fastapi import FastAPI, HTTPException, Body, Depends, Header, status  
from fastapi.responses import JSONResponse, HTMLResponse  
from fastapi.middleware.cors import CORSMiddleware  
from pydantic import BaseModel, Field  
from passlib.context import CryptContext  
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError  
import modal  
from pymongo import MongoClient  
from bson import ObjectId  
  
# --- Configuration ---  
  
# Load environment variables or set default values  
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key')  
JWT_ALGORITHM = 'HS256'  
ACCESS_TOKEN_EXPIRE_MINUTES = 15  
REFRESH_TOKEN_EXPIRE_DAYS = 180  # Approximately 6 months  
  
# MongoDB configuration  
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')  
  
# --- Modal Setup ---  
  
# Define the image with necessary Python libraries.  
image = modal.Image.debian_slim(python_version="3.12").pip_install(  
    "fastapi[standard]==0.115.4",  
    "pymongo==4.7.2",  
    "pydantic==2.7.1",  
    "passlib==1.7.4",  
    "PyJWT==2.8.0"  
)  
  
# Create a Modal App instance.  
app = modal.App("wishlist-api", image=image)  
  
# --- FastAPI App Setup ---  
  
# Create the FastAPI app.  
web_app = FastAPI(  
    title="Wishlist API with Authentication",  
    description="An API to manage items in a wishlist with JWT authentication using FastAPI, Modal, and MongoDB."  
)  
  
# Allow CORS for development purposes  
web_app.add_middleware(  
    CORSMiddleware,  
    allow_origins=["*"],  # For development, consider specifying origins  
    allow_credentials=True,  
    allow_methods=["*"],  
    allow_headers=["*"],  
)  
  
# --- Set up CryptContext for password hashing ---  
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")  
  
# --- Initialize MongoDB client ---  
client = MongoClient(MONGO_URI)  
db = client.moonshop  # Use your database  
users_collection = db.users  
refresh_tokens_collection = db.refresh_tokens  

  
# --- Pydantic Models ---  
  
class UserRegister(BaseModel):  
    username: str = Field(..., example="user1")  
    password: str = Field(..., min_length=8, example="password123")  
  
class UserAuth(BaseModel):  
    username: str = Field(..., example="user1")  
    password: str = Field(..., example="password123")  
  
class TokenResponse(BaseModel):  
    status: str  
    access_token: str  
    refresh_token: str  
  
class TokenRefreshRequest(BaseModel):  
    refresh_token: str  
  
# --- Helper Functions ---  
  
def create_access_token(username: str) -> str:  
    payload = {  
        'sub': username,  
        'iat': datetime.datetime.utcnow(),  
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  
    }  
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)  
    return token  
  
def create_refresh_token(username: str) -> str:  
    payload = {  
        'sub': username,  
        'iat': datetime.datetime.utcnow(),  
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  
    }  
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)  
    return token  
  
def get_current_user(Authorization: str = Header(None)) -> str:  
    """Decode the access token and return the username."""  
    if not Authorization:  
        raise HTTPException(status_code=401, detail="Missing Authorization header.")  
  
    try:  
        token_type, token = Authorization.split()  
        if token_type != 'Bearer':  
            raise HTTPException(status_code=401, detail="Invalid token type.")  
  
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])  
        username = payload.get('sub')  
        return username  
  
    except ExpiredSignatureError:  
        raise HTTPException(status_code=401, detail="Access token expired.")  
    except Exception as e:  
        raise HTTPException(status_code=401, detail=str(e))  
  
# --- Authentication Endpoints ---  
  
@web_app.post('/register', tags=["Authentication"])  
def register(user: UserRegister):  
    """Registers a new user."""  
    if not user.username or not user.password:  
        raise HTTPException(status_code=400, detail="Username and password are required.")  
  
    if len(user.password) < 8:  
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")  
  
    if users_collection.find_one({'username': user.username}):  
        raise HTTPException(status_code=400, detail="User already exists.")  
  
    # Hash the password for secure storage  
    password_hash = pwd_context.hash(user.password)  
  
    users_collection.insert_one({  
        'username': user.username,  
        'password_hash': password_hash  
    })  
  
    return {'status': 'ok', 'message': 'User registered successfully.'}  
  
@web_app.post('/authenticate', response_model=TokenResponse, tags=["Authentication"])  
def authenticate(user: UserAuth):  
    """Authenticates a user and returns JWT tokens."""  
    db_user = users_collection.find_one({'username': user.username})  
    if not db_user:  
        raise HTTPException(status_code=404, detail="User not found.")  
  
    if not pwd_context.verify(user.password, db_user['password_hash']):  
        raise HTTPException(status_code=401, detail="Invalid credentials.")  
  
    # Generate tokens  
    access_token = create_access_token(user.username)  
    refresh_token = create_refresh_token(user.username)  
  
    # Store refresh token  
    refresh_tokens_collection.insert_one({  
        'refresh_token': refresh_token,  
        'username': user.username  
    })  
  
    return {  
        'status': 'ok',  
        'access_token': access_token,  
        'refresh_token': refresh_token  
    }  
  
@web_app.post('/refresh', response_model=TokenResponse, tags=["Authentication"])  
def refresh_token(data: TokenRefreshRequest):  
    """Generates new access and refresh tokens."""  
    stored_token = refresh_tokens_collection.find_one({'refresh_token': data.refresh_token})  
  
    if not stored_token:  
        raise HTTPException(status_code=400, detail="Invalid refresh token.")  
  
    try:  
        payload = jwt.decode(data.refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])  
        username = payload.get('sub')  
  
        # Generate new tokens  
        access_token = create_access_token(username)  
        new_refresh_token = create_refresh_token(username)  
  
        # Update refresh tokens  
        refresh_tokens_collection.delete_one({'refresh_token': data.refresh_token})  
        refresh_tokens_collection.insert_one({  
            'refresh_token': new_refresh_token,  
            'username': username  
        })  
  
        return {  
            'status': 'ok',  
            'access_token': access_token,  
            'refresh_token': new_refresh_token  
        }  
  
    except ExpiredSignatureError:  
        raise HTTPException(status_code=400, detail="Refresh token expired.")  
    except InvalidTokenError:  
        raise HTTPException(status_code=400, detail="Invalid refresh token.")  
    except Exception as e:  
        raise HTTPException(status_code=400, detail=str(e))  
  
# --- Mount the FastAPI app with Modal ---  
  
@app.function()  
@modal.asgi_app()  
def fastapi_app():  
    """Serves the FastAPI application."""  
    return web_app  

```  
   
#### Key Components Explained:  
   
- **Modal Setup**: We define an image with the necessary dependencies and create a `Modal` app to deploy our FastAPI application.  
    
- **MongoDB Connection**: Using `pymongo`, we connect to our MongoDB instance to manage user data and refresh tokens.  
    
- **Password Hashing**: Passwords are hashed using `passlib`'s `CryptContext` to ensure they're securely stored.  
    
- **JWT Token Generation**: We have helper functions to create access and refresh tokens, embedding the username and expiration time.  
    
- **API Endpoints**:  
  - `/register`: Allows new users to register.  
  - `/authenticate`: Authenticates users and provides JWT tokens.  
  - `/refresh`: Generates new tokens using a valid refresh token.  
   
### 4. Deploying with Modal  
   
With Modal, deploying our application is straightforward. Ensure you've logged in via the CLI then, deploy your Modal app:  
   
```bash  
modal deploy modal-app.py  
```  
   
Modal takes care of building the container, deploying the application, and scaling as needed.  
   

## Demo Page (index.html)

```index.html
<!DOCTYPE html>    
<html lang="en">    
<head>    
  <meta charset="UTF-8">    
  <title>Moonsh0p</title>    
  <meta name="viewport" content="width=device-width, initial-scale=1.0">    
  <!-- Bootstrap CSS -->    
  <link href="bootstrap/bootstrap.min.css" rel="stylesheet">    
  <style>    
    body {    
      font-family: 'Inter', sans-serif;    
      padding: 15px;    
      background-color: #f9fafb;    
      margin: 0 auto;    
      width: 500px;    
      height: 620px;    
      overflow-y: auto;    
      padding-top: 2em;    
    }    
    h1 {    
      font-size: 24px;    
      font-weight: 600;    
      color: #374151;    
      margin-bottom: 20px;    
    }    
    #loginButton, #logoutButton {    
      width: 100%;    
      transition: background-color 0.3s;    
    }    
    #loginButton:hover, #logoutButton:hover {    
      background-color: #2563eb;    
      color: #fff;    
    }    
    #authSection,    
    #welcomeSection {    
      transition: opacity 0.5s ease, transform 0.5s ease;    
      /* Sections are hidden by default */    
      display: none;    
    }    
    .section-visible {    
      display: block !important;    
    }    
    .hidden {    
      opacity: 0;    
      transform: scale(0.95);    
      pointer-events: none;    
    }    
    #authSection p {    
      font-size: 14px;    
      color: #374151;    
      margin-bottom: 15px;    
    }    
  </style>    
</head>    
<body>    
  <h1 class="text-center">Moonsh0p</h1>    
    
  <!-- Authentication Section -->    
  <div id="authSection">    
    <p class="text-center">    
      Welcome to <strong>Moonsh0p</strong>!<br>    
      Please log in or register to get started.    
    </p>    
    <div class="d-grid">    
      <button id="loginButton" class="btn btn-primary mb-3">Login / Register</button>    
    </div>    
  </div>    
    
  <!-- Welcome Section (Visible when logged in) -->    
  <div id="welcomeSection" class="hidden">    
    <p id="welcomeMessage" class="text-center"></p>    
    <div class="d-grid">    
      <button id="logoutButton" class="btn btn-secondary mb-3">Logout</button>    
    </div>    
  </div>    
    
  <!-- Authentication Modal -->    
  <div class="modal fade" id="authModal" tabindex="-1" aria-labelledby="authModalLabel" aria-hidden="true">    
    <div class="modal-dialog modal-dialog-centered modal-sm">    
      <div class="modal-content">    
        <div class="modal-header">    
          <h5 class="modal-title">Login or Register</h5>    
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>    
        </div>    
        <div class="modal-body">    
          <!-- Username Input -->    
          <div class="mb-3">    
            <label for="usernameInput" class="form-label">Username</label>    
            <input type="text" id="usernameInput" class="form-control" placeholder="Enter username">    
          </div>    
          <!-- Password Input -->    
          <div class="mb-3">    
            <label for="passwordInput" class="form-label">Password</label>    
            <input type="password" id="passwordInput" class="form-control" placeholder="Enter password">    
          </div>    
        </div>    
        <div class="modal-footer">    
          <button type="button" id="loginModalButton" class="btn btn-primary">Login</button>    
          <button type="button" id="registerModalButton" class="btn btn-success">Register</button>    
        </div>    
      </div>    
    </div>    
  </div>    
    
  <!-- Bootstrap JS -->    
  <script src="bootstrap/bootstrap.bundle.min.js"></script>    
  <script>    
    // API Base URL    
    const BASE_URL = 'https://ranfysvalle02--wishlist-api-fastapi-app.modal.run'; // Update this to your actual base URL    
        
    // API Endpoints    
    const ENDPOINTS = {    
      register: `${BASE_URL}/register`,    
      authenticate: `${BASE_URL}/authenticate`,    
      refresh: `${BASE_URL}/refresh`,    
    };    
        
    // Authentication tokens    
    let accessToken = '';    
    let refreshToken = '';    
        
    // Function to store tokens in local storage    
    function storeTokens(access, refresh) {    
      accessToken = access;    
      refreshToken = refresh;    
      localStorage.setItem('accessToken', accessToken);    
      localStorage.setItem('refreshToken', refreshToken);    
    }    
        
    // Function to load tokens from local storage    
    function loadTokens() {    
      accessToken = localStorage.getItem('accessToken') || '';    
      refreshToken = localStorage.getItem('refreshToken') || '';    
    }    
        
    // Function to clear tokens    
    function clearTokens() {    
      accessToken = '';    
      refreshToken = '';    
      localStorage.removeItem('accessToken');    
      localStorage.removeItem('refreshToken');    
    }    
        
    // Function to check if the user is authenticated    
    function isAuthenticated() {    
      return !!accessToken;    
    }    
        
    // Function to make authenticated API calls    
    async function authenticatedFetch(url, options = {}) {    
      if (!options.headers) {    
        options.headers = {};    
      }    
      options.headers['Authorization'] = `Bearer ${accessToken}`;    
        
      let response = await fetch(url, options);    
        
      if (response.status === 401) {    
        // Try to refresh the token    
        const refreshed = await refreshAccessToken();    
        if (refreshed) {    
          options.headers['Authorization'] = `Bearer ${accessToken}`;    
          response = await fetch(url, options);    
        } else {    
          // Failed to refresh token, force logout    
          alert('Session expired. Please log in again.');    
          logout();    
          throw new Error('Authentication required');    
        }    
      }    
        
      return response;    
    }    
        
    // Function to refresh access token    
    async function refreshAccessToken() {    
      if (!refreshToken) {    
        return false;    
      }    
        
      try {    
        const response = await fetch(ENDPOINTS.refresh, {    
          method: 'POST',    
          headers: { 'Content-Type': 'application/json' },    
          body: JSON.stringify({ refresh_token: refreshToken }),    
        });    
        
        if (response.ok) {    
          const data = await response.json();    
          storeTokens(data.access_token, data.refresh_token);    
          return true;    
        } else {    
          clearTokens();    
          return false;    
        }    
      } catch (error) {    
        console.error('Error refreshing token:', error);    
        clearTokens();    
        return false;    
      }    
    }    
        
    // Function to register a new user    
    async function register(username, password) {    
      try {    
        const response = await fetch(ENDPOINTS.register, {    
          method: 'POST',    
          headers: { 'Content-Type': 'application/json' },    
          body: JSON.stringify({ username, password }),    
        });    
        
        if (response.ok) {    
          alert('Registration successful! You can now log in.');    
          return true;    
        } else {    
          const errorData = await response.json();    
          alert('Registration failed: ' + (errorData.detail || 'Unknown error'));    
          return false;    
        }    
      } catch (error) {    
        console.error('Error registering:', error);    
        alert('Error registering.');    
        return false;    
      }    
    }    
        
    // Function to authenticate a user (login)    
    async function login(username, password) {    
      try {    
        const response = await fetch(ENDPOINTS.authenticate, {    
          method: 'POST',    
          headers: { 'Content-Type': 'application/json' },    
          body: JSON.stringify({ username, password }),    
        });    
        
        if (response.ok) {    
          const data = await response.json();    
          storeTokens(data.access_token, data.refresh_token);    
          // Store the username for display purposes    
          localStorage.setItem('username', username);    
          return true;    
        } else {    
          const errorData = await response.json();    
          alert('Login failed: ' + (errorData.detail || 'Unknown error'));    
          return false;    
        }    
      } catch (error) {    
        console.error('Error logging in:', error);    
        alert('Error logging in.');    
        return false;    
      }    
    }    
        
    // Function to logout    
    function logout() {    
      clearTokens();    
      // Clear stored username    
      localStorage.removeItem('username');    
      // Update UI    
      const authSection = document.getElementById('authSection');    
      const welcomeSection = document.getElementById('welcomeSection');    
      showSection(authSection);    
      hideSection(welcomeSection);    
    }    
        
    // Smooth transitions when showing/hiding sections    
    function showSection(section) {    
      // Remove the 'hidden' class to start the transition    
      section.classList.remove('hidden');    
        
      // Add the 'section-visible' class to ensure the section is displayed    
      section.classList.add('section-visible');    
        
      // Force a reflow to ensure the transition starts correctly    
      void section.offsetWidth;    
    }    
        
    function hideSection(section) {    
      // Check if section is already hidden    
      if (section.classList.contains('hidden')) {    
        return;    
      }    
        
      // Define the event handler    
      function handleTransitionEnd(event) {    
        // Ensure the event is for opacity transition    
        if (event.propertyName === 'opacity') {    
          section.classList.remove('section-visible');    
          // Clean up the event listener    
          section.removeEventListener('transitionend', handleTransitionEnd);    
        }    
      }    
        
      // Add the transitionend event listener    
      section.addEventListener('transitionend', handleTransitionEnd);    
        
      // Add the 'hidden' class to start the transition    
      section.classList.add('hidden');    
    }    
        
    // Event listener for the "Login / Register" button    
    document.getElementById('loginButton').addEventListener('click', () => {    
      // Show the modal    
      const authModal = new bootstrap.Modal(document.getElementById('authModal'));    
      authModal.show();    
    });    
        
    // Event listener for the "Logout" button    
    document.getElementById('logoutButton').addEventListener('click', () => {    
      logout();    
    });    
        
    // Event listener for the "Login" button in the auth modal    
    document.getElementById('loginModalButton').addEventListener('click', async () => {    
      const username = document.getElementById('usernameInput').value.trim();    
      const password = document.getElementById('passwordInput').value;    
        
      if (username && password) {    
        const success = await login(username, password);    
        if (success) {    
          // Hide the modal    
          const authModal = bootstrap.Modal.getInstance(document.getElementById('authModal'));    
          authModal.hide();    
        
          // Update UI    
          const authSection = document.getElementById('authSection');    
          const welcomeSection = document.getElementById('welcomeSection');    
          hideSection(authSection);    
          showSection(welcomeSection);    
          document.getElementById('welcomeMessage').textContent = 'Welcome, ' + username + '!';    
        
          // Clear input fields    
          document.getElementById('usernameInput').value = '';    
          document.getElementById('passwordInput').value = '';    
        }    
      } else {    
        alert('Please enter username and password.');    
      }    
    });    
        
    // Event listener for the "Register" button in the auth modal    
    document.getElementById('registerModalButton').addEventListener('click', async () => {    
      const username = document.getElementById('usernameInput').value.trim();    
      const password = document.getElementById('passwordInput').value;    
        
      if (username && password) {    
        const success = await register(username, password);    
        if (success) {    
          // Clear input fields    
          document.getElementById('usernameInput').value = '';    
          document.getElementById('passwordInput').value = '';    
        }    
      } else {    
        alert('Please enter username and password.');    
      }    
    });    
        
    // Display the correct sections when the page loads    
    document.addEventListener('DOMContentLoaded', () => {    
      loadTokens();    
      const authSection = document.getElementById('authSection');    
      const welcomeSection = document.getElementById('welcomeSection');    
        
      if (isAuthenticated()) {    
        hideSection(authSection);    
        showSection(welcomeSection);    
        
        const username = localStorage.getItem('username') || 'User';    
        document.getElementById('welcomeMessage').textContent = 'Welcome, ' + username + '!';    
      } else {    
        showSection(authSection);    
        hideSection(welcomeSection);    
      }    
    });    
  </script>    
</body>    
</html>    
```

   
   
## How It All Works Together  
   
1. **User Registration**: The user enters a username and password in the demo page, which sends a request to the `/register` endpoint. The API hashes the password and stores the user in MongoDB.  
   
2. **User Authentication**: When logging in, the demo page sends credentials to the `/authenticate` endpoint. The API verifies the credentials, generates JWT access and refresh tokens, and returns them to the demo page.  
   
3. **Accessing Protected Resources**: The demo page uses the access token to make authenticated requests to protected endpoints like `/protected`. If the access token is expired, it uses the refresh token to obtain a new access token via the `/refresh` endpoint.  
   
4. **Token Storage and Management**: Tokens are securely stored in the browser's local storage, and the demo page handles token expiration and refreshing transparently to the user.  
   
5. **Deployment with Modal**: Modal simplifies deployment by handling containerization and scaling. We define our environment and application in code, and Modal takes care of the rest.  
   
## Advantages of Using Modal  
   
- **Simplicity**: No need to manage servers or infrastructure; focus on writing your application.  
    
- **Scalability**: Modal automatically scales your application based on demand.  
    
- **Cost-Efficiency**: Pay only for the compute resources you use.  
    
- **Speed**: Quick deployment and instant scalability mean your application can be up and running in no time.  
   
## Conclusion  
   
Building a secure authentication system doesn't have to be daunting. By leveraging powerful tools like MongoDB, JWT, FastAPI, and Modal, we can create robust applications that scale seamlessly. 
   
**Next Steps**:  
   
- **Enhancements**: Add features like email verification, password reset, or multi-factor authentication.  
    
- **Security Audits**: Ensure that your application follows best security practices, such as rate limiting and input validation.  
    
- **Deployment**: Move from a development environment to a production-ready setup, possibly integrating with CI/CD pipelines.  
   
## Resources  
   
- [MongoDB Documentation](https://docs.mongodb.com/)  
- [JWT Introduction](https://jwt.io/introduction)  
- [FastAPI Documentation](https://fastapi.tiangolo.com/)  
- [Modal Documentation](https://modal.com/docs)  
   
---  
   
*Happy coding! Secure your applications and deliver robust solutions with ease.*

---

# modal-JWTauth-demo  
   
---  

# APPENDIX
   
### Security Best Practices  
   
- **Secure Token Storage**: Store tokens securely. In mobile and desktop apps, consider using secure storage mechanisms provided by the operating system.  
- **HTTPS**: Always use HTTPS to communicate with the API to prevent man-in-the-middle attacks.  
- **Token Handling**: Implement token refresh logic to handle expired access tokens.  
- **Error Handling**: Gracefully handle errors and provide appropriate feedback to the user without exposing sensitive information.  
   
   
### Advantages of API-First Approach  
   
- **Flexibility**: Clients can be built using different technologies (web, mobile, desktop).  
- **Scalability**: The API can scale independently of the client applications.  
- **Reusability**: The same API serves multiple clients, reducing development effort.  
   
### Conclusion  
   
Our authentication system is a robust, scalable solution that can be integrated into various types of applications. By decoupling the client from the server, we provide flexibility in how users interact with our services. Whether through a browser extension, web app, or mobile application, the core authentication logic remains consistent.  
   
---  
   
# APPENDIX

# APPENDIX

### Protecting API Routes

One of the primary goals of an authentication system is to secure specific API endpoints, ensuring that only authenticated and authorized users can access them. In our FastAPI application, this is elegantly achieved using FastAPI's Dependency Injection system and our `get_current_user` helper function.

The `get_current_user` function acts as a gatekeeper. It expects a valid JWT access token in the `Authorization: Bearer <token>` header. If the token is missing, invalid, or expired, it will raise an `HTTPException`, preventing the request from reaching your route's logic. If the token is valid, it extracts the `username` and passes it to your route function, allowing you to perform user-specific operations.

**How to Protect a Route:**

To protect any FastAPI endpoint, simply add `current_user: str = Depends(get_current_user)` as a parameter to your path operation function. FastAPI will automatically handle the dependency resolution and token validation.

**Sample Code: Protecting a `/protected-data` Endpoint**

Let's illustrate this by adding a new endpoint `/protected-data` that is only accessible to users who provide a valid access token.

First, you might want to add a simple Pydantic model for the response of your protected endpoint:

```python
# In modal-app.py, within the 'Pydantic Models' section
# ... (existing models) ...

class ProtectedDataResponse(BaseModel):
    message: str
    user: str
    access_timestamp: datetime.datetime
```

Then, add the actual protected endpoint to your FastAPI `web_app`:

```python
# In modal-app.py, below your authentication endpoints
# ... (existing authentication endpoints like /register, /authenticate, /refresh) ...

@web_app.get('/protected-data', response_model=ProtectedDataResponse, tags=["Protected Resources"])
def get_protected_data(current_user: str = Depends(get_current_user)):
    """
    Retrieves a sample message accessible only by authenticated users.
    The 'current_user' string is injected by the get_current_user dependency.
    """
    return {
        "message": f"Hello {current_user}! You have successfully accessed a protected resource.",
        "user": current_user,
        "access_timestamp": datetime.datetime.utcnow()
    }
```

**Explanation:**

* **`@web_app.get('/protected-data', ...)`**: This defines a new GET endpoint at the `/protected-data` path.
* **`current_user: str = Depends(get_current_user)`**: This is the key line for protection.
    * FastAPI will first call `get_current_user`.
    * If `get_current_user` encounters any issues (e.g., missing/invalid/expired token), it will raise an `HTTPException` (e.g., 401 Unauthorized), and FastAPI will immediately return that error to the client. The `get_protected_data` function will *not* be executed.
    * If `get_current_user` successfully decodes a valid access token, it will return the `username` from the token's payload. This `username` is then passed as the `current_user` argument to your `get_protected_data` function.
* **Response**: The function then returns a dictionary that FastAPI automatically converts into a JSON response, including the authenticated `username` and the time of access.

**How to Test This Protected Endpoint:**

1.  **Deploy your Modal App:** Ensure your `modal-app.py` (with the new protected route) is deployed:
    ```bash
    modal deploy modal-app.py
    ```
2.  **Log In via `index.html`:** Use your `index.html` page to register and log in a user. Once logged in, your browser's local storage will contain the `accessToken` and `refreshToken`.
3.  **Make an Authenticated Request:** You can use your browser's developer console or a tool like Postman/Insomnia/cURL to make a request to the protected endpoint.

    * **Successful Request (with valid token):**
        ```bash
        curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE" \
             https://<your-modal-app-base-url>/protected-data
        ```
        (Replace `YOUR_ACCESS_TOKEN_HERE` with the token obtained after login, and `<your-modal-app-base-url>` with the actual URL from your Modal deployment).

        You should receive a `200 OK` response with the protected message.

    * **Unauthenticated Request (no token or invalid token):**
        ```bash
        curl https://<your-modal-app-base-url>/protected-data
        ```
        or
        ```bash
        curl -H "Authorization: Bearer an_invalid_token" \
             https://<your-modal-app-base-url>/protected-data
        ```

        You should receive a `401 Unauthorized` response, as the `get_current_user` dependency will prevent access.

By following this pattern, you can easily secure any number of endpoints in your FastAPI application, ensuring that only authenticated users can access sensitive resources or perform privileged actions.
