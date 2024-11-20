from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel

from fastapi import HTTPException, FastAPI, Response, Depends
from uuid import UUID, uuid4

from fastapi_sessions.backends.implementations import InMemoryBackend
from fastapi_sessions.session_verifier import SessionVerifier
from fastapi_sessions.frontends.implementations import SessionCookie, CookieParameters




from fastapi.responses import FileResponse

from dotenv import load_dotenv




from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Form, HTTPException, Request, Response
from passlib.context import CryptContext
import mysql.connector
import uuid
# from typng import Optional
from datetime import datetime, timedelta
from fastapi.responses import JSONResponse
# Import the Python SDK

# Used to securely store your API key
#   


# import confluencePermisson
# import permissionatpages
# import permissionspacelevel
# import openai


from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.responses import FileResponse

import os
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv


from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from fastapi import FastAPI, Form, HTTPException, Request, Response
from passlib.context import CryptContext
import mysql.connector
import uuid
# from typng import Optional

class SessionData(BaseModel):
    email: str
    password: str


cookie_params = CookieParameters(
    httponly=True,
    samesite="lax",  # Adjust to 'none' if you expect cross-origin requests
    secure=False,    # Set to True if using HTTPS
)


cookie = SessionCookie(
    cookie_name="cookie",
    identifier="general_verifier",
    auto_error=True,
    secret_key="8668115688",
    cookie_params=cookie_params,
)
backend = InMemoryBackend[UUID, SessionData]()



class BasicVerifier(SessionVerifier[UUID, SessionData]):
    def __init__(
        self,
        *,
        identifier: str,
        auto_error: bool,
        backend: InMemoryBackend[UUID, SessionData],
        auth_http_exception: HTTPException,
    ):
        self._identifier = identifier
        self._auto_error = auto_error
        self._backend = backend
        self._auth_http_exception = auth_http_exception

    @property
    def identifier(self):
        return self._identifier

    @property
    def backend(self):
        return self._backend

    @property
    def auto_error(self):
        return self._auto_error

    @property
    def auth_http_exception(self):
        return self._auth_http_exception

    def verify_session(self, model: SessionData) -> bool:
        """If the session exists, it is valid"""
        return True
    

verifier = BasicVerifier(
    identifier="general_verifier",
    auto_error=True,
    backend=backend,
    auth_http_exception=HTTPException(status_code=403, detail="invalid session"),
)


app = FastAPI()

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

@app.get("/")
def get_index():
    return FileResponse('sessions_login.html')




from fastapi import HTTPException

class UserCredentials(BaseModel):
    email: str
    password: str

@app.post("/checkCookies")
async def checkCookies(request: Request, response: Response):
    try:
        # Parse JSON body
        body = await request.json()
        email = body.get('email')
        password = body.get('password')
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        query = "SELECT * FROM registration WHERE email = %s "
        cursor.execute(query, (email,))
        user = cursor.fetchone()

        if user is None or not verify_password(password, user["password"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        print(f"this is user details{user}")
        

        print(f"email: {email}")
        print(f"Password: {password}")
    
        session = uuid4()  
        data = SessionData(email=email, password=password)  
        await backend.create(session, data) 
        cookie.attach_to_response(response, session)

        return {"message": "successful"}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {"message": str(e)}
    


@app.get("/whoami", dependencies=[Depends(cookie)])
async def whoami(session_data: SessionData = Depends(verifier)):
    if session_data is None:
        raise HTTPException(status_code=401, detail="Session is invalid or expired")
    return {"userDetails": session_data}


@app.post("/delete_session")
async def del_session(response: Response, session_id: UUID = Depends(cookie)):
    await backend.delete(session_id)
    cookie.delete_from_response(response)
    return "deleted session"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="admin123",
        database="rag"
    )

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)




import sent_otp

class EmailRequest(BaseModel):
    email: str

# @app.post('/get_otp')
# async def get_otp(email_request: EmailRequest):
#     try:
#         email = email_request.email
#         print(f"Received email: {email}")
        
#         # Assuming sent_otp.send_email() takes an email parameter
#         mail_status = sent_otp.send_email(email) 
#         if "Failed" in mail_status:
#             raise HTTPException(status_code=500, detail=mail_status)

#         # Store OTP and its expiry time in sessions
#         sessions['otp'] = {
#             'value': mail_status['otp'],
#             'expiry': datetime.now() + timedelta(minutes=1)  # OTP expires in 1 minute
#         }
        
#         print(f"sessions at last {sessions}")
#         return {'mail_status': "OTP sent to your email!"}
    
#     except Exception as e:
#         raise HTTPException(status_code=500, detail="An error occurred while sending OTP.")


