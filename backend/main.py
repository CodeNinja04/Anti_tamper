from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Request,status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from hashing import Hash
from pymongo import MongoClient
from jwttoken import create_access_token
from oauth import get_current_user
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os
from jose import jws
#from uuid import UUID
import uuid
load_dotenv()

app = FastAPI()
origins = [
    "http://localhost:3000",
    "http://localhost:8080",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


mongodb_uri = os.getenv('MONGO_URI')
port = 8000
client = MongoClient(mongodb_uri, port)
db = client["User"]
db_contract = client["Contract"]
db_contract_form =client["ContractForm"]


class User(BaseModel):
    username: str
    email : str
    name: str
    password: str
    
class Login(BaseModel):
	username: str
	password: str
class Token(BaseModel):
    access_token: str
    token_type: str
class TokenData(BaseModel):
    username: Optional[str] = None
    
 
class ContractForm(BaseModel):
    contract:str
    #contract_id:UUID

class Contract(BaseModel):
    contract_id :str
    usernameA : str
    usernameB : str
    signatureA : str
    signatureB: str
    contract: str
    hash_contractA:str
    hash_contractB:str

class Sign(BaseModel):
    createdby: str
    createdfor: str
    contract : str
    username: str
    password: str
    signtype : bool
    #signature : str
    contract_id : str
    
    

    


@app.get("/")
def read_root(current_user:User = Depends(get_current_user)):
	return {"data":"Hello OWrld"}

@app.post('/register')
def create_user(request:User):
    
    user = db["users"].find_one({"username": request.username})
    if not user:
        hashed_pass = Hash.bcrypt(request.password)
        user_object = dict(request)
        user_object["password"] = hashed_pass
        user_id = db["users"].insert(user_object)
	# print(user)
        return {"res":"created"}
    else:
        return {"error":"username already exists"}

@app.post('/login')
def login(request:OAuth2PasswordRequestForm = Depends()):
	user = db["users"].find_one({"username":request.username})
	if not user:
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail = f'No user found with this {request.username} username')
	if not Hash.verify(user["password"],request.password):
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail = f'Wrong Username or password')
	access_token = create_access_token(data={"sub": user["username"] })
	return {"access_token": access_token, "token_type": "bearer"}


@app.post("/contract/new")
def create_contract( request: ContractForm = Depends()):
    contract_is = dict(request)
    contract_is["contract_id"] = str(uuid.uuid4())
    contract_is = db["ContractForm"].insert(contract_is)
    return {"output": "created"}




@app.post("/contract/{id}/signa")
def sign(id: str,request:Sign):
    
    user = db["users"].find_one({"username":request.username})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail = f'No user found with this {request.username} username')
    if not Hash.verify(user["password"],request.password):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail = f'Wrong Username or password')
    
    signed = jws.sign({"contract": request.contract}, request.password, algorithm='HS256')
    sign_object = dict(request)
    hashed_pass = Hash.bcrypt(request.password)
    sign_object["password"] = hashed_pass
    sign_object["signatureA"]= signed
    sign_object["contract_form"]=id
    db["Contract"].insert(sign_object)
    
    return {"message":"you signed the contract"}


@app.post("/contract/{id}/signb")
def sign(id: str,request: Sign):

    user = db["users"].find_one({"username": request.username})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f'No user found with this {request.username} username')
    if not Hash.verify(user["password"], request.password):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f'Wrong Username or password')

    signed = jws.sign({"contract": request.contract},
                      request.password, algorithm='HS256')

    sign_object = dict(request)
    hashed_pass = Hash.bcrypt(request.password)
    sign_object["password"] = hashed_pass
    sign_object["signatureB"] = signed
    sign_object["contract_form"] = id
    db["Contract"].insert(sign_object)

    return {"message": "you signed the contract"}


@app.post("/contract/verify")
def verify(request:Contract):
    
    contract_id = db["ContractForm"].find_one({"contract_id":request.contract_id})
    
    if contract_id:
        verify=dict(request)
        if(request.signatureA and request.signatureB):
            
            #logic for verification
            
            verificationA=jws.verify(request.signatureA, 'secret', algorithms=['HS256'])
            verificationB = jws.verify(
                request.signatureB, 'secret', algorithms=['HS256'])
        else:
            return {"message" :"contract is not signed by both parties"}
    else:
        return {"error":"no contract with this id is aavialble pls check contract id"}
    

