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
from Crypto.Cipher import AES

from sha256 import *;
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
    private : str
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
    contract_id:str
    userA: str
    userB: str

class Contract(BaseModel):
    #contract_id :str
    usernameA : str
    usernameB : str
    # signatureA : str
    # signatureB: str
    # contract: str
    # hash_contractA:str
    # hash_contractB:str

class Sign(BaseModel):
    # createdby: str
    # createdfor: str
    #contract : str
    username: str
    password: str
    #contract_id : str
    
    
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
        
        # encrypt user secret
        key= bytes(os.getenv("SECRET_KEY1"),"utf-8")
        print(key)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(bytes(request.private,"utf-8"))
        print(ciphertext)
        nonce=cipher.nonce
        user_object["private"]=ciphertext
        user_object['nonce']=nonce
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
    #contract_is["contract_id"] = str(uuid.uuid4())
    contract_is = db["ContractForm"].insert(contract_is)
    return {"output": "created"}



@app.post("/contract/{id}/signa")
def sign(id: str,request:Sign):
    
    user = db["users"].find_one({"username":request.username})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail = f'No user found with this {request.username} username')
    if not Hash.verify(user["password"],request.password):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail = f'Wrong Username or password')
    
    contract = db["ContractForm"].find_one({"contract_id":id})
    if(contract):
        
        ciphertext=(user["private"])
        print(ciphertext)
        nonce=user["nonce"]
        print(nonce)
        key= bytes(os.getenv("SECRET_KEY1"),"utf-8")
        cipher1 = AES.new(key, AES.MODE_EAX, nonce)
        
        private = cipher1.decrypt(ciphertext)
        print(private)
        signed = jws.sign({"contract": contract["contract"]}, private.decode("utf-8"), algorithm='HS256')
        sign_object = dict(request)
        hashed_pass = Hash.bcrypt(request.password)
        sign_object["contract"] =contract["contract"] 
        sign_object["password"] = hashed_pass
        sign_object["signatureA"]= signed
        sign_object["createdBy"] = contract["userA"]
        sign_object["createdfor"] = contract["userB"]
        sign_object["flag"] = True
        sign_object["contract_id"]=id
        db["Contract"].insert(sign_object)
    
        return {"message":"you signed the contract.signatureA completed"}
    else:
        return {"error":"contract doesnt exists"}



@app.post("/contract/{id}/signb")
def sign(id: str,request:Sign):
    
    user = db["users"].find_one({"username":request.username})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail = f'No user found with this {request.username} username')
    if not Hash.verify(user["password"],request.password):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail = f'Wrong Username or password')
    
    contract = db["ContractForm"].find_one({"contract_id":id})
    if(contract):
        ciphertext = (user["private"])
        print(ciphertext)
        nonce = user["nonce"]
        print(nonce)
        key = bytes(os.getenv("SECRET_KEY1"), "utf-8")
        cipher1 = AES.new(key, AES.MODE_EAX, nonce)
        private = cipher1.decrypt(ciphertext)
        print(private)
        signed = jws.sign({"contract": contract["contract"]}, private.decode("utf-8"), algorithm='HS256')
        sign_object = dict(request)
        hashed_pass = Hash.bcrypt(request.password)
        sign_object["contract"] =contract["contract"]
        sign_object["password"] = hashed_pass
        sign_object["signatureB"]= signed
        sign_object["createdBy"] = contract["userA"]
        sign_object["createdfor"] = contract["userB"]
        sign_object["flag"] = False
        sign_object["contract_id"]=id
        db["Contract"].insert(sign_object)
    
        return {"message":"you signed the contract.signatureB completed"}
    else:
        return {"error":"contract doesnt exists"}


@app.post("/contract/{id}/verify")
def verify(id: str,request: Contract):
    
    contract_id = db["ContractForm"].find_one({"contract_id":id})
    
    #print(contract_id["contract"])
    verify=dict(request)
    # contract=dict(contract_id)
    # return {"result":"done"}
    
    if (contract_id):
        
        if(True):
       
            
            
            contractA = db["Contract"].find_one({"flag":True,"contract_id":id})
           
            
            contractB = db["Contract"].find_one(
                {"flag": False, "contract_id": id})

            userA = db["users"].find_one({"username": contractA["username"]})
            userB = db["users"].find_one({"username": contractB["username"]})
            
            ciphertext1=userA["private"]
            nonce1=userA["nonce"]
            key= bytes(os.getenv("SECRET_KEY1"),"utf-8")
            cipher1 = AES.new(key, AES.MODE_EAX, nonce1)
            private1 = cipher1.decrypt(ciphertext1)
            
            ciphertext2=userB["private"]
            nonce2=userB["nonce"]
            cipher2 = AES.new(key, AES.MODE_EAX, nonce2)
            private2 = cipher2.decrypt(ciphertext2)

          
            verify["contract_id"]=contractA["contract_id"]
            verify["contractA"]=contractA["contract"]
            verify["contractB"]=contractB["contract"]
            
            # hashing algorithm d
            hash_contractA=sha256(contractA["contract"])
            hash_contractB=sha256(contractB["contract"])
            print(hash_contractA,hash_contractB)
            verify_hash= str(hash_contractA==hash_contractB)
            #print(verify_hash)
            verify["verified_hash"]=verify_hash
           
            signatureA_verify = jws.verify(
                contractA["signatureA"],private1.decode("utf-8") , algorithms=['HS256'])
            signatureB_verify = jws.verify(
                contractB["signatureB"], private2.decode("utf-8"), algorithms=['HS256'])
            
            verify["signatureA_verified"]=signatureA_verify
            verify["signatureB_verified"]=signatureB_verify
            verify["contractDone"] = str(signatureA_verify == signatureB_verify)
            db["VerifiedContract"].insert(dict(verify))
            print(verify)
            return {"result":verify}
        
            
            # verificationA=jws.verify(request.signatureA, 'secret', algorithms=['HS256'])
            # verificationB = jws.verify(
            #     request.signatureB, 'secret', algorithms=['HS256'])
        else:
            return {"message" :"contract is not signed by both parties"}
    else:
        return {"error":"no contract with this id is aavialble pls check contract id"}
    
    
    
@app.get("/contract/{id}")
def get_contract(id:str):
    res={}
    contract=db["ContractForm"].find_one({"contract_id":id})
    print(contract)
    res["contract"]=contract["contract"]
    res["userA"]=contract["userA"]
    res["userB"]=contract["userB"]
    #contract=dict(contract)
    return {"result":res}


@app.get("/contractA/{id}")
def get_contractA(id:str):
    res={}
    contractA = db["Contract"].find_one({"flag": True, "contract_id": id})
    res["username"]=contractA["username"]
    res["contract"]=contractA["contract"]
    res["createdby"]=contractA["createdBy"]
    res["signatureA"]=contractA["signatureA"]
    res["cretedfor"]=contractA["createdfor"]
    res["flag"]=contractA["flag"]
    res["contract_id"]=contractA["contract_id"]
    return {"result":res}
    

@app.get("/contractB/{id}")
def get_contractA(id:str):
    res={}
    contractB = db["Contract"].find_one({"flag": False, "contract_id": id})
    res["username"]=contractB["username"]
    res["contract"]=contractB["contract"]
    res["createdby"]=contractB["createdBy"]
    res["cretedfor"]=contractB["createdfor"]
    res["flag"]=contractB["flag"]
    res["contract_id"]=contractB["contract_id"]
    return {"result": res}


@app.get("/contract/{id}/verify")
def get_contractA(id: str):
    res={}
    contract = db["VerifiedContract"].find_one({"contract_id": id})
    
    
    res["userA"]=contract["usernameA"]
    res["userB"]=contract["usernameB"]
    res["contractA"]=contract["contractA"]
    res["contractB"]=contract["contractB"]
    res["verified_hash"] = contract["verified_hash"]
    res["signatureA_verified"] = contract["signatureB_verified"]
    res["signatureB_verified"] = contract["signatureB_verified"]
    res["contractDone"]=contract["contractDone"]
    return {"result": res}
