"# Anti_tamper" 

<p>This app is to make contract between two parties using cryptographic algorithms</p>
so you can create the contract then both the parties sign the contract using jws and secret key used is encrypted by AES and at the time of signing we will decrypt it using a key which is there in .env file. Now signature is created after that we will hash the contract . Now there is verification function in which it will verify the contracts of both the parties and compare the hash of both the parties If it is equal then we will verify the contract


<h3>TECH STACK </h3>
1.FASTAPI
2.MONGODB

<h3>ALGORITHM USED </h3>
1.AES --> to encrypt user password
2.HS256 --> It is used in digital signature
3.SHA256 --> Used to  create hash for the contract 

<h3>HOW TO RUN </h3>

1. Clone the repo
2. cd backend
3. venv env
4. source env/Scripts/activate  (if using bash)
5. uvicorn main:app --reload
6. go to http://localhost:8000/docs 




