<h2>Anti_tamper</h2> 

<p>This app is to make contract between two parties using cryptographic algorithms</p>
so you can create the contract then both the parties sign the contract using jws and secret key used is encrypted by AES and at the time of signing we will decrypt it using a key which is there in .env file. Now signature is created after that we will hash the contract . Now there is verification function in which it will verify the contracts of both the parties and compare the hash of both the parties If it is equal then we will verify the contract


<h3>TECH STACK </h3>
<ul>FASTAPI</ul>
<ul>MONGODB</ul>


<h3>ALGORITHM USED </h3>
<li>
<ul>AES --> to encrypt user password</ul>
<ul>HS256 --> It is used in digital signature</ul>
<ul>SHA256 --> Used to  create hash for the contract </ul>
</li>

<h3>HOW TO RUN </h3>

<ul> Clone the repo</ul>
<ul> cd backend</ul>
<ul> venv env</ul>
<ul> source env/Scripts/activate  (if using bash)</ul>
<ul> uvicorn main:app --reload</ul>
<ul> go to http://localhost:8000/docs </ul> 




