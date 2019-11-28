
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import Mongoclient
import bcrypt
import requests
import subprocess
import json

app = Flask(__name__)

api= Api(app)
client= Mongoclient("mongodb://db:27017")
db =client.ImageRecognition
users=db["Users"]
def UserExit(username):
    if users.find({"Username":username}).count()==0:
        return False
    else:
        return True

    class Register(Resource):
        def post(self):
            postedData=request.get_json()
            username=postedData["username"]
            password=postedData["password"]

            if userExit(username):

                retjson= {
                    "status":301,
                    "msg":" Invalid Username"
                }
                return jsonify(retjson)
            hasedpw=bcrypt.hashpw(password.encode("utf8")),bcrypt.gensalt()
            users.insert(
                {
                    "username": username,
                    "password": hasedpw,
                    "Tokens":4
                }
            )
            retjson={
                "status":200,
                "msg": "You successfully signup for Api"
            }
            return jsonify(retjson)

        def verify_pw(username, password, Username):
            if not userExit(username):
                return False
            hashed_pw=users.find(
                {"username": username})[0]["password"]
            if bcrypt.hashpw(password.encode('utf8'),hashed_pw)==hashed_pw:
                return True
            else:
                return False
            def generateReturnDictionary(status,msg):
                retjson={
                    "status":status,
                    "msg": msg
                }

                return retjson
            def verifyCredentials(username, password):
                if not userExit(username):
                    return generateReturnDictionary(301, "Invalid Username"), True
                correct_pw= username.verify_pw(username, password)
                if not correct_pw:
                    return generateReturnDictionary(302, "Invalid Password"),True
                return None, False








            class classify(Resource):
                def post(self):
                    postedData=request.get_json()
                     username=postedData["username"]
                     Password=postedData["password"]
                      ur  = postedData["url"]

                     retjson error= verifyCredentials(username,password)
                if error:
                    return jsonify(retJson)
        tokens=users.find({
            "username": username
        })[0]["Tokens"]
        
        if tokens<=0:
            return jsonify( generateReturnDictionary(303,"Not enough Token!"))
        r=requests.get(url)
        retjson={}
        with open("temp.jpg","wt") as f:
            f.write(r.content)
            proc= subprocess.popen('python classify_image.py  --model_dir= .--image_file=./temp.jpg')
            proc.communicate()[0]
            proc.wait()
            with open("text.txt") as g:
                retJson=json.load(g)
                users.update({
                    "Username": users
                }, {
                    "$set":{
                        "Tokens": tokens-1
                    }
                })

                return retJson

            class Refill(Resource):
                def post(self, generateReturnDictionary, userExist):
                    postedData=request.get_json()

                    username=postedData["username"]
                    password=postedData["admin_pw"]
                    amount=postedData["amount"]
                    if not userExist(username):
                        return jsonify(generateReturnDictionary(301, "Invalid username"))
                    correct_pw="abc123"
                    if not password== correct_pw:
                        return jsonify(generateReturnDictionary(304,"Invalid Administration password"))
      users.update({
          "Username": username

      },
          {"$set":{
           "tokents":amount
           }
})


return jsonify( generateReturnDictionary(200, "Refilled Successfully"))


api.add_resource(Register,'/register')
api.add_resource(classify,'/classify')
api.add_resource(Refill,'/refill')

if __name__ == '__main__':
    app.run(host='0.0.0.0')
