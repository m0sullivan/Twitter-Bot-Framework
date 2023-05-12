import csv
import time
import os
import requests
import yaml
import json
import random
from flask import Flask, request, jsonify
from passlib.hash import pbkdf2_sha256
import multiprocessing as mp
import hashlib
from bs4 import BeautifulSoup
import werkzeug
import flask
import api
import upload


# Template for storing all of the settings of a specific twitter account
class Account:
    def __init__(self,
        name,
        authorization,
        guest_id,
        proxy,
        auth_token,
        ct0,
        gt,
        twid,
        userAgent,
        kdt,
        timeAdded,
        range,
        delete
    ):

        self.name = name # Name of Twitter account
        self.authorization = authorization
        self.guest_id = guest_id
        self.proxy = proxy # Proxy domain name
        self.auth_token = auth_token # Auth token 
        self.ct0 = ct0
        self.gt = gt
        self.twid = twid
        self.userAgent = userAgent
        self.kdt = kdt
        self.timeAdded = timeAdded
        self.range = range
        self.delete = delete
        print(f"INITIALIZING {name}")

"""
Calculates time for next tweet upload

c = current time (in seconds)
h = num hours until next tweet (in hours)
r = randomness added to the end result for variation (in hours)
"""
def calculateNextTweetTime(c, h, r):
    try:
        x = c + (h * 3600) + ((random.randrange((r * -1), r) * 3600))
    except:
        x = c + (h * 3600)
    return x


# Reads through account information and adds it to queue of accounts to post from
def readAccounts(accountDict, nextTweetDict, filelistDict, hoursDict):
    for i in os.listdir("./configs/"):
        with open(f"./configs/{i}", "r") as file:
            template = yaml.safe_load(file)

            if template["name"] not in accountDict and template["deactivate"] != 1:
                timeAdded = time.time()
                accountDict[template["name"]] = Account(
                    name=template["name"],
                    authorization=template["authorization"],
                    guest_id=template["guest_id"],
                    proxy=template["proxy"],
                    auth_token=template["auth_token"],
                    ct0=template["ct0"],
                    gt=template["gt"],
                    twid=template["twid"],
                    userAgent=template["user-agent"],
                    kdt=template["kdt"],
                    timeAdded=timeAdded,
                    range=template["range"],
                    delete=template["delete"]
                )

                hoursDict[template["name"]] = template["hours"]

                filelistDict[template["name"]] = api.getList(template["name"])

                nextTweetDict[template["name"]] = calculateNextTweetTime(timeAdded, hoursDict[template["name"]], template["range"])

                print(f"Next Tweet of {template['name']}: {nextTweetDict[template['name']]}")

            elif template["name"] in accountDict and template["deactivate"] == 1:
                accountDict.remove(template["name"])


# Checks if every account should tweet or not
def checkTweets(accountDict, nextTweetDict, filelistDict, hoursDict):
    print("Checking for tweets...")
    for i in accountDict:
        filelistDict[i] = api.getList(i)
        if nextTweetDict[i] < time.time() and len(filelistDict[i]) > 0:
            print("Making Tweet...")
            makeTweet(accountDict, i, filelistDict)  
            nextTweetDict[i] = calculateNextTweetTime(time.time(), hoursDict[i], accountDict[i].range)
            print(f"Next tweet of {i}: {nextTweetDict[i]}")
        


def makeTweet(accountDict, name, filelistDict):
    idx = random.randint(0, len(filelistDict[name]) - 1)
    file = filelistDict[name][idx]
    try:
        with open(f"./media/{name}/{file}", "rb") as md:
            
            md_bytes = md.read()
            md_size = len(md_bytes)

            if md_size > 4000000 or file.endswith(".mp4") or file.endswith(".gif"):
                print("CHUNKED UPLOAD")
                upload.chunkedUpload(
                    authorization=accountDict[name].authorization,
                    guest_id=accountDict[name].guest_id,
                    gt=accountDict[name].gt,
                    ct0=accountDict[name].ct0,
                    kdt=accountDict[name].kdt,
                    twid=accountDict[name].twid,
                    auth_token=accountDict[name].auth_token,
                    userAgent=accountDict[name].userAgent,
                    name=name,
                    md=md,
                    md_bytes=md_bytes,
                    md_size=md_size,
                    file=file
                )
            else:
                print("REGULAR UPLOAD")
                upload.regularUpload(
                    authorization=accountDict[name].authorization,
                    gt=accountDict[name].gt,
                    ct0=accountDict[name].ct0,
                    kdt=accountDict[name].kdt,
                    twid=accountDict[name].twid,
                    auth_token=accountDict[name].auth_token,
                    userAgent=accountDict[name].userAgent,
                    name=name,
                    md=md,
                    md_bytes=md_bytes,
                    md_size=md_size,
                    file=file
                )

            print("TWEET DONE")
                    
    except:
        print("ERROR UPLOADING")

    try:
        del filelistDict[name][idx]
        print("DELETE FROM MEMORY DONE")
    except:
        print("ERROR DELETING FROM MEMORY")

    if int(accountDict[name].delete) == 1:
        try:
            os.remove(f"./media/{name}/{file}")
            print("DELETE FILE LOCALLY DONE")
        except:
            print("ERROR DELETING FILE LOCALLY")

    

app = Flask(__name__)

@app.route("/getData", methods=["GET"])
def getData():
    try:
        if pbkdf2_sha256.verify(request.headers["Password"], pHash) == True:
            name = str(request.headers["AccountName"])
            with open(f"./configs/{name}.yml") as conf:
                template = yaml.safe_load(conf)
            return api.getData(
                request=request,
                pHash=pHash,
                hours=template["hours"],
                deactivate=template["deactivate"]
            )
        else:
            returnCode = "INCORRECT PASSWORD"
            api.logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/getAccounts", methods=["GET"])
def getAccounts():
    try:
        return api.getAccounts(request, pHash)
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode
    
@app.route("/newConfig", methods=["POST"])
def newConfig():
    try:
        return api.newConfig(request, pHash)
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/likeTweet", methods=["POST"])
def likeTweet():
    try:
        name = str(request.headers["AccountName"])
        return api.likeTweet(
            request=request,
            authorization=accounts[name].authorization,
            guest_id=accounts[name].guest_id,
            ct0=accounts[name].ct0,
            kdt=accounts[name].kdt,
            twid=accounts[name].twid,
            auth_token=accounts[name].auth_token,
            gt=accounts[name].gt,
            userAgent=accounts[name].userAgent,
            pHash=pHash
        )
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

def multiLikeHelper(
    request,
    accountDict,
    pHash
):
    head = request.headers
    data = request.data

    for i in accountDict.keys():
        api.likeTweet(
            request=request,
            authorization=accountDict[i].authorization,
            guest_id=accountDict[i].guest_id,
            ct0=accountDict[i].ct0,
            kdt=accountDict[i].kdt,
            twid=accountDict[i].twid,
            auth_token=accountDict[i].auth_token,
            gt=accountDict[i].gt,
            userAgent=accountDict[i].userAgent,
            pHash=pHash
        )
        time.sleep(random.randint(30, 120))


@app.route("/multiLike", methods=["POST"])
def multiLike():
    try:
        if pbkdf2_sha256.verify(request.headers["Password"], pHash) == True:
            head = request.headers
            data = request.data
            
            found = False
            with open("./logfile.log") as f:
                lines = f.readlines()
            for i in lines[-10000:]:
                reg = re.findall(f"{head['TweetID']}", i)
                if reg != []:
                    found = True
                    break
            if found == True:
                returnCode = "TWEETID RECENTLY USED"
                api.logInfo(request.headers, request.remote_addr, returnCode)
                return returnCode
            else:
                pMultiLike = mp.Process(target=multiLikeHelper, args=(
                    request, accounts, pHash
                ))
                pMultiLike.start()
                returnCode = "OK"
                api.logInfo(request.headers, request.remote_addr, returnCode)
                return returnCode
            
        else:
            returnCode = "INCORRECT PASSWORD"
            api.logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/deleteTweet", methods=["POST"])
def deleteTweet():
    try:
        name = str(request.headers["AccountName"])
        return api.deleteTweet(
            request=request,
            authorization=accounts[name].authorization,
            guest_id=accounts[name].guest_id,
            ct0=accounts[name].ct0,
            kdt=accounts[name].kdt,
            twid=accounts[name].twid,
            auth_token=accounts[name].auth_token,
            gt=accounts[name].gt,
            userAgent=accounts[name].userAgent,
            pHash=pHash
        )
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/stop", methods=["POST"])
def stop():
    try:
        if pbkdf2_sha256.verify(head["Password"], pHash) == True:
            returnCode = api.stop(request, pHash)
            nextTweet[request.headers["AccountName"]] = 999999999999999999999999999999999999
            accounts[request.headers["AccountName"]].deactivate = 1
            return returnCode
        else:
            returnCode = "INCORRECT PASSWORD"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/restart", methods=["POST"])
def restart():
    try:
        if pbkdf2_sha256.verify(head["Password"], pHash) == True:
            returnCode = api.restart(request, pHash)
            nextTweet[request.headers["Name"]] = calculateNextTweetTime(
                time.time(),
                hoursDict[request.headers["Name"]],
                accounts[request.headers["Name"]].range
            )
            print(nextTweet[request.headers["Name"]])
            return returnCode
        else:
            returnCode = "INCORRECT PASSWORD"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/changeRate", methods=["POST"])
def changeRate():
    try:
        if pbkdf2_sha256.verify(head["Password"], pHash) == True:
            hoursDict[request.headers["AccountName"]] = request.headers['Hours']
        else:
            returnCode = "INCORRECT PASSWORD"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode
    except:
        print("ERROR CHANGING RATE")
    try:
        return api.changeRate(request, pHash)
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/media/mediaUpload", methods=["POST"])
def mediaUpload():
    try:
        return api.mediaUpload(request, pHash)
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/media/mediaDelete", methods=["POST"])
def mediaDelete():
    try:
        return api.mediaDelete(request, pHash)
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/media/getMedia", methods=["GET"])
def getMedia():
    try:
        return api.getMedia(request, pHash)
    except:
        returnCode = "ERROR (probably because the directory doesn't exist, if the name of the account is correct, try retrieving again to make an empty directory)"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/media/openMedia", methods=["GET"])
def openMedia():
    try:
        return api.openMedia(request, pHash)
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/")
def root():
    try:
        p = request.cookies.get("p")
        if pbkdf2_sha256.verify(p, pHash) == True:
            return open("./index.html", "rb")
    except:
        return open("./login.html", "rb")
    return open("./login.html", "rb") 

@app.route("/passCheck")
def passCheck():
    head = request.headers
    data = request.data
    try:
        if pbkdf2_sha256.verify(head["Password"], pHash) == True:
            return "OK"
        else:
            return "INCORRECT PASSWORD"
    except:
        return "ERROR"

@app.route("/bot")
def bot():
    try:
        p = request.cookies.get("p")
        if pbkdf2_sha256.verify(p, pHash) == True:
            return open("./bot.html", "rb")
    except:
        return open("./login.html", "rb")
    return open("./login.html", "rb") 

@app.route("/media")
def media():
    try:
        p = request.cookies.get("p")
        if pbkdf2_sha256.verify(p, pHash) == True:
            return open("./media.html", "rb")
    except:
        return open("./login.html", "rb")
    return open("./login.html", "rb") 

with open("./shadow.yml", "r") as f:
    template = yaml.safe_load(f)
    pHash = template["main"]

def startTerm():
    app.run('0.0.0.0', debug=False, port=42874, use_reloader=False, ssl_context=("./server.crt", "./server.key"))


manager = mp.Manager()
accounts = manager.dict()
nextTweet = {}
filelistDict = {}
hoursDict = {}

def startBot():
    print("INITIALIZED")
    while True:
        try:
            readAccounts(accounts, nextTweet, filelistDict, hoursDict)
        except:
            print("ERROR READACCOUNTS")
        try:
            checkTweets(accounts, nextTweet, filelistDict, hoursDict)
        except:
            print(f"ERROR CHECKTWEETS")
        time.sleep(10)


if __name__ == "__main__":
    p = mp.Process(target=startTerm)
    p.start()
    startBot()
    
with open("./shadow.yml", "r") as f:
    template = yaml.safe_load(f)
    pHash = template["main"]