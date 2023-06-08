import csv
import time
import os
import requests
import yaml
import json
import random
from flask import Flask, request, jsonify, render_template, redirect, url_for, send_file
from passlib.hash import pbkdf2_sha256
import multiprocessing as mp
import hashlib
from bs4 import BeautifulSoup
import werkzeug
import flask
import api
import upload
from datetime import datetime
import re
import math
import sqlite3
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key
import base64
from io import BytesIO
import zipfile
import glob


con = sqlite3.connect("database.db", check_same_thread=False)
cur = con.cursor()

cur.execute("CREATE TABLE if not exists keys(name VARCHAR UNIQUE, key, permissions);")
cur.execute("CREATE TABLE if not exists accounts(name VARCHAR UNIQUE, proxy, guest_id, auth_token, ct0, gt, twid, userAgent, kdt, timeAdded, cookie, hours, range, rm, deactivate);")
cur.execute("CREATE TABLE if not exists tweetdeckAccounts(name VARCHAR UNIQUE, guest_id, auth_token, ct0, gt, twid, userAgent, kdt, timeAdded, cookie);")
con.commit()


# Template for storing all of the settings of a specific twitter account
class Account:
    def __init__(self,
        name,
        guest_id,
        auth_token,
        ct0,
        gt,
        twid,
        userAgent,
        kdt,
        timeAdded,
        rm,
    ):

        self.name = name # Name of Twitter account
        self.guest_id = guest_id
        self.auth_token = auth_token # Auth token 
        self.ct0 = ct0
        self.gt = gt
        self.twid = twid
        self.userAgent = userAgent
        self.kdt = kdt
        self.timeAdded = timeAdded
        self.rm = rm
        print(f"INITIALIZING {name}")

class AutolikeDict:
    def __init__(self,
        name,
        accounts,
        isRandom,
        lastTweet,
    ):

        self.name = name
        self.accounts = accounts
        self.isRandom = isRandom
        self.lastTweet = lastTweet

class TweetdeckAccount:
    def __init__(self,
        name,
        guest_id,
        auth_token,
        ct0,
        gt,
        twid,
        userAgent,
        kdt,
        timeAdded,
        cookie,
    ):

        self.name = name
        self.guest_id = guest_id
        self.auth_token = auth_token
        self.ct0 = ct0
        self.gt = gt
        self.twid = twid
        self.userAgent = userAgent
        self.kdt = kdt
        self.timeAdded = timeAdded
        self.cookie = cookie

"""
Calculates time for next tweet upload

c = current time (in seconds)
h = num hours until next tweet (in hours)
r = randomness added to the end result for variation (in hours)
"""
def calculateNextTweetTime(c, h, r):
    try:
        x = c + (h * 3600) + ((random.uniform((r * -1), r) * 3600))
    except:
        x = c + (h * 3600)
    return x

# Scrapes the last tweet from an account from a random Nitter instance listed
def grabLastTweet(name, mirrorList):
    for i in range(0, 10):
        try:
            mirror = mirrorList[random.randint(0, len(mirrorList) - 1)]
            res = requests.get(f"https://{mirror}/{name}", timeout=10)
            soup = BeautifulSoup(res.text, "html.parser")
            tweets = soup.find_all(class_="tweet-link")
            for j in tweets: 
                link = re.findall(f"(?<={name}/status/)\d*", j["href"])
                if link != []:
                    return link[0]
        except:
            continue

# Returns an object taken from a YAML config file for each account
def allSettings(name):
    with open(f"./configs/{name}.yml", "r") as f:
        template = yaml.safe_load(f)
        return template

def getAccountSettingFromDB(name, setting):
    res = cur.execute(f"SELECT {setting} FROM accounts WHERE name = ?", (name,))
    return res.fetchone()[0]

# Returns a list of mirrors for nitter instances from a file
def getNitterMirrors():
    out = []
    with open("./nitter.txt", "r") as f:
        lines = f.readlines()
        for i in lines:
            out.append(re.sub("\n", "", i))

    return out

# Appends to a log file at a specific location
def logData(data, location):
    try:
        if os.path.exists(f"./logs/{location}.log"):
            with open(f"./logs/{location}.log", "a") as log:
                log.write(f"{data}\n")
        else:
            with open(f"./logs/{location}.log", "w") as log:
                log.write(f"{data}\n")
    except:
        print("LOGGING ERROR")

# Authenticates by checking if a password has a certain permission
def verify(password, pHash, permission):
    if pbkdf2_sha256.verify(password, pHash) == True:
        return True
    try:
        p = base64.b64decode(bytes(password, "utf-8"))

        private = serialization.load_pem_private_key(
            p,
            password=None,
        )
        public = base64.b64encode(private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode("utf-8")

        res = con.execute("SELECT * FROM keys WHERE key=?", (public, ))
        out = res.fetchall()
        if len(out) > 0:
            for i in out:
                if permission in json.loads(i[2])["permissions"]:
                    return True
                else:
                    return False
        else:
            return False
    except:
        logData(f"PASSWORD ERROR {datetime.utcfromtimestamp(time.time())}", "error")
        return False

# Reads through account information and adds it to queue of accounts to post from
def readAccounts(accountDict, nextTweetDict, filelistDict, hoursDict):
    for i in os.listdir("./configs/"):
        try:
            template = allSettings(i.split(".")[0])
        except:
            continue

        if template["name"] not in accountDict and template["deactivate"] != 1:
            timeAdded = time.time()
            accountDict[template["name"]] = Account(
                name=template["name"],
                guest_id=template["guest_id"],
                auth_token=template["auth_token"],
                ct0=template["ct0"],
                gt=template["gt"],
                twid=template["twid"],
                userAgent=template["user-agent"],
                kdt=template["kdt"],
                timeAdded=timeAdded,
                rm=template["rm"],
            )

            hoursDict[template["name"]] = template["hours"]

            res = cur.execute("SELECT * FROM accounts WHERE name = ?", (template["name"], ))
            if len(res.fetchall()) > 0:
                cur.execute("DELETE FROM accounts WHERE name = ?", (template["name"], ))

            insert = (
                    template["name"],
                    template["proxy"],
                    template["guest_id"],
                    template["auth_token"],
                    template["ct0"],
                    template["gt"],
                    template["twid"],
                    template["user-agent"],
                    template["kdt"],
                    timeAdded,
                    template["cookie"],
                    template["hours"],
                    template["range"],
                    template["rm"],
                    template["deactivate"]
                )
            

            cur.execute("INSERT OR IGNORE INTO accounts VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", insert)
            con.commit()
            
            filelistDict[template["name"]] = api.getList(template["name"])

            nextTweetDict[template["name"]] = calculateNextTweetTime(timeAdded, hoursDict[template["name"]], template["range"])

            print(f"Next Tweet of {template['name']}: {datetime.utcfromtimestamp(nextTweetDict[template['name']])}")

        elif template["name"] in accountDict and template["deactivate"] == 1:
            accountDict.remove(template["name"])
    
    res = cur.execute("SELECT * FROM accounts")
    for i in res.fetchall():
        if i[0] not in accountDict:
            accountDict[template["name"]] = Account(
                name=i[0],
                guest_id=i[2],
                auth_token=i[3],
                ct0=i[4],
                gt=i[5],
                twid=i[6],
                userAgent=i[7],
                kdt=i[8],
                timeAdded=i[9],
                rm=i[13],
            )

            hoursDict[i[0]] = i[11]

            filelistDict[i[0]] = api.getList(i[0])

            nextTweetDict[i[0]] = calculateNextTweetTime(timeAdded, hoursDict[i[0]], i[12])

            print(f"Next Tweet of {i[0]}: {datetime.utcfromtimestamp(nextTweetDict[i[0]])}")


def tweetdeckReadAccounts(tweetdeckDict, userIDDict):
    for i in os.listdir("./tweetdeck_configs/"):
        try:
            template = allSettings(i.split(".")[0])
        except:
            continue

            if template["name"] not in tweetdeckDict:
                timeAdded = time.time()
                tweetdeckDict[template["name"]] = TweetdeckAccount(
                    name=template["name"],
                    guest_id=template["guest_id"],
                    auth_token=template["auth_token"],
                    ct0=template["ct0"],
                    gt=template["gt"],
                    twid=template["twid"],
                    userAgent=template["user-agent"],
                    kdt=template["kdt"],
                    timeAdded=timeAdded,
                    cookie=template["cookie"],
                )

                with open(f"./tweetdeck_userids/{i.split('.')[0]}.txt", "r") as f:
                    userIDDict[template["name"]] = re.findall("\d{1,1000}", f.read())

                res = cur.execute("SELECT * FROM tweetdeckAccounts WHERE name = ?", (template["name"], ))
                if len(res.fetchall()) > 0:
                    cur.execute("DELETE FROM tweetdeckAccounts WHERE name = ?", (template["name"], ))

                insert = [
                    (
                        template["name"],
                        template["guest_id"],
                        template["auth_token"],
                        template["ct0"],
                        template["gt"],
                        template["twid"],
                        template["user-agent"],
                        template["kdt"],
                        timeAdded,
                        template["cookie"],
                    )
                ]

                cur.executemany("INSERT INTO tweetdeckAccounts VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", insert)
                con.commit()


# Checks if every account should tweet or not
def checkTweets(accountDict, nextTweetDict, filelistDict, hoursDict):
    print("Checking for tweets...")
    for i in accountDict:
        filelistDict[i] = api.getList(i)
        hoursDict[i] = float(getAccountSettingFromDB(i, "hours"))
        if nextTweetDict[i] < time.time() and len(filelistDict[i]) > 0:
            print("Making Tweet...")
            nextTweetDict[i] = calculateNextTweetTime(time.time(), hoursDict[i], float(getAccountSettingFromDB(i, "range")))
            try:
                makeTweet(accountDict, i, filelistDict)
            except:
                logData(f"Error tweeting at {datetime.utcfromtimestamp(time.time())}", "error")
            print(f"Next tweet of {i}: {datetime.utcfromtimestamp(nextTweetDict[i])}")

# Checks if a certain time threshold has passed, and then likes the last tweet on an account
def autolike(accounts, mirrorList, autolikes):
    if len(autolikes) == 0:
        return
    print("Checking Autolikes...")
    for i in autolikes:
        print(i.name)
        tweet = grabLastTweet(i.name, mirrorList)
        print(tweet)
        if i.lastTweet != tweet:
            if i.isRandom == False:
                for j in i.accounts:

                    proxy = getAccountSettingFromDB(j, proxy)

                    api.likeTweet(
                        tweet=tweet,
                        proxy=proxy,
                        guest_id=accounts[j].guest_id,
                        ct0=accounts[j].ct0,
                        kdt=accounts[j].kdt,
                        twid=accounts[j].twid,
                        auth_token=accounts[j].auth_token,
                        gt=accounts[j].gt,
                        userAgent=accounts[j].userAgent
                    )
                    i.lastTweet = tweet
                    log = f"{j} AutoLiked {tweet} at {datetime.utcfromtimestamp(time.time())}"
                    logData(log, "like")

            elif i.isRandom == True:
                accs = []
                for j in accounts:
                    accs.append(j.name)

                while len(accs) > accounts:
                    accs.pop(random.randint(0, len(accs) - 1))

                for j in accs:

                    proxy = getAccountSettingFromDB(j, "proxy")

                    api.likeTweet(
                        tweet=tweet,
                        proxy=proxy,
                        guest_id=accounts[j].guest_id,
                        ct0=accounts[j].ct0,
                        kdt=accounts[j].kdt,
                        twid=accounts[j].twid,
                        auth_token=accounts[j].auth_token,
                        gt=accounts[j].gt,
                        userAgent=accounts[j].userAgent,
                    )
                    i.lastTweet = tweet
                    log = f"{j} AutoLiked {tweet} at {datetime.utcfromtimestamp(time.time())}"
                    logData(log, "like")


# Uploads a file and tweets using that file as media for that tweet
def makeTweet(accountDict, name, filelistDict):
    try:
        idx = random.randint(0, len(filelistDict[name]) - 1)
        file = filelistDict[name][idx]
        with open(f"./media/{name}/{file}", "rb") as md:
            
            md_bytes = md.read()
            md_size = len(md_bytes)

            proxy = getAccountSettingFromDB(name, "proxy")

            if md_size > 4000000 or file.endswith(".mp4") or file.endswith(".gif"):
                print("CHUNKED UPLOAD")
                
                upload.chunkedUpload(
                    proxy=proxy,
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
                    proxy=proxy,
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
            log = f"{name} Tweeted {file} at {datetime.utcfromtimestamp(time.time())}"
            logData(log, "tweet")
                    
    except:
        print("ERROR UPLOADING")

    try:
        del filelistDict[name][idx]
        print("DELETE FROM MEMORY DONE")
    except:
        print("ERROR DELETING FROM MEMORY")

    if int(getAccountSettingFromDB(name, "rm")) == 1:
        try:
            os.remove(f"./media/{name}/{file}")
            print("DELETE FILE LOCALLY DONE")
        except:
            print("ERROR DELETING FILE LOCALLY")

    
app = Flask(__name__)

@app.route("/getData", methods=["GET"])
def getData():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "getData") == True:
            name = str(request.headers["AccountName"])
            hours = getAccountSettingFromDB(name, "hours")
            deactivate = getAccountSettingFromDB(name, "deactivate")
            return api.getData(
                request=request,
                pHash=pHash,
                hours=hours,
                deactivate=deactivate
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
    #try:
        return api.getAccounts(request, pHash)
    #except:
     #   returnCode = "ERROR"
     #   api.logInfo(request.headers, request.remote_addr, returnCode)
     #   return returnCode
    
@app.route("/newConfig", methods=["POST"])
def newConfig():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "delConfig") == True:
            res = cur.execute("SELECT * FROM accounts WHERE name = ?", (template["name"], ))
                if len(res.fetchall()) > 0:
                    returnCode = "ACCOUNT ALREADY EXISTS"
                    api.logInfo(request.headers, request.remote_addr, returnCode)
                    return returnCode

            template = yaml.safe_load(request.data)

            timeAdded = time.time()
            accounts[template["name"]] = Account(
                name=template["name"],
                guest_id=template["guest_id"],
                auth_token=template["auth_token"],
                ct0=template["ct0"],
                gt=template["gt"],
                twid=template["twid"],
                userAgent=template["user-agent"],
                kdt=template["kdt"],
                timeAdded=timeAdded,
                rm=template["rm"],
            )

            hoursDict[template["name"]] = template["hours"]

            filelistDict[template["name"]] = api.getList(template["name"])

            nextTweetDict[template["name"]] = calculateNextTweetTime(timeAdded, hoursDict[template["name"]], template["range"])
            return api.newConfig(request, pHash, template)
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/delConfig", methods=["POST"])
def delConfig():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "delConfig") == True:
            del accounts[request.headers["AccountName"]]
            return api.delConfig(request, pHash)
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/newTweetdeckConfig", methods=["POST"])
def newTweetdeckConfig():
    #try:
        p = request.cookies.get("p")
        if verify(p, pHash, "delConfig") == True:
            res = cur.execute("SELECT * FROM tweetdeckAccounts WHERE name = ?", (template["name"], ))
                if len(res.fetchall()) > 0:
                    returnCode = "ACCOUNT ALREADY EXISTS"
                    api.logInfo(request.headers, request.remote_addr, returnCode)
                    return returnCode
            template = yaml.safe_load(request.data)

            timeAdded = time.time()
            tweetdeckDict[template["name"]] = TweetdeckAccount(
                name=template["name"],
                guest_id=template["guest_id"],
                auth_token=template["auth_token"],
                ct0=template["ct0"],
                gt=template["gt"],
                twid=template["twid"],
                userAgent=template["user-agent"],
                kdt=template["kdt"],
                timeAdded=timeAdded,
                cookie=template["cookie"],
            )
        return api.newTweetdeckConfig(request, pHash, template)
    #except:
     #   returnCode = "ERROR"
     #   api.logInfo(request.headers, request.remote_addr, returnCode)
     #   return returnCode

@app.route("/delConfig", methods=["POST"])
def delTweetdeckConfig():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "delConfig") == True:
            del tweetdeckDict[request.headers["AccountName"]]
        return api.delConfig(request, pHash)
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/createKey", methods={"POST"})
def createKey():
    try:
        data = json.loads(request.data)
        p = request.cookies.get("p")
        if verify(p, pHash, "createKey") == True:

            private = rsa.generate_private_key(
                public_exponent=65537,
                key_size=512
            )
            privateStr = base64.b64encode(private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )).decode("utf-8")
            public = base64.b64encode(private.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode("utf-8")

            values = (
                data["name"],
                public,
                json.dumps({"permissions": data["permissions"]})
            )

            cur.execute("INSERT INTO keys VALUES(?, ?, ?)", values)
            con.commit()

            log = f"Key Created {data['name']} {data['permissions']} at {datetime.utcfromtimestamp(time.time())}"

            logData(log, "key")

            returnCode = json.dumps({"private": privateStr, "public": public})
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


@app.route("/likeTweet", methods=["POST"])
def likeTweet():
    #try:
        p = request.cookies.get("p")
        if verify(p, pHash, "likeTweet") == True:
            data = json.loads(request.data)
            if data["isRandom"] == True:
                names = []
                for i in accounts.keys():
                    names.append(i)

                for i in range(0, min(int(data["accounts"]), len(names))):
                    idx = random.randint(0, len(names) - 1)
                    name = names[idx]
                    try:
                        tweet = re.findall("(?<=status/)\d*", request.headers["TweetID"])[0]
                    except:
                        tweet = request.headers["TweetID"]

                    proxy = getAccountSettingFromDB(name, "proxy")

                    api.likeTweet(
                        tweet=tweet,
                        proxy=proxy,
                        guest_id=accounts[name].guest_id,
                        ct0=accounts[name].ct0,
                        kdt=accounts[name].kdt,
                        twid=accounts[name].twid,
                        auth_token=accounts[name].auth_token,
                        gt=accounts[name].gt,
                        userAgent=accounts[name].userAgent,
                    )
                    names.pop(idx)
                    time.sleep(random.randint(30, 120))

            elif data["isRandom"] == False:
                for i in data["accounts"]:

                    proxy = getAccountSettingFromDB(i, "proxy")

                    try:
                        tweet = re.findall("(?<=status/)\d*", request.headers["TweetID"])[0]
                    except:
                        tweet = request.headers["TweetID"]

                    api.likeTweet(
                        tweet=tweet,
                        proxy=proxy,
                        guest_id=accounts[i].guest_id,
                        ct0=accounts[i].ct0,
                        kdt=accounts[i].kdt,
                        twid=accounts[i].twid,
                        auth_token=accounts[i].auth_token,
                        gt=accounts[i].gt,
                        userAgent=accounts[i].userAgent,
                    )
                    time.sleep(random.randint(30, 120))
            
            returnCode = "OK"
            api.logInfo(request.headers, request.remote_addr, returnCode)

            log = f"{data['accounts']} Liked {request.headers['TweetID']} at {datetime.utcfromtimestamp(time.time())}"
            logData(log, "like")

            return returnCode
        else:
            returnCode = "INCORRECT PASSWORD"
            api.logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode

    #except:
     #   returnCode = "ERROR"
      #  api.logInfo(request.headers, request.remote_addr, returnCode)
       # return returnCode

def multiLikeHelper(
    request,
    accountDict,
    pHash
):
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "multiLike") == True:
            head = request.headers
            data = request.data

            for i in accountDict.keys():

                proxy = getAccountSettingFromDB(i, "proxy")

                api.likeTweet(
                    tweet=request.headers["TweetID"],
                    proxy=proxy,
                    guest_id=accountDict[i].guest_id,
                    ct0=accountDict[i].ct0,
                    kdt=accountDict[i].kdt,
                    twid=accountDict[i].twid,
                    auth_token=accountDict[i].auth_token,
                    gt=accountDict[i].gt,
                    userAgent=accountDict[i].userAgent,
                )
                time.sleep(random.randint(30, 120))
        else:
            returnCode = "INCORRECT PASSWORD"
            api.logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/multiLike", methods=["POST"])
def multiLike():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "multiLike") == True:
            data = request.data
            
            found = False
            with open("./logs/requests.log") as f:
                lines = f.readlines()
            for i in lines[-10000:]:
                reg = re.findall(f"{request.headers['TweetID']}", i)
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

                log = f"All Accounts Liked {request.headers['TweetID']} at {datetime.utcfromtimestamp(time.time())}"
                logData(log, "like")

                return returnCode
            
        else:
            returnCode = "INCORRECT PASSWORD"
            api.logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/createAutolike", methods=["POST"])
def createAutolike():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "createAutolike") == True:
            data = json.loads(request.data)

            if len(data["accounts"]) > 0:
                if data["accounts"] == "all":
                    accs = len(accounts)
                else:
                    accs = data["accounts"]

                output = AutolikeDict(
                    name=data["name"],
                    accounts=accs,
                    isRandom=data["isRandom"],
                    lastTweet=None
                )

                for i in autolikes:
                    if i.name == data["name"]:
                        returnCode = "SAME AUTOLIKE"
                        api.logInfo(request.headers, request.remote_addr, returnCode)
                        return returnCode

                autolikes.append(output)
                autolikes[len(autolikes) - 1] = output

                log = f"Autolike Created for {data['name']} using {data['accounts']} accounts at {datetime.utcfromtimestamp(time.time())}"
                logData(log, "autolike")
        
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

@app.route("/deleteAutolike", methods={"POST"})
def deleteAutolike():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "deleteAutolike") == True:
            data = json.loads(request.data)

            tmp = {}

            for i in data["autolikes"]:
                tmp[i] = True

            for i in range(0, len(autolikes)):
                if autolikes[i].name in tmp:
                    autolikes.pop(i)

            print(len(autolikes))
            returnCode = "OK"
            api.logInfo(request.headers, request.remote_addr, returnCode)

            log = f"Autolike Deleted for {data['name']} using {data['accounts']} accounts at {datetime.utcfromtimestamp(time.time())}"
            logData(log, "autolike")

            return returnCode
        else:
            returnCode = "INCORRECT PASSWORD"
            api.logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode


@app.route("/getAutolikes", methods=["GET"])
def getAutolikes():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "getAutolikes") == True:

            out = []

            for i in autolikes:
                if i.name.startswith(request.headers["StartsWith"]):
                    out.append(i.name)

            returnCode = json.dumps({"autolikes": out})
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
        proxy = None

        proxy = getAccountSettingFromDB(name, "proxy")
            
        return api.deleteTweet(
            request=request,
            proxy=proxy,
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
        p = request.cookies.get("p")
        if verify(p, pHash, "stop") == True:
            returnCode = api.stop(request, pHash)
            nextTweet[request.headers["AccountName"]] = 999999999999999999999999999999999999
            return returnCode
        else:
            returnCode = "INCORRECT PASSWORD"
            api.logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/restart", methods=["POST"])
def restart():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "restart") == True:
            returnCode = api.restart(request, pHash)
            nextTweet[request.headers["AccountName"]] = calculateNextTweetTime(
                time.time(),
                float(getAccountSettingFromDB(request.headers["AccountName"], "hours")),
                float(getAccountSettingFromDB(request.headers["AccountName"], "range"))
            )
            print(nextTweet[request.headers["AccountName"]])
            return returnCode
        else:
            returnCode = "INCORRECT PASSWORD"
            api.logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/getSettings", methods=["GET"])
def getSettings():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "getSettings") == True:
            res = cur.execute("SELECT hours, range, rm, proxy FROM accounts WHERE name = ?", (request.headers['AccountName'], ))
            out = res.fetchone()

            tmp = {"settings": {"hours": out[0], "range": out[1], "delete": out[2]}}
            returnCode = tmp

            if out[3] == None or "":
                proxy = ""
            else:
                proxy = out[3]

            api.logInfo(request.headers, request.remote_addr, returnCode)
            return render_template("./accountSettings.html", hours=out[0], range=out[1], proxy=proxy)
        else:
            returnCode = "INCORRECT PASSWORD"
            api.logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    except:
        returnCode = '<h2 class="text-black text-center">Error Finding Account</h2>'
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/changeSettings", methods=["POST"])
def changeSettings():
    try:
        try:
            p = request.cookies.get("p")
        except:
            p = request.headers["Password"]
        if verify(p, pHash, "changeSettings") == True:
            data = json.loads(request.data)
            returnCode = api.changeSettings(request)
            if "hours" in data:
                hoursDict[request.headers["AccountName"]] = data["hours"]
                    
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

@app.route("/changeRate", methods=["POST"])
def changeRate():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "changeRate") == True:
            hoursDict[request.headers["AccountName"]] = request.headers['Hours']
        else:
            returnCode = "INCORRECT PASSWORD"
            api.logInfo(request.headers, request.remote_addr, returnCode)
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

@app.route("/openUIElement", methods=["GET"])
def openUIElement():
    try:
        return api.openUIElement(request, pHash)
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/export", methods=["GET"])
def export():
    p = request.cookies.get("p")
    if verify(p, pHash, "export") == True:
        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w') as zf:
            toZip = []
            for dirname, dirnames, filenames in os.walk('.'):
                for i in filenames:
                    toZip.append(os.path.join(dirname, i))
                    
            for i in toZip:
                print(i)
                try:
                    data = zipfile.ZipInfo(i)
                    data.date_time = time.localtime(time.time())[:6]
                    data.compress_type = zipfile.ZIP_DEFLATED
                    with open(i, "rb") as f:
                        zf.writestr(data, f.read())
                    print(i)
                except:
                    print(f"didn't work {i}")
                    continue
                    
        memory_file.seek(0)
        return send_file(memory_file, download_name='archive.zip', as_attachment=True)

@app.route("/exportLog", methods=["GET"])
def exportLog():
    p = request.cookies.get("p")
    if verify(p, pHash, "exportLog") == True:
        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w') as zf:
            toZip = []
            for dirname, dirnames, filenames in os.walk('./logs/'):
                for i in filenames:
                    toZip.append(os.path.join(dirname, i))
                    
            for i in toZip:
                print(i)
                try:
                    data = zipfile.ZipInfo(i)
                    data.date_time = time.localtime(time.time())[:6]
                    data.compress_type = zipfile.ZIP_DEFLATED
                    with open(i, "rb") as f:
                        zf.writestr(data, f.read())
                    print(i)
                except:
                    print(f"didn't work {i}")
                    continue
                    
        memory_file.seek(0)
        return send_file(memory_file, download_name='log.zip', as_attachment=True)

@app.route("/exportMedia", methods=["GET"])
def exportMedia():
    p = request.cookies.get("p")
    if verify(p, pHash, "exportMedia") == True:
        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w') as zf:
            toZip = []
            for dirname, dirnames, filenames in os.walk('./media/'):
                for i in filenames:
                    toZip.append(os.path.join(dirname, i))
                    
            for i in toZip:
                print(i)
                try:
                    data = zipfile.ZipInfo(i)
                    data.date_time = time.localtime(time.time())[:6]
                    data.compress_type = zipfile.ZIP_DEFLATED
                    with open(i, "rb") as f:
                        zf.writestr(data, f.read())
                    print(i)
                except:
                    print(f"didn't work {i}")
                    continue
                    
        memory_file.seek(0)
        return send_file(memory_file, download_name='media.zip', as_attachment=True)

@app.route("/passCheck")
def passCheck():
    try:
        p = request.headers["Password"]
        if verify(p, pHash, "passCheck") == True:
            return "OK"
        else:
            return "INCORRECT PASSWORD"
    except:
        return "ERROR"

@app.route("/")
def root():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "root") == True:
            return open("./index.html", "rb")
    except:
        return open("./login.html", "rb")
    return open("./login.html", "rb") 

@app.route("/bot")
def bot():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "bot") == True:
            return open("./bot.html", "rb")
    except:
        return open("./login.html", "rb")
    return open("./login.html", "rb") 

@app.route("/media")
def media():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "media") == True:
            try:
                a = request.args.get("a")
                return render_template("./media.html", accountName=a)
            except:    
                return render_template("./media.html", accountName="")
    except:
        return open("./login.html", "rb")
    return open("./login.html", "rb")

@app.route("/boost")
def boost():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "boost") == True:
            try:
                a = request.args.get("a")
                return render_template("./boost.html")
            except:    
                return render_template("./boost.html")
    except:
        return open("./login.html", "rb")
    return open("./login.html", "rb")

@app.route("/pass")
def passgen():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "passgen") == True:
            try:
                a = request.args.get("a")
                return render_template("./passgen.html")
            except:    
                return render_template("./passgen.html")
    except:
        return open("./login.html", "rb")
    return open("./login.html", "rb")

with open("./shadow.yml", "r") as f:
    template = yaml.safe_load(f)
    pHash = template["main"]

def startTerm():
    con = sqlite3.connect("database.db", check_same_thread=False)
    cur = con.cursor()
    app.run('0.0.0.0', debug=False, port=42874, use_reloader=False, ssl_context=("./server.crt", "./server.key"))
    

manager = mp.Manager()
accounts = manager.dict()
autolikes = manager.list()
nextTweet = {}
filelistDict = {}
hoursDict = {}
mirrorList = getNitterMirrors()
tweetdeckDict = manager.dict()
userIDDict = {}

def startBot():
    print("INITIALIZED")
    while True:
        #try:
        readAccounts(accounts, nextTweet, filelistDict, hoursDict)
        #except:
         #   print("ERROR READACCOUNTS")
        try:
            checkTweets(accounts, nextTweet, filelistDict, hoursDict)
        except:
            print(f"ERROR CHECKTWEETS")
        try:
            autolike(accounts, mirrorList, autolikes)
        except:
            print("ERROR AUTOLIKE")
        time.sleep(30)


if __name__ == "__main__":
    p = mp.Process(target=startTerm)
    p.start()
    startBot()
    
with open("./shadow.yml", "r") as f:
    template = yaml.safe_load(f)
    pHash = template["main"]