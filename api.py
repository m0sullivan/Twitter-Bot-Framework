import json
from flask import Flask, request, jsonify
import os
import yaml
from passlib.hash import pbkdf2_sha256
import time
import hashlib
import requests
from bs4 import BeautifulSoup
import werkzeug
import flask
import random
import multiprocessing as mp
from main import verify
import re
from datetime import datetime

# Returns a list of filenames
def getList(name):
    try:
        return os.listdir(f"./media/{name}/")
    except:
        os.mkdir(f"./media/{name}/")
        return os.listdir(f"./media/{name}/")


def logInfo(head, ip, returnCode):
    print(returnCode)
    try:
        with open("./logs/requests.log", "a") as log:
            log.write(f"---------------------\n{datetime.utcfromtimestamp(time.time())}\n")
            log.write(f"\nHeader Hash: {hashlib.sha256(bytes(str(head), 'utf-8')).hexdigest()}\n")
            log.write(f"{head}{ip}\nReturn Code: {returnCode}\n")
                
    except:
        print("LOGGING ERROR")


def contains_duplicates(X):
    seen = set()
    seen_add = seen.add
    for x in X:
        if (x in seen or seen_add(x)):
            return True
    return False


def getAccounts(request, pHash):
    p = request.cookies.get("p")
    if verify(p, pHash, "getAccounts") == True:

        tmp = os.listdir("./configs/")
        out = []

        for i in tmp:
            if i.startswith(request.headers["StartsWith"]):
                out.append(i[:i.index(".")])

        returnCode = json.dumps({"accounts": out})
        logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode


def newConfig(request, pHash):
    data = request.data
    try:
        p = request.cookies.get("p")
    except:
        p = request.headers["Password"]
    if verify(p, pHash, "newConfig") == True:
        try:
            with open(f"./configs/{request.headers['AccountName']}.yml", "wb") as conf:
                conf.write(data)
            returnCode = "OK"
            logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR MAKING CONFIG"
            logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode


def delConfig(request, pHash):
    try:
        p = request.cookies.get("p")
    except:
        p = request.headers["Password"]
    if verify(p, pHash, "newConfig") == True:
        try:
            os.remove(f"./configs/{request.headers['AccountName']}.yml")
            returnCode = "OK"
            logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR DELETING CONFIG"
            logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode


def stop(request, pHash):
    p = request.cookies.get("p")
    if verify(p, pHash, "stop") == True:
        try:
            with open(f"./configs/{request.headers['AccountName']}.yml", "r") as conf:
                
                out = ""
                for i in conf.readlines():
                    if i.startswith("deactivate: 0"):
                        out += "deactivate: 1\n"
                    else:
                        out += f"{i}"
            with open(f"./configs/{request.headers['AccountName']}.yml", "w") as conf:
                conf.write(out)
                
                returnCode = "OK"
                logInfo(request.headers, request.remote_addr, returnCode)
                return returnCode
        except:
            returnCode = "ERROR EDITING CONFIG"
            logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode


def restart(request, pHash):
    p = request.cookies.get("p")
    if verify(p, pHash, "restart") == True:
        try:
            with open(f"./configs/{request.headers['AccountName']}.yml", "r") as conf:
                out = ""
                for i in conf.readlines():
                    if i.startswith("deactivate: 1"):
                        out += "deactivate: 0\n"
                    else:
                        out += f"{i}"

            with open(f"./configs/{request.headers['AccountName']}.yml", "w") as conf:
                conf.write(out)
                
                returnCode = "OK"
                logInfo(request.headers, request.remote_addr, returnCode)
                return returnCode
        except:
            returnCode = "ERROR EDITING CONFIG"
            logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode


def getData(request, pHash, hours, deactivate):
    p = request.cookies.get("p")
    if verify(p, pHash, "getData") == True:

        filelist = getList(request.headers['AccountName'])

        out = "" 

        try:
            res = requests.get(f"https://nitter.nl/{request.headers['AccountName']}")
            soup = BeautifulSoup(res.text, "html.parser")

            stats = []

            for i in soup.find_all(class_="profile-stat-num"):
                stats.append(i)

            out += f"Followers: {stats[2]}\n"
            out += f"Tweets: {stats[0]}\n"
        except:
            out += f"We weren't able to retrieve follower and tweet count\n"

        if deactivate == 1:
            out += f"The account is not active,\n"
        elif deactivate == 0:
            out += f"The account is active,\n"
        else:
            out += f"There is an error with the activation part of the account config file,\n"
        out += f"Frequency of posting (hours): {hours},\n"
        out += f"Number of tweets: {len(filelist)},\n"
        out += f"Time left until account is out of tweets: {len(filelist) * hours} Hours - {len(filelist) * hours / 24} days."

        returnCode = out
        logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode


# Uses an input of a tweet ID and calls the API to like said tweet
def likeTweet(
    tweet,
    proxy,
    authorization,
    guest_id,
    ct0,
    kdt,
    twid,
    auth_token,
    gt,
    userAgent
):
    url = "	https://twitter.com/i/api/graphql/lI07N6Otwv1PhnEgXILM7A/FavoriteTweet"

    data = '{"variables":{"tweet_id":"' + tweet + '"},"queryId":"lI07N6Otwv1PhnEgXILM7A"}'

    if proxy != None:
        p = {
            "http": f"{proxy}"
        }
    else:
        p = None

    h = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json",
        "Accept-Language": "en-US,en;q=0.5",
        "authorization": f"Bearer {authorization}",
        "Connection": "keep-alive",
        "Content-Length": f"{len(data)}",
        "Cookie": f"guest_id={guest_id}; ct0={ct0}; kdt={kdt}; twid={twid}; auth_token={auth_token}; gt={gt};",
        "DNT": "1",
        "host": "twitter.com",
        "origin": "https://twitter.com",
        "referer": "https://twitter.com",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "TE": "trailers",
        "User-Agent": f"{userAgent}",
        "x-csrf-token": f"{ct0}",
        "x-twitter-active-user": "yes",
        "x-twitter-auth-type": "OAuth2Session",
        "x-twitter-client-language": "en"
    }

    if p != None:
        res = requests.post(url=url, headers=h, data=data, timeout=10, proxies=p)
        print(res.text)
    else:
        res = requests.post(url=url, headers=h, data=data, timeout=10)
        print(res.text)



def deleteTweet(
    request,
    proxy,
    authorization,
    guest_id,
    ct0,
    kdt,
    twid,
    auth_token,
    gt,
    userAgent,
    pHash
):

    data = request.data
    p = request.cookies.get("p")
    if verify(p, pHash, "deleteTweet") == True:
        account = request.headers["AccountName"]

        try:
            tweet = re.findall("(?<=status/)\d*", str(request.headers["TweetID"]))[0]
        except:
            tweet = request.headers["TweetID"]
            
        try:
            url = "https://twitter.com/i/api/graphql/VaenaVgh5q5ih7kvyVjgtg/DeleteTweet"

            data = '{"variables":{"tweet_id":"' + tweet + '","dark_request":false},"queryId":"VaenaVgh5q5ih7kvyVjgtg"}'

            if len(proxy) > 0:
                p = {
                    "http": f"{proxy}"
                }
            else:
                p = None

            h = {
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate, br",
                "Content-Type": "application/json",
                "Accept-Language": "en-US,en;q=0.5",
                "authorization": f"Bearer {authorization}",
                "Connection": "keep-alive",
                "Content-Length": f"{len(data)}",
                "Cookie": f"guest_id={guest_id}; ct0={ct0}; kdt={kdt}; twid={twid}; auth_token={auth_token}; gt={gt};",
                "DNT": "1",
                "host": "twitter.com",
                "origin": "https://twitter.com",
                "referer": f"https://twitter.com/{account}/status/{tweet}",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "TE": "trailers",
                "User-Agent": f"{userAgent}",
                "x-csrf-token": f"{ct0}",
                "x-twitter-active-user": "yes",
                "x-twitter-auth-type": "OAuth2Session",
                "x-twitter-client-language": "en"
            }

            try:
                if p != None:
                    res = requests.post(url=url, headers=h, data=data, timeout=10, proxies=p)
                    print(res.text)
                else:
                    res = requests.post(url=url, headers=h, data=data, timeout=10)
                    print(res.text)
            except:
                returnCode = "ERROR MAKING REQUEST"
                logInfo(request.headers, request.remote_addr, returnCode)
                return returnCode

            returnCode = "OK"
            logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR DELETING TWEET"
            logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

def changeSettings(request):
    data = request.data
    try:
        data = json.loads(request.data)

        valid = ["hours", "range", "delete", "proxy"]

        if contains_duplicates(list(data.keys())) == True:
            returnCode = "IMPROPER INPUT"
            logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode

        for i in data:
            print(data[i])
            print(i)
            if i in valid:
                with open(f"./configs/{request.headers['AccountName']}.yml", "r") as conf:
                    template = yaml.safe_load(conf)

                    if i == "delete" and int(data[i]) not in [0, 1]:
                        returnCode = "IMPROPER INPUT"
                        logInfo(request.headers, request.remote_addr, returnCode)
                        return returnCode

                    if i == "proxy" and len(str(data[i])) < 0:
                        returnCode = "IMPROPER INPUT"
                        logInfo(request.headers, request.remote_addr, returnCode)
                        return returnCode

                    if i == "range" and int(data[i]) < 0:
                        returnCode = "IMPROPER INPUT"
                        logInfo(request.headers, request.remote_addr, returnCode)
                        return returnCode
                    elif i == "range" and int(data[i]) > template["hours"]:
                        if "hours" in data:
                            if int(data["hours"]) <= int(data[i]):
                                returnCode = "IMPROPER INPUT"
                                logInfo(request.headers, request.remote_addr, returnCode)
                                return returnCode
                        else:
                            returnCode = "IMPROPER INPUT"
                            logInfo(request.headers, request.remote_addr, returnCode)
                            return returnCode


                    if i == "hours" and int(data[i]) < 0:
                        returnCode = "IMPROPER INPUT"
                        logInfo(request.headers, request.remote_addr, returnCode)
                        return returnCode
                    elif i == "hours" and int(data[i]) < template["range"]:
                        if "range" in data:
                            if int(data["range"]) >= int(data[i]):
                                returnCode = "IMPROPER INPUT"
                                logInfo(request.headers, request.remote_addr, returnCode)
                                return returnCode
                        else:
                            returnCode = "IMPROPER INPUT"
                            logInfo(request.headers, request.remote_addr, returnCode)
                            return returnCode
            else:
                returnCode = "IMPROPER INPUT"
                logInfo(request.headers, request.remote_addr, returnCode)
                return returnCode

        for i in data:
            if i in valid:
                with open(f"./configs/{request.headers['AccountName']}.yml", "r") as conf:
                    out = ""
                    for j in conf.readlines():
                        if j.startswith(f"{i}:"):
                            out += f"{i}: {data[i]}\n"
                        else:
                            out += f"{j}"


                with open(f"./configs/{request.headers['AccountName']}.yml", "w") as conf:
                    conf.write(out)
                    
        returnCode = "OK"
        logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode
                
    except:
        returnCode = "ERROR EDITING CONFIG"
        logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

def mediaUpload(request, pHash):
    p = request.cookies.get("p")
    if verify(p, pHash, "mediaUpload") == True:
        try:
            uploaded_files = flask.request.files.getlist("file")

            for file in uploaded_files:
                file.save(f"./media/{request.headers['AccountName']}/{werkzeug.utils.secure_filename(file.filename)}")
            
            returnCode = "OK"
            logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR UPLOADING FILE"
            logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

def mediaDelete(request, pHash):
    p = request.cookies.get("p")
    if verify(p, pHash, "mediaDelete") == True:
        try:
            files = json.loads(request.headers["Files"])

            for i in files:
                os.remove(f"./media/{request.headers['AccountName']}/{i}")
            
            returnCode = "OK"
            logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR DELETING FILE"
            logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

def getMedia(request, pHash):
    if request.headers['AccountName'] == "":
        return "NO ACCOUNTNAME"

    p = request.cookies.get("p")
    if pbkdf2_sha256.verify(p, pHash) == True:

        err = False
        out = []
        try:
            tmp = os.listdir(f"./media/{request.headers['AccountName']}")
        except:
            err = True
        if err != True:
            if len(tmp) == 0:
                if os.path.exists(f".configs/{request.headers['AccountName']}.yml"):
                    os.mkdir(f"./media/{request.headers['AccountName']}")
            else:
                for i in tmp:
                    
                    if i.startswith(request.headers["StartsWith"]):
                        print(request.headers["StartsWith"])
                        out.append(i)

        returnCode = "OK"
        logInfo(request.headers, request.remote_addr, returnCode)
        return json.dumps({"media": out})
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

def openMedia(request, pHash):
    try:
        accountName = request.args.get("accountName")
        p = request.args.get("password")
        file = request.args.get("file")
    except:
        return "INCORRECT ACCOUNTNAME OR PASSWORD"
    if verify(p, pHash, "openMedia") == True:
        returnCode = flask.send_from_directory(
            directory=f"./media/{accountName}",
            path=file,
            as_attachment=False
        )
        logInfo(request.headers, request.remote_addr, "RETURNED VIDEO")
        return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

def openUIElement(request, pHash):
    try:
        p = request.args.get("password")
        file = request.args.get("file")
    except:
        return "INCORRECT ACCOUNTNAME OR PASSWORD"
    if verify(p, pHash, "openMedia") == True:
        returnCode = flask.send_from_directory(
            directory=f"./UI/",
            path=file,
            as_attachment=False
        )
        logInfo(request.headers, request.remote_addr, "RETURNED UI ELEMENT")
        return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode
