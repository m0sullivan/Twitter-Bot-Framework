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
        with open("./logfile.log", "a") as log:
            log.write(f"\nHeader Hash: {hashlib.sha256(bytes(str(head), 'utf-8')).hexdigest()}\n")
            log.write(f"{head}{ip}\nReturn Code: {returnCode}\n")
            
    except:
        print("LOGGING ERROR")


def getAccounts(request, pHash):
    head = request.headers
    if pbkdf2_sha256.verify(head["Password"], pHash) == True:

        tmp = os.listdir("./configs/")
        out = []

        for i in tmp:
            if i.startswith(head["StartsWith"]):
                out.append(i[:i.index(".")])

        returnCode = json.dumps({"accounts": out})
        logInfo(head, request.remote_addr, returnCode)
        return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(head, request.remote_addr, returnCode)
        return returnCode


def newConfig(request, pHash):
    head = request.headers
    data = request.data
    if pbkdf2_sha256.verify(head["Password"], pHash) == True:
        try:
            with open(f"./configs/{head['AccountName']}.yml", "wb") as conf:
                conf.write(data)
            returnCode = "OK"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR MAKING CONFIG"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode


def stop(request, pHash):
    head = request.headers
    data = request.data
    if pbkdf2_sha256.verify(head["Password"], pHash) == True:
        try:
            with open(f"./configs/{head['AccountName']}.yml", "r") as conf:
                
                out = ""
                for i in conf.readlines():
                    if i.startswith("deactivate: 0"):
                        out += "deactivate: 1\n"
                    else:
                        out += f"{i}"
            with open(f"./configs/{head['AccountName']}.yml", "w") as conf:
                conf.write(out)
                
                returnCode = "OK"
                logInfo(head, request.remote_addr, returnCode)
                return returnCode
        except:
            returnCode = "ERROR EDITING CONFIG"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(head, request.remote_addr, returnCode)
        return returnCode


def restart(request, pHash):
    head = request.headers
    data = request.data
    if pbkdf2_sha256.verify(head["Password"], pHash) == True:
        try:
            with open(f"./configs/{head['AccountName']}.yml", "r") as conf:
                out = ""
                for i in conf.readlines():
                    if i.startswith("deactivate: 1"):
                        out += "deactivate: 0\n"
                    else:
                        out += f"{i}"

            with open(f"./configs/{head['AccountName']}.yml", "w") as conf:
                conf.write(out)
                
                returnCode = "OK"
                logInfo(head, request.remote_addr, returnCode)
                return returnCode
        except:
            returnCode = "ERROR EDITING CONFIG"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(head, request.remote_addr, returnCode)
        return returnCode


def getData(request, pHash, hours, deactivate):
    head = request.headers
    if pbkdf2_sha256.verify(head["Password"], pHash) == True:

        filelist = getList(head['AccountName'])

        out = "" 

        try:
            res = requests.get(f"https://nitter.nl/{head['AccountName']}")
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
        logInfo(head, request.remote_addr, returnCode)
        return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(head, request.remote_addr, returnCode)
        return returnCode


# Uses an input of a tweet ID and calls the API to like said tweet
def likeTweet(
    request,
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

    head = request.headers
    data = request.data
    if pbkdf2_sha256.verify(head["Password"], pHash) == True:
        tweet = head["TweetID"]
        try:
            url = "	https://twitter.com/i/api/graphql/lI07N6Otwv1PhnEgXILM7A/FavoriteTweet"

            data = '{"variables":{"tweet_id":"' + tweet + '"},"queryId":"lI07N6Otwv1PhnEgXILM7A"}'

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

            try:
                res = requests.post(url=url, headers=h, data=data, timeout=10)
                print(res.text)
            except:
                returnCode = "ERROR MAKING REQUEST"
                logInfo(head, request.remote_addr, returnCode)
                return returnCode

            returnCode = "OK"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR LIKING TWEET"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(head, request.remote_addr, returnCode)
        return returnCode


def deleteTweet(
    request,
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

    head = request.headers
    data = request.data
    if pbkdf2_sha256.verify(head["Password"], pHash) == True:
        account = head["AccountName"]
        tweet = head["TweetID"]
        try:
            url = "https://twitter.com/i/api/graphql/VaenaVgh5q5ih7kvyVjgtg/DeleteTweet"

            data = '{"variables":{"tweet_id":"' + tweet + '","dark_request":false},"queryId":"VaenaVgh5q5ih7kvyVjgtg"}'

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
                res = requests.post(url=url, headers=h, data=data, timeout=10)
                print(res.text)
            except:
                returnCode = "ERROR MAKING REQUEST"
                logInfo(head, request.remote_addr, returnCode)
                return returnCode

            returnCode = "OK"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR DELETING TWEET"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(head, request.remote_addr, returnCode)
        return returnCode


def changeRate(request, pHash):
    head = request.headers
    data = request.data
    if pbkdf2_sha256.verify(head["Password"], pHash) == True:
        try:
            with open(f"./configs/{head['AccountName']}.yml", "r") as conf:
                out = ""
                for i in conf.readlines():
                    if i.startswith("hours:"):
                        out += f"hours: {head['Hours']}\n"
                    else:
                        out += f"{i}"

            with open(f"./configs/{head['AccountName']}.yml", "w") as conf:
                conf.write(out)
                
                returnCode = "OK"
                logInfo(head, request.remote_addr, returnCode)
                return returnCode
        except:
            returnCode = "ERROR EDITING CONFIG"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(head, request.remote_addr, returnCode)
        return returnCode

def mediaUpload(request, pHash):
    head = request.headers
    data = request.data
    if pbkdf2_sha256.verify(head["Password"], pHash) == True:
        try:
            uploaded_files = flask.request.files.getlist("file")

            for file in uploaded_files:
                file.save(f"./media/{head['AccountName']}/{werkzeug.utils.secure_filename(file.filename)}")
            
            returnCode = "OK"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR UPLOADING FILE"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(head, request.remote_addr, returnCode)
        return returnCode

def mediaDelete(request, pHash):
    head = request.headers
    data = request.data
    if pbkdf2_sha256.verify(head["Password"], pHash) == True:
        try:
            files = json.loads(head["Files"])

            for i in files:
                os.remove(f"./media/{head['AccountName']}/{i}")
            
            returnCode = "OK"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR DELETING FILE"
            logInfo(head, request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(head, request.remote_addr, returnCode)
        return returnCode

def getMedia(request, pHash):
    head = request.headers

    if head['AccountName'] == "":
        return "NO ACCOUNTNAME"

    if pbkdf2_sha256.verify(head["Password"], pHash) == True:

        try:
            tmp = os.listdir(f"./media/{head['AccountName']}")
        except:
            if os.path.exists(f".configs/{head['AccountName']}.yml"):
                os.mkdir(f"./media/{head['AccountName']}")

        out = []

        for i in tmp:
            out.append(i)

        returnCode = "OK"
        logInfo(head, request.remote_addr, returnCode)
        return json.dumps({"media": out})
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(head, request.remote_addr, returnCode)
        return returnCode

def openMedia(request, pHash):
    head = request.headers
    try:
        accountName = request.args.get("accountName")
        password = request.args.get("password")
        file = request.args.get("file")
    except:
        return "INCORRECT ACCOUNTNAME OR PASSWORD"
    if pbkdf2_sha256.verify(password, pHash) == True:
        returnCode = flask.send_from_directory(
            directory=f"./media/{accountName}",
            path=file,
            as_attachment=False
        )
        logInfo(head, request.remote_addr, "RETURNED VIDEO")
        return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(head, request.remote_addr, returnCode)
        return returnCode
