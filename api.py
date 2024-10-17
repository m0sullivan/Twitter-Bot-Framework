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
from main import verify, getFromDB, logData
import re
from datetime import datetime
import sqlite3

con = sqlite3.connect("database.db", check_same_thread=False)
cur = con.cursor()

# Returns a list of filenames
def getList(name):
    try:
        return os.listdir(f"./media/{name}/")
    except:
        os.mkdir(f"./media/{name}/")
        return os.listdir(f"./media/{name}/")


def logInfo(userAgent, ip, returnCode):
    print(returnCode)
    try:
        with open("./logs/requests.log", "a") as log:
            log.write(f"---------------------\n{datetime.utcfromtimestamp(time.time())}\n")
            log.write(f"{userAgent}\n{ip}\nReturn Code: {returnCode}\n")
                    
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

        out = []

        res = cur.execute("SELECT name FROM accounts")
        x = res.fetchall()

        for i in x:
            if i[0].startswith(request.headers["StartsWith"]):
                out.append(i[0])

        if request.headers["referer"].__contains__("boost"):
            res = cur.execute("SELECT name FROM userIDs")
            userIDs = res.fetchall()
                    
            for i in userIDs:
                if i[0].startswith(request.headers["StartsWith"]):
                    out.append(i[0])
        else:
            res = cur.execute("SELECT name FROM tweetdeckAccountsTweeting")
            userIDs = res.fetchall()
                    
            for i in userIDs:
                if i[0].startswith(request.headers["StartsWith"]):
                    out.append(i[0])

        returnCode = json.dumps({"accounts": out})
        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
        return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
        return returnCode


def newConfig(request, pHash, template):
    data = request.data
    try:
        p = request.cookies.get("p")
    except:
        p = request.headers["Password"]
    if verify(p, pHash, "newConfig") == True:
        try:
            timeAdded = time.time()
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

            returnCode = "OK"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR MAKING CONFIG"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode


def delConfig(request, pHash):
    try:
        p = request.cookies.get("p")
    except:
        p = request.headers["Password"]
    if verify(p, pHash, "newConfig") == True:
        try:
            if os.path.exists(f"./configs/{request.headers['AccountName']}.yml"):
                os.remove(f"./configs/{request.headers['AccountName']}.yml")

            cur.execute("DELETE FROM accounts WHERE name = ?", (request.headers['AccountName'], ))
            con.commit()

            returnCode = "OK"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR DELETING CONFIG"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode


def newTweetdeckConfig(request, pHash, template):
    data = request.data
    try:
        p = request.cookies.get("p")
    except:
        p = request.headers["Password"]
    if verify(p, pHash, "newConfig") == True:
        try:
            timeAdded = time.time()
            insert = (
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
                    template["proxy"],
                )

            res = cur.execute("SELECT * FROM tweetdeckAccounts WHERE name = ?", (template["name"], ))
            if len(res.fetchall()) > 0:
                cur.execute("DELETE FROM tweetdeckAccounts WHERE name = ?", (template["name"], ))

            cur.execute("INSERT OR IGNORE INTO tweetdeckAccounts VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", insert)
            con.commit()

            returnCode = "OK"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR MAKING CONFIG"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode


def delTweetdeckConfig():
    try:
        p = request.cookies.get("p")
    except:
        p = request.headers["Password"]
    if verify(p, pHash, "newConfig") == True:
        try:
            cur.execute("DELETE FROM accounts WHERE name = ?", (request.headers['AccountName'], ))
            con.commit()

            returnCode = "OK"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR DELETING CONFIG"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode


def stop(request, pHash, isTweetdeck):
    p = request.cookies.get("p")
    if verify(p, pHash, "stop") == True:
        try:
            if isTweetdeck == False:
                if os.path.exists("./configs/{request.headers['AccountName']}.yml"):
                    with open(f"./configs/{request.headers['AccountName']}.yml", "r") as conf:
                        
                        out = ""
                        for i in conf.readlines():
                            if i.startswith("deactivate: 0"):
                                out += "deactivate: 1\n"
                            else:
                                out += f"{i}"
                    with open(f"./configs/{request.headers['AccountName']}.yml", "w") as conf:
                        conf.write(out)

                cur.execute(f"UPDATE accounts SET deactivate = ? WHERE name = ?", (1, request.headers['AccountName']))
                con.commit()
                    
                returnCode = "OK"
                logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
                return returnCode
            else:
                cur.execute(f"UPDATE tweetdeckAccountsTweeting SET deactivate = ? WHERE name = ?", (1, request.headers['AccountName']))
                con.commit()
                    
                returnCode = "OK"
                logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
                return returnCode
        except:
            returnCode = "ERROR EDITING CONFIG"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
        return returnCode


def restart(request, pHash, isTweetdeck):
    p = request.cookies.get("p")
    if verify(p, pHash, "restart") == True:
        try:
            if isTweetdeck == False:
                if os.path.exists(f"./configs/{request.headers['AccountName']}.yml"):
                    with open(f"./configs/{request.headers['AccountName']}.yml", "r") as conf:
                        out = ""
                        for i in conf.readlines():
                            if i.startswith("deactivate: 1"):
                                out += "deactivate: 0\n"
                            else:
                                out += f"{i}"

                    with open(f"./configs/{request.headers['AccountName']}.yml", "w") as conf:
                        conf.write(out)

                cur.execute(f"UPDATE accounts SET deactivate = ? WHERE name = ?", (0, request.headers['AccountName']))
                con.commit()
                    
                returnCode = "OK"
                logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
                return returnCode
            else:
                cur.execute(f"UPDATE tweetdeckAccountsTweeting SET deactivate = ? WHERE name = ?", (0, request.headers['AccountName']))
                con.commit()
                    
                returnCode = "OK"
                logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
                return returnCode
        except:
            returnCode = "ERROR EDITING CONFIG"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
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
        out += f"Number of tweets left: {len(filelist)},\n"
        out += f"Time left until account is out of tweets: {len(filelist) * hours} Hours - {len(filelist) * hours / 24} days."

        returnCode = out
        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
        return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
        return returnCode


# Uses an input of a tweet ID and calls the API to like said tweet
def likeTweet(
    tweet,
    proxy,
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

    p = proxy

    h = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json",
        "Accept-Language": "en-US,en;q=0.5",
        "authorization": f"Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
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

def tweetdeckLikeTweet(
    tweet,
    proxy,
    guest_id,
    ct0,
    kdt,
    twid,
    auth_token,
    gt,
    userAgent,
    userID,
    cookie,
    isOwner
):

    url = "https://api.twitter.com/1.1/favorites/create.json"

    data = f"id={tweet}&cards_platform=Web-13&include_entities=1&include_user_entities=1&include_cards=1&send_error_codes=1&tweet_mode=extended&include_ext_alt_text=true&include_reply_count=true"

    p = proxy

    useCookie = False

    if gt == None or twid == None or guest_id == None:
        useCookie = True
    
    if useCookie == False:
        h = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Accept-Language": "en-US,en;q=0.5",
            "authorization": f"Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
            "Connection": "keep-alive",
            "Content-Length": f"{len(data)}",
            "Cookie": f"guest_id={guest_id}; ct0={ct0}; kdt={kdt}; twid={twid}; auth_token={auth_token}; gt={gt};",
            "DNT": "1",
            "host": "api.twitter.com",
            "origin": "https://tweetdeck.twitter.com",
            "referer": "https://tweetdeck.twitter.com/",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "TE": "trailers",
            "User-Agent": f"{userAgent}",
            "x-csrf-token": f"{ct0}",
            "x-twitter-active-user": "yes",
            "x-twitter-auth-type": "OAuth2Session",
            "x-twitter-client-language": "en",
            "x-act-as-user-id": f"{userID}",
            "x-twitter-client-version": "Twitter-TweetDeck-blackbird-chrome/4.0.220811153004 web/"
        }
    else:
        h = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Accept-Language": "en-US,en;q=0.5",
            "authorization": f"Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
            "Connection": "keep-alive",
            "Content-Length": f"{len(data)}",
            "Cookie": f"{cookie}",
            "DNT": "1",
            "host": "api.twitter.com",
            "origin": "https://tweetdeck.twitter.com",
            "referer": "https://tweetdeck.twitter.com/",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "TE": "trailers",
            "User-Agent": f"{userAgent}",
            "x-csrf-token": f"{ct0}",
            "x-twitter-active-user": "yes",
            "x-twitter-auth-type": "OAuth2Session",
            "x-twitter-client-language": "en",
            "x-act-as-user-id": f"{userID}",
            "x-twitter-client-version": "Twitter-TweetDeck-blackbird-chrome/4.0.220811153004 web/"
        }

    if isOwner == True:
        h.pop("x-act-as-user-id")

    if p != None:
        res = requests.post(url=url, headers=h, data=data, timeout=10, proxies=p)
        print(res.text)
    else:
        res = requests.post(url=url, headers=h, data=data, timeout=10)
        print(res.text)

def deleteTweet(
    request,
    proxy,
    guest_id,
    ct0,
    kdt,
    twid,
    auth_token,
    gt,
    userAgent,
    pHash,
    isTweetdeck,
    **kwargs
):

    data = request.data
    p = request.cookies.get("p")
    if verify(p, pHash, "deleteTweet") == True:
        account = request.headers["AccountName"]

        p = proxy

        try:
            tweet = re.findall("(?<=status/)\d*", str(request.headers["TweetID"]))[0]
        except:
            tweet = request.headers["TweetID"]
        
        try:
            if isTweetdeck == False:
                url = "https://twitter.com/i/api/graphql/VaenaVgh5q5ih7kvyVjgtg/DeleteTweet"

                data = '{"variables":{"tweet_id":"' + tweet + '","dark_request":false},"queryId":"VaenaVgh5q5ih7kvyVjgtg"}'

                h = {
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Content-Type": "application/json",
                    "Accept-Language": "en-US,en;q=0.5",
                    "authorization": f"Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
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

   
            else:
                userID = kwargs.get("userID")
                url = f"https://api.twitter.com/1.1/statuses/destroy/{tweet}.json"

                data = 'cards_platform=Web-13&include_entities=1&include_user_entities=1&include_cards=1&send_error_codes=1&tweet_mode=extended&include_ext_alt_text=true&include_reply_count=true'

                h = {
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Content-Type": "application/json",
                    "Accept-Language": "en-US,en;q=0.5",
                    "authorization": f"Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
                    "Connection": "keep-alive",
                    "Content-Length": f"{len(data)}",
                    "Cookie": f"guest_id={guest_id}; ct0={ct0}; kdt={kdt}; twid={twid}; auth_token={auth_token}; gt={gt}; tweetdeck_version=legacy;",
                    "DNT": "1",
                    "host": "api.twitter.com",
                    "origin": "https://tweetdeck.twitter.com",
                    "referer": f"https://tweetdeck.twitter.com/",
                    "sec-fetch-dest": "empty",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-site": "same-site",
                    "TE": "trailers",
                    "User-Agent": f"{userAgent}",
                    "x-csrf-token": f"{ct0}",
                    "x-act-as-user-id": f"{userID}",
                    "x-twitter-auth-type": "OAuth2Session",
                    "X-Twitter-Client-Version": "Twitter-TweetDeck-blackbird-chrome/4.0.220811153004 web/",
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
                logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
                return returnCode

            returnCode = "OK"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR DELETING TWEET"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
        return returnCode

def changeSettings(request):
    data = request.data
    try:
        data = json.loads(request.data)

        valid = ["hours", "range", "rm", "proxy"]

        if contains_duplicates(list(data.keys())) == True:
            returnCode = "IMPROPER INPUT"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode

        name = request.headers['AccountName']

        res = cur.execute("SELECT name FROM accounts WHERE name = ?", (name,))
        if res.fetchall() != []:

            hours = float(getFromDB("accounts", name, "hours"))
            range = float(getFromDB("accounts", name, "range"))
            rm = getFromDB("accounts", name, "rm")
            proxy = getFromDB("accounts", name, "proxy")

            for i in data:
                print(data[i])
                print(i)
                if i in valid:
                    if i == "rm" and int(data[i]) not in [0, 1]:
                        returnCode = "IMPROPER INPUT"
                        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
                        return returnCode

                    if i == "proxy" and len(str(data[i])) < 0:
                        returnCode = "IMPROPER INPUT"
                        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
                        return returnCode

                    if i == "range" and int(data[i]) < 0:
                        returnCode = "IMPROPER INPUT"
                        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
                        return returnCode
                    elif i == "range" and int(data[i]) > hours:
                        if "hours" in data:
                            if int(data["hours"]) <= int(data[i]):
                                returnCode = "IMPROPER INPUT"
                                logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
                                return returnCode
                        else:
                            returnCode = "IMPROPER INPUT"
                            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
                            return returnCode


                    if i == "hours" and int(data[i]) < 0:
                        returnCode = "IMPROPER INPUT"
                        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
                        return returnCode
                    elif i == "hours" and int(data[i]) < range:
                        if "range" in data:
                            if int(data["range"]) >= int(data[i]):
                                returnCode = "IMPROPER INPUT"
                                logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
                                return returnCode
                        else:
                            returnCode = "IMPROPER INPUT"
                            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
                            return returnCode
                else:
                    returnCode = "IMPROPER INPUT"
                    logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
                    return returnCode

            for i in data:
                if i in valid:
                    if os.path.exists(f"./configs/{request.headers['AccountName']}.yml"):
                        with open(f"./configs/{request.headers['AccountName']}.yml", "r") as conf:
                            out = ""
                            for j in conf.readlines():
                                if j.startswith(f"{i}:"):
                                    out += f"{i}: {data[i]}\n"
                                else:
                                    out += f"{j}"

                        with open(f"./configs/{request.headers['AccountName']}.yml", "w") as conf:
                            conf.write(out)

                    cur.execute(f"UPDATE accounts SET {i} = ? WHERE name = ?", (data[i], request.headers['AccountName']))
                    con.commit()

            returnCode = "OK"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode
        
        res = cur.execute("SELECT name FROM tweetdeckAccountsTweeting WHERE name = ?", (name,))
        if res.fetchall() != []:
            for i in data:
                if i in valid:
                    cur.execute(f"UPDATE tweetdeckAccountsTweeting SET {i} = ? WHERE name = ?", (data[i], request.headers['AccountName']))
                    con.commit()

            returnCode = "OK"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode

        returnCode = "UNABLE TO FIND CONFIG"
        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
        return returnCode
    except:
        returnCode = "ERROR EDITING CONFIG"
        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
        return returnCode

def mediaUpload(request, pHash):
    p = request.cookies.get("p")
    if verify(p, pHash, "mediaUpload") == True:
        try:
            uploaded_files = flask.request.files.getlist("file")

            valid = [".mp4", ".png", ".jpg", ".webm", ".gif"]

            for file in uploaded_files:
                for i in valid:
                    if file.filename.endswith(i):
                        file.save(f"./media/{request.headers['AccountName']}/{werkzeug.utils.secure_filename(file.filename)}")
            
            returnCode = "OK"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR UPLOADING FILE"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
        return returnCode

def mediaDelete(request, pHash):
    p = request.cookies.get("p")
    if verify(p, pHash, "mediaDelete") == True:
        try:
            files = json.loads(request.headers["Files"])

            for i in files:
                os.remove(f"./media/{request.headers['AccountName']}/{i}")
            
            returnCode = "OK"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode
        except:
            returnCode = "ERROR DELETING FILE"
            logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
            return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
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
        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
        return json.dumps({"media": out})
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
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
        logInfo(request.headers.get("user-agent"), request.remote_addr, "RETURNED VIDEO")
        return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
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
        logInfo(request.headers.get("user-agent"), request.remote_addr, "RETURNED UI ELEMENT")
        return returnCode
    else:
        returnCode = "INCORRECT PASSWORD"
        logInfo(request.headers.get("user-agent"), request.remote_addr, returnCode)
        return returnCode
