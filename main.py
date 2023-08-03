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
import traceback as tb


con = sqlite3.connect("database.db", check_same_thread=False)
cur = con.cursor()

cur.execute("CREATE TABLE if not exists keys(name VARCHAR UNIQUE, key, permissions);")
cur.execute("CREATE TABLE if not exists accounts(name VARCHAR UNIQUE, proxy, guest_id, auth_token, ct0, gt, twid, userAgent, kdt, timeAdded, cookie, hours, range, rm, deactivate);")
cur.execute("CREATE TABLE if not exists tweetdeckAccounts(name VARCHAR UNIQUE, guest_id, auth_token, ct0, gt, twid, userAgent, kdt, timeAdded, cookie, proxy);")
cur.execute("CREATE TABLE if not exists userIDs(name, id, owner);")
cur.execute("CREATE TABLE if not exists tweetdeckAccountsTweeting(name VARCHAR UNIQUE, timeAdded, hours, range, rm, deactivate, proxy)")
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
        print(f"INITIALIZING {name}")

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
        print(f"INITIALIZING {name}")

class tweetdeckAccountsTweeting:
    def __init__(self,
        name,
        timeAdded,
        hours,
        range,
        rm,
        deactivate,
        proxy
    ):

        self.name = name
        self.timeAdded = timeAdded
        self.hours = hours
        self.range = range
        self.rm = rm
        self.deactivate = deactivate
        self.proxy = proxy
        print(f"INITIALIZING {name}")

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

# Scrapes the last tweet from an account from a random Nitter instance listed [deprecated]
def grabLastTweet(name, mirrorList):
    for i in range(0, 10):
        try:
            mirror = mirrorList[random.randint(0, len(mirrorList) - 1)]
            res = requests.get(f"https://{mirror}/{name}", timeout=10)
            soup = BeautifulSoup(res.text, "html.parser")
            tweets = soup.find_all(class_="timeline-item")
            for j in tweets:
                if len(j.find_all(class_="pinned")) == 0:
                    tmp = j.find_all(class_="tweet-link")[0]
                    link = re.findall(f"(?<={name}/status/)\d*", tmp["href"])
                    if link != []:
                        return link[0]
        except:
            continue

# Gets the last tweet of a certain account by using the twitter web API and cookies
def grabLastTweetV2(userID, guest_id, ct0, kdt, twid, auth_token, gt, userAgent, proxy):

    url = 'https://twitter.com/i/api/graphql/XicnWRbyQ3WgVY__VataBQ/UserTweets?variables={"userId":"' + str(userID) + '","count":20,"includePromotedContent":true,"withQuickPromoteEligibilityTweetFields":true,"withVoice":true,"withV2Timeline":true}&features={"rweb_lists_timeline_redesign_enabled":true,"responsive_web_graphql_exclude_directive_enabled":true,"verified_phone_label_enabled":false,"creator_subscriptions_tweet_preview_api_enabled":true,"responsive_web_graphql_timeline_navigation_enabled":true,"responsive_web_graphql_skip_user_profile_image_extensions_enabled":false,"tweetypie_unmention_optimization_enabled":true,"responsive_web_edit_tweet_api_enabled":true,"graphql_is_translatable_rweb_tweet_is_translatable_enabled":true,"view_counts_everywhere_api_enabled":true,"longform_notetweets_consumption_enabled":true,"responsive_web_twitter_article_tweet_consumption_enabled":false,"tweet_awards_web_tipping_enabled":false,"freedom_of_speech_not_reach_fetch_enabled":true,"standardized_nudges_misinfo":true,"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled":true,"longform_notetweets_rich_text_read_enabled":true,"longform_notetweets_inline_media_enabled":true,"responsive_web_media_download_video_enabled":false,"responsive_web_enhance_cards_enabled":false}'

    h = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json",
        "Accept-Language": "en-US,en;q=0.5",
        "authorization": f"Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
        "Connection": "keep-alive",
        "Cookie": f"guest_id={guest_id}; ct0={ct0}; kdt={kdt}; twid={twid}; auth_token={auth_token}; gt={gt};",
        "DNT": "1",
        "host": "twitter.com",
        "origin": "https://twitter.com",
        "referer": f"https://twitter.com/intent/user?user_id={userID}",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "TE": "trailers",
        "User-Agent": f"{userAgent}",
        "x-csrf-token": f"{ct0}",
        "x-twitter-active-user": "yes",
        "x-Client-Transaction-Id": "QN3gBTbbrW/H5NGTXK6d0JfZhDLDzdN+H2U+2XYL87NaTrxLIn51G+k9FkaST1RzF29aO0D+3pdiMXSNg6elt7Aq1AURQQ",
        "x-twitter-auth-type": "OAuth2Session",
        "x-twitter-client-language": "en"
    }

    res = requests.get(url=url, headers=h, proxies=proxy)

    output = res.json()


    try:
        uncleaned = output["data"]["user"]["result"]["timeline_v2"]["timeline"]["instructions"][1]["entries"][0]["entryId"]
    except:
        uncleaned = output["data"]["user"]["result"]["timeline_v2"]["timeline"]["instructions"][2]["entries"][0]["entryId"]

    return re.findall('(?<=tweet-)\d{1,200}', uncleaned)[0]


# Returns a dict of which a request using python's request module can use, with an input of just text
def genProxyDict(input):
    return {
        "http": f"{input}",
        "https": f"{input}"
    }

# Returns an object taken from a YAML config file for each account
def allSettings(name):
    with open(f"./configs/{name}.yml", "r") as f:
        template = yaml.safe_load(f)
        return template

# Returns a specific setting from a database
def getFromDB(db, name, setting):
    res = cur.execute(f"SELECT {setting} FROM {db} WHERE name = ?", (name,))
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

# Reads through accounts in the SQL database and reads through .yml files to add to a cache in memory for information to be stored easier
def readAccounts(accountDict, nextTweetDict, filelistDict, hoursDict):
    for i in os.listdir("./configs/"):
        try:
            nameSplit = i.split(".")[0]
            template = allSettings(nameSplit)
        except:
            continue

        if nameSplit not in accountDict:
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
            accountDict[i[0]] = Account(
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

            nextTweetDict[i[0]] = calculateNextTweetTime(time.time(), hoursDict[i[0]], i[12])

            print(f"Next Tweet of {i[0]}: {datetime.utcfromtimestamp(nextTweetDict[i[0]])}")


# Reads through .yml files and SQL database to add to a memory cache, same as the last function but saves all of the data in a different format to fit with Tweetdeck integration
def tweetdeckReadAccounts(tweetdeckDict, userIDDict, tweetdeckTweetingDict, nextTweetDict):
    if os.path.isdir("./tweetdeck_configs/"):
        for i in os.listdir("./tweetdeck_configs/"):
            try:
                nameSplit = i.split(".")[0]
                template = allSettings(nameSplit)
            except:
                continue

            if nameSplit not in tweetdeckDict:
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

                    with open(f"./tweetdeck_userids/{nameSplit}.txt", "r") as f:
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
                            template["proxy"],
                        )
                    ]

                    cur.executemany("INSERT INTO tweetdeckAccounts VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", insert)
                    con.commit()

    res = cur.execute("SELECT * FROM tweetdeckAccounts")
    fetched = res.fetchall()
    if len(fetched) > len(tweetdeckDict):
        for i in fetched:
            if i[0] not in tweetdeckDict:
                tweetdeckDict[i[0]] = TweetdeckAccount(
                    name=i[0],
                    guest_id=i[1],
                    auth_token=i[2],
                    ct0=i[3],
                    gt=i[4],
                    twid=i[5],
                    userAgent=i[6],
                    kdt=i[7],
                    timeAdded=i[8],
                    cookie=i[9],
                )

    res = cur.execute("SELECT * FROM tweetdeckAccountsTweeting")
    for i in res.fetchall():
        if i[0] not in tweetdeckTweetingDict:
            tweetdeckTweetingDict[i[0]] = tweetdeckAccountsTweeting(
                name=i[0],
                timeAdded=i[1],
                hours=i[2],
                range=i[3],
                rm=i[4],
                deactivate=i[5],
                proxy=i[6]
            )
            filelistDict[i[0]] = api.getList(i[0])
            hoursDict[i[0]] = i[2]

            nextTweetDict[i[0]] = calculateNextTweetTime(i[1], hoursDict[i[0]], i[3])


def fixBug(name):
    if name not in nextTweet:
        res = cur.execute("SELECT * FROM accounts WHERE name = ?", (name,))
        fetched = res.fetchone()
        nextTweet[name] = calculateNextTweetTime(fetched[9], hoursDict[name], fetched[12])

# Periodically checks if an account should tweet or not, and tweets if the current time is after the timestamp set for the next time to tweet per each account, then after that, it sets a new time for the next tweet
def checkTweets(accountDict, filelistDict, hoursDict, tweetdeckTweeting):
    print("Checking for tweets...")
    for i in accountDict:
        filelistDict[i] = api.getList(i)
        hoursDict[i] = float(getFromDB("accounts", i, "hours"))
        fixBug(i)
        if nextTweet[i] < time.time() and len(filelistDict[i]) > 0:
            print("Making Tweet...")
            nextTweet[i] = calculateNextTweetTime(time.time(), hoursDict[i], float(getFromDB("accounts", i, "range")))
            makeTweet(i, filelistDict, accountDict=accountDict)
            print(f"Next tweet of {i}: {datetime.utcfromtimestamp(nextTweet[i])}")

    for i in tweetdeckTweeting:
        filelistDict[i] = api.getList(i)
        hoursDict[i] = float(getFromDB("tweetdeckAccountsTweeting", i, "hours"))
        fixBug(i)
        if nextTweet[i] < time.time() and len(filelistDict[i]) > 0:
            print("Making Tweet...")
            nextTweet[i] = calculateNextTweetTime(time.time(), hoursDict[i], float(getFromDB("tweetdeckAccountsTweeting", i, "range")))
            makeTweet(i, filelistDict, tweetdeckAccountsTweeting=tweetdeckTweeting)
            print(f"Next tweet of {i}: {datetime.utcfromtimestamp(nextTweet[i])}")

# Periodically checks if there is a new tweet on an account, and then likes it
def autolike(accounts, mirrorList, autolikes):
    if len(autolikes) == 0:
        return
    print("Checking Autolikes...")
    for i in autolikes:
        print(i.name)

        proxy = getFromDB("accounts", i.accounts[0], "proxy")

        tweet = grabLastTweetV2(
            i.name, 
            accounts[i.accounts[0]].guest_id,
            accounts[i.accounts[0]].ct0,
            accounts[i.accounts[0]].kdt,
            accounts[i.accounts[0]].twid,
            accounts[i.accounts[0]].auth_token,
            accounts[i.accounts[0]].gt,
            accounts[i.accounts[0]].userAgent,
            genProxyDict(proxy)
        )

        print(tweet)
        if i.lastTweet != tweet:
            if i.isRandom == False:
                names = {}

                res = cur.execute("SELECT name FROM accounts")
                accs = res.fetchall()

                for j in accs:
                    names[j[0]] = {"name": j[0], "isTweetdeck": False}

                res = cur.execute("SELECT * FROM userIDs")
                userIDs = res.fetchall()
                
                for j in userIDs:
                    names[j[0]] = {"name": j[0], "isTweetdeck": True}

                for j in i.accounts:
                    if j in names:
                        if names[j]["isTweetdeck"] == False:
                            proxy = getFromDB("accounts", j, "proxy")

                            api.likeTweet(
                                tweet=tweet,
                                proxy=genProxyDict(proxy),
                                guest_id=accounts[j].guest_id,
                                ct0=accounts[j].ct0,
                                kdt=accounts[j].kdt,
                                twid=accounts[j].twid,
                                auth_token=accounts[j].auth_token,
                                gt=accounts[j].gt,
                                userAgent=accounts[j].userAgent,
                            )
                            
                        if names[j]["isTweetdeck"] == True:
                            userID = getFromDB("userIDs", j, "id")
                            owner = getFromDB("userIDs", j, "owner")
                            proxy = getFromDB("tweetdeckAccounts", owner, "proxy")

                            if owner == j:
                                isOwner = True
                            else:
                                isOwner = False


                            api.tweetdeckLikeTweet(
                                tweet=tweet,
                                proxy=genProxyDict(proxy),
                                guest_id=tweetdeckAccounts[owner].guest_id,
                                ct0=tweetdeckAccounts[owner].ct0,
                                kdt=tweetdeckAccounts[owner].kdt,
                                twid=tweetdeckAccounts[owner].twid,
                                auth_token=tweetdeckAccounts[owner].auth_token,
                                gt=tweetdeckAccounts[owner].gt,
                                userAgent=tweetdeckAccounts[owner].userAgent,
                                userID=userID,
                                cookie=tweetdeckAccounts[owner].cookie,
                                isOwner=isOwner
                            )
                        i.lastTweet = tweet
                        log = f"{j} AutoLiked {tweet} at {datetime.utcfromtimestamp(time.time())}"
                        logData(log, "like")

            elif i.isRandom == True:
                names = []

                res = cur.execute("SELECT name FROM accounts")
                accs = res.fetchall()

                for j in accs:
                    names.append({"name": j[0], "isTweetdeck": False})

                res = cur.execute("SELECT name FROM userIDs")
                userIDs = res.fetchall()
                
                for j in userIDs:
                    names.append({"name": j[0], "isTweetdeck": True})
                    
                for j in range(0, len(i.accounts)):
                    idx = random.randint(0, len(names) - 1)
                    name = names[idx]

                    if name["isTweetdeck"] == False:
                        proxy = getFromDB("accounts", name["name"], "proxy")

                        api.likeTweet(
                            tweet=tweet,
                            proxy=genProxyDict(proxy),
                            guest_id=accounts[name["name"]].guest_id,
                            ct0=accounts[name["name"]].ct0,
                            kdt=accounts[name["name"]].kdt,
                            twid=accounts[name["name"]].twid,
                            auth_token=accounts[name["name"]].auth_token,
                            gt=accounts[name["name"]].gt,
                            userAgent=accounts[name["name"]].userAgent,
                        )
                    else:
                        userID = getFromDB("userIDs", name["name"], "id")
                        owner = getFromDB("userIDs", name["name"], "owner")
                        proxy = getFromDB("tweetdeckAccounts", owner, "proxy")

                        if owner == j:
                            isOwner = True
                        else:
                            isOwner = False

                        api.tweetdeckLikeTweet(
                            tweet=tweet,
                            proxy=genProxyDict(proxy),
                            guest_id=tweetdeckAccounts[owner].guest_id,
                            ct0=tweetdeckAccounts[owner].ct0,
                            kdt=tweetdeckAccounts[owner].kdt,
                            twid=tweetdeckAccounts[owner].twid,
                            auth_token=tweetdeckAccounts[owner].auth_token,
                            gt=tweetdeckAccounts[owner].gt,
                            userAgent=tweetdeckAccounts[owner].userAgent,
                            userID=userID,
                            cookie=tweetdeckAccounts[owner].cookie,
                            isOwner=isOwner
                        )

                    names.pop(idx)
            i.lastTweet = tweet
        time.sleep(random.randint(30, 120))


# Uploads a file and tweets using that file as media for that tweet
# Does not tweet with text attached to the tweet, only tweets media
def makeTweet(name, filelistDict, **kwargs):
    try:
        if "accountDict" in kwargs:
            accountDict = kwargs["accountDict"]

            idx = random.randint(0, len(filelistDict[name]) - 1)
            file = filelistDict[name][idx]
            with open(f"./media/{name}/{file}", "rb") as md:
                
                md_bytes = md.read()
                md_size = len(md_bytes)

                proxy = getFromDB("accounts", name, "proxy")

                if md_size > 4000000 or file.endswith(".mp4") or file.endswith(".gif"):
                    print("CHUNKED UPLOAD")
                    
                    upload.chunkedUpload(
                        proxy=genProxyDict(proxy),
                        guest_id=accountDict[name].guest_id,
                        gt=accountDict[name].gt,
                        ct0=accountDict[name].ct0,
                        kdt=accountDict[name].kdt,
                        twid=accountDict[name].twid,
                        auth_token=accountDict[name].auth_token,
                        userAgent=accountDict[name].userAgent,
                        md=md,
                        md_bytes=md_bytes,
                        md_size=md_size,
                        file=file
                    )
                else:
                    print("REGULAR UPLOAD")
                    upload.regularUpload(
                        proxy=genProxyDict(proxy),
                        gt=accountDict[name].gt,
                        ct0=accountDict[name].ct0,
                        kdt=accountDict[name].kdt,
                        twid=accountDict[name].twid,
                        auth_token=accountDict[name].auth_token,
                        userAgent=accountDict[name].userAgent,
                        md=md,
                        md_bytes=md_bytes,
                        md_size=md_size,
                        file=file
                    )

                print("TWEET DONE")
                log = f"{name} Tweeted {file} at {datetime.utcfromtimestamp(time.time())}"
                logData(log, "tweet")
                        
            try:
                del filelistDict[name][idx]
                print("DELETE FROM MEMORY DONE")
            except:
                print("ERROR DELETING FROM MEMORY")

            if int(getFromDB("accounts", name, "rm")) == 1:
                try:
                    os.remove(f"./media/{name}/{file}")
                    print("DELETE FILE LOCALLY DONE")
                except:
                    print("ERROR DELETING FILE LOCALLY")

        elif "tweetdeckAccountsTweeting" in kwargs:
            tweetdeckTweeting = kwargs["tweetdeckAccountsTweeting"]

            idx = random.randint(0, len(filelistDict[name]) - 1)
            file = filelistDict[name][idx]
            with open(f"./media/{name}/{file}", "rb") as md:
                
                md_bytes = md.read()
                md_size = len(md_bytes)

                res = cur.execute("SELECT owner, id FROM userIDs WHERE name = ?",(name,))
                fetched = res.fetchone()
                owner = fetched[0]
                userID = fetched[1]

                proxy = getFromDB("tweetdeckAccountsTweeting", name, "proxy")

                if md_size > 4000000 or file.endswith(".mp4") or file.endswith(".gif"):
                    print("CHUNKED UPLOAD")
                    
                    upload.chunkedUpload(
                        proxy=genProxyDict(proxy),
                        guest_id=tweetdeckAccounts[owner].guest_id,
                        gt=tweetdeckAccounts[owner].gt,
                        ct0=tweetdeckAccounts[owner].ct0,
                        kdt=tweetdeckAccounts[owner].kdt,
                        twid=tweetdeckAccounts[owner].twid,
                        auth_token=tweetdeckAccounts[owner].auth_token,
                        userAgent=tweetdeckAccounts[owner].userAgent,
                        md=md,
                        md_bytes=md_bytes,
                        md_size=md_size,
                        file=file,
                        isTweetdeck=True,
                        userID=userID
                    )
                else:
                    print("REGULAR UPLOAD")
                    upload.regularUpload(
                        proxy=genProxyDict(proxy),
                        gt=tweetdeckAccounts[name].gt,
                        ct0=tweetdeckAccounts[name].ct0,
                        kdt=tweetdeckAccounts[name].kdt,
                        twid=tweetdeckAccounts[name].twid,
                        auth_token=tweetdeckAccounts[name].auth_token,
                        userAgent=tweetdeckAccounts[name].userAgent,
                        md=md,
                        md_bytes=md_bytes,
                        md_size=md_size,
                        file=file,
                        isTweetdeck=True,
                        userID=userID
                    )

                print("TWEET DONE")
                log = f"{name} Tweeted {file} at {datetime.utcfromtimestamp(time.time())}"
                logData(log, "tweet")

            try:
                del filelistDict[name][idx]
                print("DELETE FROM MEMORY DONE")
            except:
                print("ERROR DELETING FROM MEMORY")

            if int(getFromDB("tweetdeckAccountsTweeting", name, "rm")) == 1:
                try:
                    os.remove(f"./media/{name}/{file}")
                    print("DELETE FILE LOCALLY DONE")
                except:
                    print("ERROR DELETING FILE LOCALLY")

    except:
        print("ERROR UPLOADING")

app = Flask(__name__)

# Rudimentary way of telling the user information about a certain account, could probably use some improvement
@app.route("/getData", methods=["GET"])
def getData():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "getData") == True:
            name = str(request.headers["AccountName"])
            
            res = cur.execute("SELECT name FROM accounts WHERE name = ?", (name,))
            if res.fetchall() != []:
                hours = getFromDB("accounts", name, "hours")
                deactivate = getFromDB("accounts", name, "deactivate")


            res = cur.execute("SELECT name FROM tweetdeckAccountsTweeting WHERE name = ?", (name,))
            if res.fetchall() != []:
                hours = getFromDB("tweetdeckAccountsTweeting", name, "hours")
                deactivate = getFromDB("tweetdeckAccountsTweeting", name, "deactivate")

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
    try:
        return api.getAccounts(request, pHash)
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

# Adds a new account to the database and into memory, might add a GUI frontend for making this easier to set up, but it's probably better if I don't do that anyway
@app.route("/newConfig", methods=["POST"])
def newConfig():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "newConfig") == True:
            template = yaml.safe_load(request.data)
            res = cur.execute("SELECT * FROM accounts WHERE name = ?", (template["name"], ))
            if len(res.fetchall()) > 0:
                returnCode = "ACCOUNT ALREADY EXISTS"
                api.logInfo(request.headers, request.remote_addr, returnCode)
                return returnCode

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

            nextTweet[template["name"]] = calculateNextTweetTime(timeAdded, template["hours"], template["range"])
            return api.newConfig(request, pHash, template)
        else:
            returnCode = "INCORRECT PASSWORD"
            api.logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/delConfig", methods=["POST"])
def delConfig():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "delConfig") == True:
            accounts.pop(request.headers["AccountName"])
            return api.delConfig(request, pHash)
        else:
            returnCode = "INCORRECT PASSWORD"
            api.logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

# Adds a new tweetdeck account to the database and to memory, same thing as the newConfig function
@app.route("/newTweetdeckConfig", methods=["POST"])
def newTweetdeckConfig():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "newTweetdeckConfig") == True:
            template = yaml.safe_load(request.data)
            res = cur.execute("SELECT * FROM tweetdeckAccounts WHERE name = ?", (template["name"], ))
            if len(res.fetchall()) > 0:
                returnCode = "ACCOUNT ALREADY EXISTS"
                api.logInfo(request.headers, request.remote_addr, returnCode)
                return returnCode

            timeAdded = time.time()
            tweetdeckAccounts[template["name"]] = TweetdeckAccount(
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
        else:
            returnCode = "INCORRECT PASSWORD"
            api.logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/getTweetdeckAccounts", methods=["GET"])
def getTweetdeckAccounts():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "getTweetdeckAccounts") == True:
            res = cur.execute("SELECT name FROM tweetdeckAccounts")
            returnCode = json.dumps(res.fetchall())
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

@app.route("/delTweetdeckConfig", methods=["POST"])
def delTweetdeckConfig():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "delTweetdeckConfig") == True:
            tweetdeckAccounts.pop(request.headers["AccountName"])
            return api.delTweetdeckConfig(request, pHash)
        else:
            returnCode = "INCORRECT PASSWORD"
            api.logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/newUserIDs", methods=["POST"])
def newUserIDs():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "newUserIDs") == True:
            template = yaml.safe_load(request.data)
            insert = []
            for i in template.keys():
                userIDDict[i] = template[i]
                insert.append((i, template[i], request.headers["AccountName"]))

            cur.execute("DELETE FROM userIDs WHERE owner = ?;", (request.headers["AccountName"],))

            cur.executemany("INSERT OR IGNORE INTO userIDs VALUES(?, ?, ?);", insert)
            con.commit()

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

@app.route("/delUserIDs", methods=["POST"])
def delUserIDs():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "delUserIDs") == True:
            template = yaml.safe_load(request.data)
            cur.execute("DELETE FROM userIDs where owner = ?", (request.headers["AccountName"],))
            con.commit()
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

@app.route("/getUserIDs", methods=["GET"])
def getUserIDs():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "getUserIDs") == True:
            res = cur.execute("SELECT * FROM userIDs")
            returnCode = json.dumps(res.fetchall())
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

@app.route("/newTweetdeckTweeting", methods=["POST"])
def newTweetdeckTweeting():
    try:
        res = cur.execute("SELECT name FROM userIDs WHERE name = ?", (request.headers["AccountName"],))
        fetched = res.fetchall()
        if len(fetched) > 0:
            for i in fetched:

                insert = (
                    request.headers["AccountName"],
                    time.time(),
                    4,
                    2,
                    1,
                    0,
                    ""
                )

                cur.execute("INSERT OR IGNORE INTO tweetdeckAccountsTweeting VALUES(?, ?, ?, ?, ?, ?, ?)", insert)
                con.commit()

                nextTweet[request.headers["AccountName"]] = calculateNextTweetTime(time.time(), 4, 2)

                returnCode = "OK"
                api.logInfo(request.headers, request.remote_addr, returnCode)
                return returnCode
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
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "likeTweet") == True:
            data = json.loads(request.data)

            try:
                tweet = re.findall("(?<=status/)\d*", request.headers["TweetID"])[0]
            except:
                tweet = request.headers["TweetID"]

            if data["isRandom"] == True:
                names = []

                res = cur.execute("SELECT name FROM accounts")
                accs = res.fetchall()

                for i in accs:
                    names.append({"name": i[0], "isTweetdeck": False})

                res = cur.execute("SELECT * FROM userIDs")
                userIDs = res.fetchall()
                
                for i in userIDs:
                    names.append({"name": i[0], "isTweetdeck": True})

                try:
                    num = int(data["accounts"])
                    isInt = True
                except:
                    isInt = False

                
                if isInt == True:
                    for i in range(0, int(data["accounts"])):
                        idx = random.randint(0, len(names) - 1)
                        name = names[idx]

                        if name["isTweetdeck"] == False:
                            proxy = getFromDB("accounts", name, "proxy")

                            api.likeTweet(
                                tweet=tweet,
                                proxy=genProxyDict(proxy),
                                guest_id=accounts[name].guest_id,
                                ct0=accounts[name].ct0,
                                kdt=accounts[name].kdt,
                                twid=accounts[name].twid,
                                auth_token=accounts[name].auth_token,
                                gt=accounts[name].gt,
                                userAgent=accounts[name].userAgent,
                            )
                        else:
                            userID = getFromDB("userIDs", name["name"], "id")
                            owner = getFromDB("userIDs", name["name"], "owner")
                            proxy = getFromDB("tweetdeckAccounts", owner, "proxy")

                            if owner == i:
                                isOwner = True
                            else:
                                isOwner = False

                            api.tweetdeckLikeTweet(
                                tweet=tweet,
                                proxy=genProxyDict(proxy),
                                guest_id=tweetdeckAccounts[owner].guest_id,
                                ct0=tweetdeckAccounts[owner].ct0,
                                kdt=tweetdeckAccounts[owner].kdt,
                                twid=tweetdeckAccounts[owner].twid,
                                auth_token=tweetdeckAccounts[owner].auth_token,
                                gt=tweetdeckAccounts[owner].gt,
                                userAgent=tweetdeckAccounts[owner].userAgent,
                                userID=userID,
                                cookie=tweetdeckAccounts[owner].cookie,
                                isOwner=isOwner
                            )

                        names.pop(idx)
                        time.sleep(random.randint(30, 120))
                else:
                    returnCode = "ERROR"
                    api.logInfo(request.headers, request.remote_addr, returnCode)
                    return returnCode

            elif data["isRandom"] == False:
                names = {}

                res = cur.execute("SELECT name FROM accounts")
                accs = res.fetchall()

                for i in accs:
                    names[i[0]] = {"name": i[0], "isTweetdeck": False}

                res = cur.execute("SELECT * FROM userIDs")
                userIDs = res.fetchall()
                
                for i in userIDs:
                    names[i[0]] = {"name": i[0], "isTweetdeck": True}

                for i in data["accounts"]:

                    if i in names:
                        if names[i]["isTweetdeck"] == False:
                            proxy = getFromDB("accounts", i, "proxy")

                            api.likeTweet(
                                tweet=tweet,
                                proxy=genProxyDict(proxy),
                                guest_id=accounts[i].guest_id,
                                ct0=accounts[i].ct0,
                                kdt=accounts[i].kdt,
                                twid=accounts[i].twid,
                                auth_token=accounts[i].auth_token,
                                gt=accounts[i].gt,
                                userAgent=accounts[i].userAgent,
                            )
                            
                        if names[i]["isTweetdeck"] == True:
                            userID = getFromDB("userIDs", i, "id")
                            owner = getFromDB("userIDs", i, "owner")
                            proxy = getFromDB("tweetdeckAccounts", owner, "proxy")

                            if owner == i:
                                isOwner = True
                            else:
                                isOwner = False


                            api.tweetdeckLikeTweet(
                                tweet=tweet,
                                proxy=genProxyDict(proxy),
                                guest_id=tweetdeckAccounts[owner].guest_id,
                                ct0=tweetdeckAccounts[owner].ct0,
                                kdt=tweetdeckAccounts[owner].kdt,
                                twid=tweetdeckAccounts[owner].twid,
                                auth_token=tweetdeckAccounts[owner].auth_token,
                                gt=tweetdeckAccounts[owner].gt,
                                userAgent=tweetdeckAccounts[owner].userAgent,
                                userID=userID,
                                cookie=tweetdeckAccounts[owner].cookie,
                                isOwner=isOwner
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

    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

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

                proxy = getFromDB("accounts", i, "proxy")

                api.likeTweet(
                    tweet=request.headers["TweetID"],
                    proxy=genProxyDict(proxy),
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
        p = request.cookies.get("p")
        if verify(p, pHash, "deleteTweet") == True:
            res = cur.execute("SELECT name FROM accounts WHERE name = ?", (request.headers["AccountName"],))
            if res.fetchall() != []:
                name = str(request.headers["AccountName"])
                proxy = None

                proxy = getFromDB("accounts", name, "proxy")
                    
                return api.deleteTweet(
                    request=request,
                    proxy=genProxyDict(proxy),
                    guest_id=accounts[name].guest_id,
                    ct0=accounts[name].ct0,
                    kdt=accounts[name].kdt,
                    twid=accounts[name].twid,
                    auth_token=accounts[name].auth_token,
                    gt=accounts[name].gt,
                    userAgent=accounts[name].userAgent,
                    pHash=pHash,
                    isTweetdeck=False
                )
                returnCode = "OK"
                api.logInfo(request.headers, request.remote_addr, returnCode)
                return returnCode

            res = cur.execute("SELECT name FROM tweetdeckAccountsTweeting WHERE name = ?", (request.headers["AccountName"],))
            if res.fetchall() != []:
                name = str(request.headers["AccountName"])
                proxy = None

                proxy = getFromDB("tweetdeckAccountsTweeting", name, "proxy")

                res = cur.execute("SELECT owner, id FROM userIDs WHERE name = ?",(name,))
                fetched = res.fetchone()
                owner = fetched[0]
                userID = fetched[1]
                    
                return api.deleteTweet(
                    request=request,
                    proxy=genProxyDict(proxy),
                    guest_id=tweetdeckAccounts[owner].guest_id,
                    ct0=tweetdeckAccounts[owner].ct0,
                    kdt=tweetdeckAccounts[owner].kdt,
                    twid=tweetdeckAccounts[owner].twid,
                    auth_token=tweetdeckAccounts[owner].auth_token,
                    gt=tweetdeckAccounts[owner].gt,
                    userAgent=tweetdeckAccounts[owner].userAgent,
                    pHash=pHash,
                    isTweetdeck=True,
                    userID=userID
                )
                returnCode = "OK"
                api.logInfo(request.headers, request.remote_addr, returnCode)
                return returnCode

            returnCode = "ACCOUNT NOT FOUND"
            api.logInfo(request.headers, request.remote_addr, returnCode)
            return returnCode
    except:
        returnCode = "ERROR"
        api.logInfo(request.headers, request.remote_addr, returnCode)
        return returnCode

@app.route("/stop", methods=["POST"])
def stop():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "stop") == True:
            res = cur.execute("SELECT name FROM accounts WHERE name = ?", (request.headers["AccountName"],))
            if res.fetchall() != []:
                returnCode = api.stop(request, pHash, isTweetdeck=False)

            res = cur.execute("SELECT name FROM tweetdeckAccountsTweeting WHERE name = ?", (request.headers["AccountName"],))
            if res.fetchall() != []:
                returnCode = api.stop(request, pHash, isTweetdeck=True)
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
            res = cur.execute("SELECT name FROM accounts WHERE name = ?", (request.headers["AccountName"],))
            if res.fetchall() != []:
                returnCode = api.restart(request, pHash, isTweetdeck=False)
                nextTweet[request.headers["AccountName"]] = calculateNextTweetTime(
                    time.time(),
                    float(getFromDB("accounts", request.headers["AccountName"], "hours")),
                    float(getFromDB("accounts", request.headers["AccountName"], "range"))
                )
                print(nextTweet[request.headers["AccountName"]])
                return returnCode
            res = cur.execute("SELECT name FROM tweetdeckAccountsTweeting WHERE name = ?", (request.headers["AccountName"],))
            if res.fetchall() != []:
                returnCode = api.restart(request, pHash, isTweetdeck=True)
                nextTweet[request.headers["AccountName"]] = calculateNextTweetTime(
                    time.time(),
                    float(getFromDB("tweetdeckAccountsTweeting", request.headers["AccountName"], "hours")),
                    float(getFromDB("tweetdeckAccountsTweeting", request.headers["AccountName"], "range"))
                )
                print(nextTweet[request.headers["AccountName"]])
                return returnCode

            returnCode = "ERROR"
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

@app.route("/getSettings", methods=["GET"])
def getSettings():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "getSettings") == True:
            res = cur.execute("SELECT hours, range, rm, proxy FROM accounts WHERE name = ?", (request.headers['AccountName'], ))
            fetched = res.fetchall()
            if fetched == []:
                res = cur.execute("SELECT hours, range, rm, proxy FROM tweetdeckAccountsTweeting WHERE name = ?", (request.headers['AccountName'], ))
                fetched = res.fetchall()
                
            
            out = fetched[0]

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
            nextTweet[request.headers["AccountName"]] = calculateNextTweetTime(time.time(), data["hours"], data["range"])
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

@app.route("/delLogs", methods=["POST"])
def delLogs():
    try:
        p = request.cookies.get("p")
        if verify(p, pHash, "delLogs") == True:
            for i in os.listdir("./logs"):
                print(f"./logs/{i}")
                os.remove(f"./logs/{i}")
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
tweetdeckAccounts = manager.dict()
tweetdeckTweeting = manager.dict()
userIDDict = {}

def startBot():
    print("INITIALIZED")
    while True:
        try:
            readAccounts(accounts, nextTweet, filelistDict, hoursDict)
        except Exception as e:
            logData(f"{''.join(tb.format_exception(None, e, e.__traceback__))}","error")
        try:
            tweetdeckReadAccounts(tweetdeckAccounts, userIDDict, tweetdeckTweeting, nextTweet)
        except Exception as e:
            logData(f"{''.join(tb.format_exception(None, e, e.__traceback__))}","error")
        try:
            checkTweets(accounts, filelistDict, hoursDict, tweetdeckTweeting)
        except Exception as e:
            logData(f"{''.join(tb.format_exception(None, e, e.__traceback__))}","error")
        try:
            autolike(accounts, mirrorList, autolikes)
        except Exception as e:
            logData(f"{''.join(tb.format_exception(None, e, e.__traceback__))}","error")
        time.sleep(30)


if __name__ == "__main__":
    p = mp.Process(target=startTerm)
    p.start()
    startBot()
    
with open("./shadow.yml", "r") as f:
    template = yaml.safe_load(f)
    pHash = template["main"]