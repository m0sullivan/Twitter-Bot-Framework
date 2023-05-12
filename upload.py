import requests
import json
import random
import os
import yaml
import base64
import math
import time

def regularUpload(
    authorization,
    ct0,
    kdt,
    twid,
    auth_token,
    userAgent,
    gt,
    name,
    md,
    md_bytes,
    md_size,
    file
):

    md_b64 = base64.b64encode(md_bytes)
    url = "https://upload.twitter.com/i/media/upload.json"

    upload_image = {
        "media_data":md_b64,
        "media_category":"tweet_image",
    }

    h = {
        "Accept-Language": "en-US,en;q=0.5",
        "authorization": f"Bearer {authorization}",
        "Connection": "keep-alive",
        "Content-Length": "0",
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": f"ct0={ct0}; kdt={kdt}; twid={twid}; auth_token={auth_token};",
        "Host": "upload.twitter.com",
        "Origin": "https://twitter.com",
        "Referer": "https://twitter.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "TE": "trailers",
        "User-Agent": f"{userAgent}",
        "x-csrf-token": f"{ct0}",
        "x-twitter-auth-type": "OAuth2Session"
    }

    try:
        resImage = requests.post(url, headers=h, data=upload_image, timeout=10)
        print(resImage.text)
    except:
        print("ERROR UPLOADING IMAGE")
        return

    media_id = str(json.loads(resImage.text)["media_id_string"])
    data = '{"variables":{"tweet_text":"","dark_request":false,"media":{"media_entities":[{"media_id":"' + media_id + '","tagged_users":[]}],"possibly_sensitive":false},"semantic_annotation_ids":[]},"features":{"tweetypie_unmention_optimization_enabled":true,"vibe_api_enabled":true,"responsive_web_edit_tweet_api_enabled":true,"graphql_is_translatable_rweb_tweet_is_translatable_enabled":true,"view_counts_everywhere_api_enabled":true,"longform_notetweets_consumption_enabled":true,"tweet_awards_web_tipping_enabled":false,"interactive_text_enabled":true,"responsive_web_text_conversations_enabled":false,"longform_notetweets_rich_text_read_enabled":true,"blue_business_profile_image_shape_enabled":true,"responsive_web_graphql_exclude_directive_enabled":true,"verified_phone_label_enabled":false,"freedom_of_speech_not_reach_fetch_enabled":false,"standardized_nudges_misinfo":true,"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled":false,"responsive_web_graphql_skip_user_profile_image_extensions_enabled":false,"responsive_web_graphql_timeline_navigation_enabled":true,"responsive_web_enhance_cards_enabled":false},"queryId":"1RyAhNwby-gzGCRVsMxKbQ"}'

    h = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json",
        "Content-Length": f"{len(data)}",
        "Accept-Language": "en-US,en;q=0.5",
        "authorization": f"Bearer {authorization}",
        "Connection": "keep-alive",
        "Cookie": f"gt={gt}; ct0={ct0}; kdt={kdt}; twid={twid}; auth_token={auth_token};",
        "host": "twitter.com",
        "origin": "https://twitter.com",
        "referer": "https://twitter.com/compose/tweet",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "User-Agent": f"{userAgent}",
        "x-csrf-token": f"{ct0}",
        "x-guest-token": f"{gt}",
        "x-twitter-active-user": "yes",
        "x-twitter-client-language": "en"
    }

    tweeturl = "https://twitter.com/i/api/graphql/1RyAhNwby-gzGCRVsMxKbQ/CreateTweet"

    time.sleep(3)

    try:
        resTweet = requests.post(tweeturl, headers=h, data=data, timeout=10)
        print(resTweet.text)
    except:
        print("ERROR TWEETING")

def chunkedUpload(
    authorization,
    guest_id,
    gt,
    ct0,
    kdt,
    twid,
    auth_token,
    userAgent,
    name,
    md,
    md_bytes,
    md_size,
    file
):

    chunked_headers = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.5",
        "authorization": f"Bearer {authorization}",
        "Connection": "keep-alive",
        "Content-Length": "0",
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": f"guest_id={guest_id}; gt={gt}; ct0={ct0}; kdt={kdt}; twid={twid}; auth_token={auth_token};",
        "Host": "upload.twitter.com",
        "Origin": "https://twitter.com",
        "Referer": "https://twitter.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "TE": "trailers",
        "User-Agent": f"{userAgent}",
        "x-csrf-token": f"{ct0}",
        "x-twitter-auth-type": "OAuth2Session"
    }

    if file.endswith(".mp4"):
        mediaType = "video/mp4"
        mediaCategory = "tweet_video"
    elif file.endswith(".gif"):
        mediaType = "image/gif"
        mediaCategory = "tweet_gif"
    elif file.endswith(".png"):
        mediaType = "image/png"
        mediaCategory = "tweet_image"
    elif file.endswith(".jpg"):
        mediaType = "image/jpg"
        mediaCategory = "tweet_image"
    elif file.endswith(".webp"):
        mediaType = "image/webp"
        mediaCategory = "tweet_image"
    else:
        print("ERROR")
        return

    initurl = f"https://upload.twitter.com/i/media/upload.json?command=INIT&total_bytes={md_size}&media_type={mediaType}&media_category={mediaCategory}"

    try:
        resinit = requests.post(url=initurl, headers=chunked_headers, timeout=10)
        j = json.loads(resinit.text)
        print(resinit.text)
    except:
        print("ERROR INIT")


    chunkCount = math.floor(md_size/4000000) + 2

    for i in range(0, chunkCount):
        
        startidx = math.floor((md_size/chunkCount) * i)
        endidx = math.floor(((md_size/chunkCount) * (i + 1)) - 1)

        chunk = md_bytes[startidx:endidx + 1]
        print(f"{startidx} {endidx}")


        append_headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.5",
            "authorization": f"Bearer {authorization}",
            "Connection": "keep-alive",
            "Content-Length": f"{(endidx - startidx) + 1}",
            "Cookie": f"gt={gt}; ct0={ct0}; kdt={kdt}; twid={twid}; auth_token={auth_token};",
            "Host": "upload.twitter.com",
            "Origin": "https://twitter.com",
            "Referer": "https://twitter.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "TE": "trailers",
            "User-Agent": f"{userAgent}",
            "x-csrf-token": f"{ct0}",
            "x-twitter-auth-type": "OAuth2Session"
        }

        files = {
            "media": chunk
        }

        appendurl = f"https://upload.twitter.com/i/media/upload.json?command=APPEND&media_id={j['media_id']}&segment_index={i}&"

        try:
            resappend = requests.post(url=appendurl, headers=append_headers, files=files, timeout=10)
            print(resappend.text)
        except:
            print("ERROR APPEND")


    finalizeurl = f"https://upload.twitter.com/i/media/upload.json?command=FINALIZE&media_id={j['media_id']}&allow_async=true"


    try:
        resfinalize = requests.post(url=finalizeurl, headers=chunked_headers, timeout=10)
        print(resfinalize.text)
    except:
        print("ERROR FINALIZE")

    time.sleep(1)

    statusurl = f"https://upload.twitter.com/i/media/upload.json?command=STATUS&media_id={j['media_id']}"

    try:
        for i in range(0, 6):
            resStatus = requests.get(url=statusurl, headers=chunked_headers, timeout=10)

            status = json.loads(resStatus.text)

            print(json.dumps(status, indent=4))

            if "processing_info" in status:
                state = json.loads(resStatus.text)["processing_info"]["state"]
                print(f"{state}")
                if state == "succeeded":
                    break
            time.sleep(10)
    except:
        print("ERROR STATUS")


    media_id = str(json.loads(resfinalize.text)["media_id_string"])
    data = '{"variables":{"tweet_text":"","dark_request":false,"media":{"media_entities":[{"media_id":"' + media_id + '","tagged_users":[]}],"possibly_sensitive":false},"semantic_annotation_ids":[]},"features":{"tweetypie_unmention_optimization_enabled":true,"vibe_api_enabled":true,"responsive_web_edit_tweet_api_enabled":true,"graphql_is_translatable_rweb_tweet_is_translatable_enabled":true,"view_counts_everywhere_api_enabled":true,"longform_notetweets_consumption_enabled":true,"tweet_awards_web_tipping_enabled":false,"interactive_text_enabled":true,"responsive_web_text_conversations_enabled":false,"longform_notetweets_rich_text_read_enabled":true,"blue_business_profile_image_shape_enabled":true,"responsive_web_graphql_exclude_directive_enabled":true,"verified_phone_label_enabled":false,"freedom_of_speech_not_reach_fetch_enabled":false,"standardized_nudges_misinfo":true,"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled":false,"responsive_web_graphql_skip_user_profile_image_extensions_enabled":false,"responsive_web_graphql_timeline_navigation_enabled":true,"responsive_web_enhance_cards_enabled":false},"queryId":"1RyAhNwby-gzGCRVsMxKbQ"}'

    h = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json",
        "Content-Length": f"{len(data)}",
        "Accept-Language": "en-US,en;q=0.5",
        "authorization": f"Bearer {authorization}",
        "Connection": "keep-alive",
        "Cookie": f"gt={gt}; ct0={ct0}; kdt={kdt}; twid={twid}; auth_token={auth_token};",
        "host": "twitter.com",
        "origin": "https://twitter.com",
        "referer": "https://twitter.com/compose/tweet",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "User-Agent": f"{userAgent}",
        "x-csrf-token": f"{ct0}",
        "x-guest-token": f"{gt}",
        "x-twitter-active-user": "yes",
        "x-twitter-client-language": "en"
    }

    tweeturl = "https://twitter.com/i/api/graphql/1RyAhNwby-gzGCRVsMxKbQ/CreateTweet"

    try:
        resTweet = requests.post(tweeturl, headers=h, data=data, timeout=10)
        print(resTweet.text)
    except:
        print("ERROR TWEETING")