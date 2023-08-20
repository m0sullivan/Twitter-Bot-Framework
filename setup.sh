#!/bin/bash
mkdir logs
mkdir configs
mkdir media
mkdir tweetdeck_configs
mkdir tweetdeck_userids
docker build -t twitter .
docker run -it --name twitcontainer -d -p 42874:42874 twitter