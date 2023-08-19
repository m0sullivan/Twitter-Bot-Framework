#!/bin/bash
docker build -t twitter .
docker run -it --name twitcontainer -d -p 42874:42874 twitter