FROM python:3.12.0a7
EXPOSE 42874
WORKDIR /
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN pip install regex
COPY . .
CMD mkdir configs
CMD mkdir media
CMD mkdir logs
CMD mkdir tweetdeck_configs
CMD mkdir tweetdeck_userids
CMD python3 main.py