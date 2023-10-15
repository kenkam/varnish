FROM python:3.11.6-alpine3.18

COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt

RUN chmod 755 main.py

STOPSIGNAL SIGINT

CMD python3 -u main.py --hostname $HOSTNAME --port 8080
