FROM python:3.11.6-alpine3.18 as builder

WORKDIR /app
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt

FROM python:3.11.6-alpine3.18

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
STOPSIGNAL SIGINT

COPY --from=builder /app/wheels /wheels
COPY --from=builder /app/requirements.txt .
COPY main.py .

RUN pip install --no-cache /wheels/*

CMD python3 main.py --hostname $HOSTNAME --port 8080 --authority $AUTHORITY
