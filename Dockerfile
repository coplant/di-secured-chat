FROM python:3-slim-buster

WORKDIR /code/backend

COPY /requirements.txt .

RUN pip install -r requirements.txt

COPY . .

RUN chmod a+x /code/backend/docker/*.sh