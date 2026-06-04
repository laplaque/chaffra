FROM ubuntu:latest

RUN apt-get update && apt-get install -y curl

ADD https://example.com/app.tar.gz /opt/

ENV API_KEY=sk-1234567890abcdef
ARG DB_PASSWORD=hunter2hunter2

COPY . /app
WORKDIR /app
CMD ["./app"]
