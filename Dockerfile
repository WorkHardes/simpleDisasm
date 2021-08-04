FROM openjdk:slim

COPY --from=python:3.9 / /

COPY ./app /usr/src/app
COPY ./files /usr/src/files
COPY ./jadx-1.2.0 /usr/src/jadx-1.2.0
COPY ./dex2jar-2.0 /usr/src/dex2jar-2.0
COPY ./results /usr/src/results
COPY ./extracted_archives /usr/src/extracted_archives
COPY ./requirements.txt /usr/src/

RUN pip3 install --upgrade pip && \
    pip3 install -r /usr/src/requirements.txt

WORKDIR /usr/src/app