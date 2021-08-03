FROM openjdk:slim

COPY --from=python:3.9 / /

COPY ./app /usr/src/app
COPY ./files /usr/src/files
COPY ./dex2jar-2.0 /usr/src/dex2jar-2.0
COPY ./results /usr/src/results
COPY ./extracted_archives /usr/src/extracted_archives
COPY ./requirements.txt /usr/src/

RUN pip3 install --upgrade pip && \
    pip3 install -r /usr/src/requirements.txt

WORKDIR /usr/src
RUN git clone https://github.com/skylot/jadx.git
WORKDIR /usr/src/jadx
RUN ./gradlew

WORKDIR /usr/src/app