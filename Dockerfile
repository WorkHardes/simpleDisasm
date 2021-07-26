FROM python:3.9

COPY ./app /usr/src/app

COPY ./files /usr/src/files

COPY ./results /usr/src/results

COPY ./extracted_archives /usr/src/extracted_archives

COPY ./requirements.txt /usr/src/

RUN pip3 install --upgrade pip

RUN pip3 install -r /usr/src/requirements.txt

WORKDIR /usr/src/app