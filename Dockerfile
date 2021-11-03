FROM debian:stable

RUN apt-get update \
&& apt-get install -y build-essential pkg-config bison flex autoconf \
                                                automake libtool make git python3 python3-pip   \
                                                sqlite3 cmake git libmbedtls-dev
COPY . /workdir
WORKDIR /workdir
RUN pip3 install -r requirements.txt
RUN ./install.sh docker
ENTRYPOINT ["./start_openplc.sh"]
