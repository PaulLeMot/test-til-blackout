FROM ubuntu:18.04

RUN apt update && apt install -y wget curl gnupg2

# Добавляем репозиторий КриптоПРО
RUN wget -q -O - http://repo.cryptopro.ru/keys/public.key | apt-key add -
RUN echo "deb http://repo.cryptopro.ru/ubuntu/18.04/ stable non-free" >> /etc/apt/sources.list

RUN apt update && apt install -y cprocsp-rdr-gost

# Собираем curl с поддержкой GOST
RUN apt install -y build-essential libssl-dev libgost-engine-dev
RUN wget https://curl.se/download/curl-7.68.0.tar.gz && \
    tar -xzf curl-7.68.0.tar.gz && \
    cd curl-7.68.0 && \
    ./configure --with-ssl --with-engine && \
    make && make install

WORKDIR /certs
CMD ["/bin/bash"]
