FROM ubuntu:22.04
RUN DEBIAN_FRONTEND=noninteractive apt update &&  apt-get install -y --no-install-recommends tzdata
RUN TZ=Asia/Taipei \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && dpkg-reconfigure -f noninteractive tzdata
RUN apt install -y gcc make gdb wget
RUN cd /usr/local/src/ && \
    wget 'https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.6.zip'
RUN apt install -y unzip perl && \
    cd /usr/local/src/ && \
    unzip openssl-3.0.6.zip && \
    mv openssl-openssl-3.0.6 openssl-3.0.6/ && \
    cd openssl-3.0.6 && \
    mkdir build && \
    cd build && \
    ../config -v --prefix=/usr/local/ssl --openssldir=/usr/local/ssl --debug && \
    make && \
    make install && \
    ldconfig /usr/local/ssl/lib64/