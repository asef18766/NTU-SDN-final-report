FROM ubuntu:22.04
RUN DEBIAN_FRONTEND=noninteractive apt update &&  apt-get install -y --no-install-recommends tzdata
RUN TZ=Asia/Taipei \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && dpkg-reconfigure -f noninteractive tzdata
RUN apt install -y gcc make gdb wget libc6-dbg 

# set up openssl 
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


# set up gef gdb and python3 
RUN apt-get install -y python3 
RUN apt install -y python3-pip 
RUN pip3 install  pwntools
RUN wget -O /root/.gdbinit-gef.py http://gef.blah.cat/py
RUN echo source /root/.gdbinit-gef.py >> /root/.gdbinit


RUN apt-get install -y vim \
    file \
    strace \
    ltrace \
    locales \
    git  \
    tcpdump \
    net-tools
    

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

WORKDIR /home
RUN git clone https://github.com/colmmacc/CVE-2022-3602

## set up openssl lib path
ENV LD_LIBRARY_PATH=/usr/local/ssl/lib64/
ENV PATH_TO_OPENSSL=/usr/local/ssl/bin

RUN cd ./CVE-2022-3602 && \
    mkdir server && \
    mkdir client 
COPY server/* /home/CVE-2022-3602/server/
COPY client/* /home/CVE-2022-3602/client/
COPY run*.sh /home/CVE-2022-3602/
COPY gdb_script /home/CVE-2022-3602/
