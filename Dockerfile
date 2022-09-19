FROM ubuntu:latest as base

RUN apt-get update -y \
    && apt-get upgrade -y \
    && apt-get install -y \
        libmodsecurity-dev \
        build-essential \
        curl git \
        erlang \
    && apt-get -y autoremove \
    && apt-get -y autoclean \
    && rm -rf /tmp/*


FROM ubuntu:latest

COPY --from=base / /

WORKDIR /erl_modsec

COPY . .
ENV LDLIBS=/usr/lib/x86_64-linux-gnu/libmodsecurity.so
RUN make tests
