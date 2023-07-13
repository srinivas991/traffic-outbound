FROM ubuntu:20.04 as tcpconnect

RUN apt update && apt install -y git vim build-essential libelf-dev clang-12 llvm-12

WORKDIR /app
COPY . ./

WORKDIR /tmp/bpftool
RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git .
WORKDIR /tmp/bpftool/src
RUN make && make install && rm -rf /tmp/bpftool

WORKDIR /tmp/libbpf
RUN git clone https://github.com/libbpf/libbpf.git .
WORKDIR /tmp/libbpf/src
RUN make && make install

WORKDIR /app/tcpconnect
RUN make

RUN apt install wget -y
WORKDIR /tmp
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') && \
    wget https://golang.org/dl/go1.20.6.linux-${ARCH}.tar.gz

RUN ARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') && \
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.20.6.linux-${ARCH}.tar.gz

RUN /usr/local/go/bin/go version

WORKDIR /app/
# RUN /usr/local/go/bin/go mod init main
# RUN /usr/local/go/bin/go mod tidy

RUN cp tcpconnect/vmlinux.h ./

RUN BPF_CLANG=clang-12 BPF_CFLAGS="-O2 -g -Wall -Werror" /usr/local/go/bin/go generate
RUN /usr/local/go/bin/go build

FROM ubuntu:20.04
WORKDIR /app

COPY --from=0 /app/main ./
COPY --from=0 /app/tcpconnect/tcpconnect ./

RUN apt update && apt install libelf-dev -y && apt autoremove
