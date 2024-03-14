FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ARG P4UTIL_REPO=https://github.com/sebymiano/p4-utils.git
ARG P4UTIL_VERSION=a384f78d347a12e21287972d9accc992ff14dc83
ARG BPFTOOL_TAG=v7.3.0

USER root
WORKDIR /root

COPY .Xresources /root/

RUN apt update && apt upgrade -y
RUN apt-get -y install sudo vim x11-xserver-utils xterm wireshark-qt wget sudo curl
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
RUN apt-get update && apt-get install -y --no-install-recommends git build-essential 
RUN apt-get update && apt-get install -y --no-install-recommends lsb-release wget software-properties-common gnupg

### eBPF part ###
WORKDIR /root

# Install LLVM
RUN wget https://apt.llvm.org/llvm.sh
RUN chmod +x llvm.sh
RUN ./llvm.sh 15

COPY docker/llvm-update-alternatives.sh /root/
RUN chmod +x /root/llvm-update-alternatives.sh
RUN /root/llvm-update-alternatives.sh 15

# Remove files used for installation of LLVM
RUN rm /root/llvm.sh
RUN rm /root/llvm-update-alternatives.sh

# Install bpftool
RUN apt-get update && apt-get install -y --no-install-recommends linux-tools-common linux-tools-generic binutils-dev libelf-dev
RUN apt-get update && apt-get install -y --no-install-recommends linux-headers-$(uname -r) libpcap-dev libcap-dev
RUN git clone --depth 1 --branch $BPFTOOL_TAG https://github.com/libbpf/bpftool.git
RUN cd bpftool && git submodule update --init --recursive --depth 1
RUN cd bpftool && cd src && make && sudo make install

### P4 part ###

# Install P4Utils
RUN apt-get update && apt-get install -y locales
RUN git clone --depth 1 $P4UTIL_REPO p4-utils --recurse-submodules

# Navigate into the repository's directory
WORKDIR /root/p4-utils

# Fetch the specific commit.
RUN git fetch --depth 1 origin $P4UTIL_VERSION

# Checkout the specific commit
RUN git checkout $P4UTIL_VERSION

# Install P4Utils
RUN chmod +x /root/p4-utils/install-tools/install-p4-dev.sh
RUN /root/p4-utils/install-tools/install-p4-dev.sh

# Cleanup the files we don't need
RUN sudo rm -rf /root/p4-tools/ptf /root/p4-tools/protobuf \
                /root/p4-tools/PI /root/p4-tools/p4c \
                /root/p4-tools/libyang /root/p4-tools/grpc \
                /root/p4-tools/frr /root/p4-tools/bmv2 \
                /root/p4-tools/p4-learning

WORKDIR /root

COPY docker/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD [ "/bin/bash" ]