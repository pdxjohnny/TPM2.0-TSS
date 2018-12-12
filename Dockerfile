FROM ubuntu:18.04 AS base
RUN apt-get update && apt-get install -y \
    autoconf \
    autoconf-archive \
    automake \
    build-essential \
    doxygen \
    g++ \
    gcc \
    git \
    gnulib \
    libssl-dev \
    libtool \
    m4 \
    net-tools \
    pkg-config \
    wget

# OpenSSL
ARG openssl_name=openssl-1.1.0h
WORKDIR /tmp
RUN wget --quiet --show-progress --progress=dot:giga https://www.openssl.org/source/$openssl_name.tar.gz \
	&& tar xvf $openssl_name.tar.gz \
	&& rm /tmp/$openssl_name.tar.gz
WORKDIR $openssl_name
RUN ./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl \
	&& make -j$(nproc) \
	&& make install \
	&& openssl version

# IBM's Software TPM 2.0
ARG ibmtpm_name=ibmtpm1119
WORKDIR /tmp
RUN wget --quiet --show-progress --progress=dot:giga "https://downloads.sourceforge.net/project/ibmswtpm2/$ibmtpm_name.tar.gz" \
	&& sha256sum $ibmtpm_name.tar.gz | grep ^b9eef79904e276aeaed2a6b9e4021442ef4d7dfae4adde2473bef1a6a4cd10fb \
	&& mkdir -p $ibmtpm_name \
	&& tar xvf $ibmtpm_name.tar.gz -C $ibmtpm_name \
	&& rm $ibmtpm_name.tar.gz
WORKDIR $ibmtpm_name/src
RUN CFLAGS="-I/usr/local/openssl/include" make -j$(nproc) \
	&& cp tpm_server /usr/local/bin

RUN apt-get install -y \
    libcmocka0 \
    libcmocka-dev \
    libgcrypt20-dev \
    libtool \
    liburiparser-dev \
    uthash-dev

## Fuzzing
FROM base AS fuzzing
# TPM Fuzzing
RUN apt-get install -y \
    vim \
    gdb
COPY . /tmp/tpm2-tss/
WORKDIR /tmp/tpm2-tss
RUN ./bootstrap -I /usr/share/gnulib/m4
RUN ./configure --enable-unit \
  --enable-integration
RUN make -j $(($(nproc)+1)) check && \
  make clean
ENV CC /usr/local/bin/afl-gcc
ENV CXX /usr/local/bin/afl-g++
RUN ./configure \
  --enable-unit \
  --enable-integration \
  --enable-debug \
  --enable-tcti-fuzzing \
  --enable-tcti-device=no \
  --enable-tcti-mssim=no \
  --disable-shared
RUN make -j $(($(nproc)+1))
RUN ldconfig
ENV LD_LIBRARY_PATH /usr/local/lib

# TPM2-TSS
FROM base AS unit
COPY . /tmp/tpm2-tss/
WORKDIR /tmp/tpm2-tss
RUN ./bootstrap -I /usr/share/gnulib/m4 \
	&& ./configure --enable-unit \
	&& make -j$(nproc) check \
	&& make install \
	&& ldconfig
ENV LD_LIBRARY_PATH /usr/local/lib
RUN cat test-suite.log

