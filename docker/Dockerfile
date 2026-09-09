# syntax=docker/dockerfile:1

FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf automake libtool pkg-config gettext gperf git ca-certificates \
    libgnutls28-dev \
    liblasso3-dev \
    libglib2.0-dev \
    libapr1-dev \
    libnl-3-dev libnl-route-3-dev \
    libpam0g-dev \
    libradcli-dev \
    libreadline-dev \
    libseccomp-dev \
    libtalloc-dev \
    libprotobuf-c-dev protobuf-c-compiler \
    libgeoip-dev \
    libcurl4-gnutls-dev \
    libhttp-parser-dev \
    libxml2-dev \
    libxmlsec1-dev \
    libev-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone https://github.com/wisnu-sanjaya/ocserv-vpn.git .

RUN chmod +x autogen.sh && ./autogen.sh
RUN ./configure --enable-saml-auth --prefix=/usr --sysconfdir=/etc
RUN make -j$(nproc)

FROM ubuntu:22.04

ARG TZ=Asia/Jakarta
ENV TZ=${TZ}
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata \
    gettext-base \
    libgnutls30 \
    liblasso3 \
    libglib2.0-0 \
    libapr1 \
    libnl-3-200 libnl-route-3-200 libnl-genl-3-200 \
    libpam0g \
    libradcli4 \
    libreadline8 \
    libseccomp2 \
    libtalloc2 \
    libprotobuf-c1 \
    libgeoip1 \
    libcurl4 libcurl3-gnutls \
    libhttp-parser2.9 \
    libxml2 \
    libxmlsec1 libxmlsec1-gnutls \
    libev4 \
    iproute2 iptables \
    ca-certificates \
    && ln -fs /usr/share/zoneinfo/${TZ} /etc/localtime \
    && dpkg-reconfigure -f noninteractive tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/src/ocserv /usr/sbin/ocserv
COPY --from=builder /build/src/occtl/occtl /usr/bin/occtl
COPY --from=builder /build/src/ocpasswd/ocpasswd /usr/bin/ocpasswd

COPY templates/ /templates/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 443/tcp 443/udp

ENTRYPOINT ["/entrypoint.sh"]
