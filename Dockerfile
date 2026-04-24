FROM alpine:3.18 AS builder

# Install build-dependencies
RUN apk add --no-cache \
    gcc g++ make cmake \
    zeromq-dev cppzmq \
    curl-dev openssl-dev \
    libpcap-dev numactl-dev \
    libtool automake autoconf pkgconfig \
    git bash

# Build nDPI 5.0-stable
WORKDIR /src
RUN git clone -b 5.0-stable --depth 1 https://github.com/ntop/nDPI.git && \
    cd nDPI && \
    ./autogen.sh && \
    ./configure --with-only-libndpi --enable-static --disable-shared && \
    make -j$(nproc) && \
    make install

# Compile C++ capture tool
WORKDIR /app
COPY capture.cpp .

RUN g++ -O3 capture.cpp -o fritz-capture \
    $(find /src/nDPI -name libndpi.a | head -n 1) \
    -lzmq -lcurl -lcrypto -lpthread

# Final stage
FROM alpine:3.18

# Install runtime libraries
RUN apk add --no-cache \
    libzmq \
    libcurl \
    libstdc++ \
    openssl \
    ca-certificates

COPY --from=builder /app/fritz-capture /app/fritz-capture

WORKDIR /app

# Start binary
CMD ["./fritz-capture"]
