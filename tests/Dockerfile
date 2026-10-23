FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl xz-utils build-essential libmnl-dev libsqlite3-dev \
    nftables iproute2 netbase python3 && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      arm64) arch=aarch64; sha=958ed7d1e00d0ea76590d27666efbf7a932281b3d7ba0c6b01b0ff26498f667f ;; \
      amd64) arch=x86_64; sha=02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239 ;; \
      *) exit 1 ;; \
    esac; \
    curl --fail --location --retry 3 "https://ziglang.org/download/0.15.2/zig-${arch}-linux-0.15.2.tar.xz" -o /tmp/zig.tar.xz; \
    echo "$sha  /tmp/zig.tar.xz" | sha256sum --check; \
    mkdir /opt/zig; tar -xJf /tmp/zig.tar.xz --strip-components=1 -C /opt/zig; \
    rm /tmp/zig.tar.xz
ENV PATH="/opt/zig:${PATH}"
WORKDIR /workspace
COPY . .
RUN zig build && zig build test
CMD ["python3", "tests/integration.py"]
