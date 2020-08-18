#sha256 of rust:1.45.2
FROM rust@sha256:582bedbe2d3b7ada087ba37cd22ab266f085e58f019201d95972d4413e1e4651 as builder

RUN apt update && apt install -qqy clang=1:7.0-47 llvm=1:7.0-47

RUN cargo install afl && rustup target add x86_64-unknown-linux-musl

WORKDIR /usr/src/mla

COPY . .

WORKDIR /usr/src/mla/mlar

RUN cargo install --target x86_64-unknown-linux-musl --path . 

FROM scratch

COPY --from=builder /usr/local/cargo/bin/mlar .

ENTRYPOINT [ "./mlar" ]
