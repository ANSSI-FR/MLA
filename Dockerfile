FROM rust:latest

RUN apt update && apt install -qqy clang llvm
RUN cargo install afl

WORKDIR /usr/src/mla

COPY . .
