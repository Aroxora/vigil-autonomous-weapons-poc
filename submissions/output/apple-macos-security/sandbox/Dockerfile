FROM --platform=linux/arm64 debian:12-slim
RUN apt-get update && apt-get install -y clang lldb python3 gdb binutils && rm -rf /var/lib/apt/lists/*
WORKDIR /exploit
COPY poc/ ./
RUN make -f Makefile
