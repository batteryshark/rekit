ARG UBUNTU_IMAGE=ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

FROM ${UBUNTU_IMAGE} AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG LLVM_VERSION=21
ARG LLVM_PACKAGE_VERSION=1:21.1.8~++20251221032922+2078da43e25a-1~exp1~20251221153059.70
ARG REMILL_COMMIT=0e324aee8c67a63ec759ef379dcfafa0b3cb1448
ARG LLVM_INSTALLER_SHA256=9474ecd78b52aba6e923976b1e9773f5613027cc7e237b9956986cb536e02a36

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates cmake git gnupg lsb-release ninja-build python3 \
      software-properties-common wget \
    && wget -q https://apt.llvm.org/llvm.sh \
    && echo "${LLVM_INSTALLER_SHA256}  llvm.sh" | sha256sum -c - \
    && chmod +x llvm.sh \
    && ./llvm.sh "${LLVM_VERSION}" \
    && apt-get install -y --no-install-recommends \
         "llvm-${LLVM_VERSION}-dev=${LLVM_PACKAGE_VERSION}" \
    && rm -rf /var/lib/apt/lists/* llvm.sh

ENV CC=clang-${LLVM_VERSION}
ENV CXX=clang++-${LLVM_VERSION}

WORKDIR /src/remill
RUN git clone --filter=blob:none https://github.com/lifting-bits/remill.git . \
    && git checkout --detach "${REMILL_COMMIT}" \
    && test "$(git rev-parse HEAD)" = "${REMILL_COMMIT}"

RUN llvm_prefix="$(llvm-config-${LLVM_VERSION} --prefix)" \
    && cmake -G Ninja -S dependencies -B dependencies/build \
         -DUSE_EXTERNAL_LLVM=ON \
         "-DCMAKE_PREFIX_PATH=${llvm_prefix}" \
    && cmake --build dependencies/build --parallel 2 \
    && cmake -G Ninja -S . -B build \
         "-DCMAKE_PREFIX_PATH=${llvm_prefix};/src/remill/dependencies/install" \
         -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_INSTALL_PREFIX=/opt/remill \
         -DREMILL_ENABLE_INSTALL_TARGET=ON \
    && cmake --build build --parallel 2 \
    && cmake --install build

FROM ${UBUNTU_IMAGE} AS runtime

ARG DEBIAN_FRONTEND=noninteractive
ARG LLVM_VERSION=21
ARG LLVM_PACKAGE_VERSION=1:21.1.8~++20251221032922+2078da43e25a-1~exp1~20251221153059.70
ARG REMILL_COMMIT=0e324aee8c67a63ec759ef379dcfafa0b3cb1448
ARG LLVM_INSTALLER_SHA256=9474ecd78b52aba6e923976b1e9773f5613027cc7e237b9956986cb536e02a36

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates gnupg lsb-release software-properties-common wget \
    && wget -q https://apt.llvm.org/llvm.sh \
    && echo "${LLVM_INSTALLER_SHA256}  llvm.sh" | sha256sum -c - \
    && chmod +x llvm.sh \
    && ./llvm.sh "${LLVM_VERSION}" \
    && apt-get install -y --no-install-recommends \
         "llvm-${LLVM_VERSION}=${LLVM_PACKAGE_VERSION}" \
    && rm -rf /var/lib/apt/lists/* llvm.sh

COPY --from=builder /opt/remill /opt/remill
COPY --from=builder /src/remill/LICENSE /licenses/Remill.txt
COPY LICENSE /licenses/Rekit.txt
COPY containers/native-lift/entrypoint.sh /usr/local/bin/native-lift

RUN chmod 0555 /usr/local/bin/native-lift \
    && mkdir -p /input /output \
    && cp "/usr/share/doc/llvm-${LLVM_VERSION}/copyright" /licenses/LLVM.txt \
    && chmod 0555 /input \
    && chmod 0777 /output

ENV PATH=/opt/remill/bin:${PATH}
ENV REMILL_VERSION=v6.0.1
ENV REMILL_COMMIT=${REMILL_COMMIT}
ENV LLVM_VERSION=${LLVM_VERSION}

LABEL org.opencontainers.image.title="Rekit native-lift runtime" \
      org.opencontainers.image.description="Pinned Remill runtime for static byte-region lifting" \
      org.opencontainers.image.source="https://github.com/batteryshark/rekit" \
      org.opencontainers.image.licenses="Apache-2.0 AND Apache-2.0 WITH LLVM-exception" \
      org.opencontainers.image.version="remill-6.0.1-llvm-21" \
      org.opencontainers.image.revision="${REMILL_COMMIT}"

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/native-lift"]

FROM runtime AS smoke

RUN printf '\211\370\303' > /tmp/x86.bin \
    && native-lift --input /tmp/x86.bin --arch x86 \
         --os linux --address 0 --entry-address 0 --ir-out /tmp/x86.ll \
    && test -s /tmp/x86.ll \
    && printf '\110\211\370\303' > /tmp/amd64.bin \
    && native-lift --input /tmp/amd64.bin --arch amd64 \
         --os linux --address 0 --entry-address 0 --ir-out /tmp/amd64.ll \
    && test -s /tmp/amd64.ll \
    && printf '\300\003\137\326' > /tmp/aarch64.bin \
    && native-lift --input /tmp/aarch64.bin --arch aarch64 \
         --os linux --address 0 --entry-address 0 --ir-out /tmp/aarch64.ll \
    && test -s /tmp/aarch64.ll \
    && rm -f /tmp/x86.bin /tmp/x86.ll /tmp/amd64.bin /tmp/amd64.ll \
         /tmp/aarch64.bin /tmp/aarch64.ll

FROM smoke AS final
