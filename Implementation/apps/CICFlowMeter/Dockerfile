# cicflowmeter-worker: short-lived container started by pcap-watcher.
#   docker run ... cicflowmeter-worker:latest <pcap|pcapng file> <output dir>
# Writes <output dir>/<file name>_Flow.csv; exits non-zero on failure.
# Env: CFM_READ_IPV6=true to include IPv6 flows (off by default).

# --- Stage 1: Build CICFlowMeter with Java 8 ---
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-8-jdk-headless \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# Seed local Maven repository with jnetpcap 1.4.1 so Gradle resolves reliably
RUN set -eux; \
    JAR_SRC="./jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar"; \
    test -f "$JAR_SRC"; \
    mkdir -p /root/.m2/repository/org/jnetpcap/jnetpcap/1.4.1; \
    cp "$JAR_SRC" /root/.m2/repository/org/jnetpcap/jnetpcap/1.4.1/jnetpcap-1.4.1.jar; \
    printf '<project><modelVersion>4.0.0</modelVersion><groupId>org.jnetpcap</groupId><artifactId>jnetpcap</artifactId><version>1.4.1</version></project>' \
      > /root/.m2/repository/org/jnetpcap/jnetpcap/1.4.1/jnetpcap-1.4.1.pom

# installDist also copies jnetpcap-1.4.r1425/*.so into build/install/CICFlowMeter/lib/native (build.gradle)
RUN chmod +x ./gradlew && ./gradlew clean installDist --no-daemon

# --- Stage 2: Minimal Ubuntu 22.04 Runtime ---
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
ENV APP_HOME=/opt/cicflowmeter

# wireshark-common provides editcap, used by run-cfm.sh to convert pcapng to pcap.
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-8-jre-headless \
    libpcap0.8 \
    wireshark-common \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/build/install/CICFlowMeter/ ${APP_HOME}/
COPY docker/log4j-console.properties ${APP_HOME}/conf/log4j.properties
COPY docker/run-cfm.sh ${APP_HOME}/bin/run-cfm.sh

# Fail the build if the jnetpcap native library or its libpcap dependency is missing.
# jnetpcap 1.4's libjnetpcap.so links against the unversioned "libpcap.so", which Ubuntu only ships
# in libpcap-dev; point it at the runtime library from libpcap0.8 instead.
RUN set -eux; \
    test -f ${APP_HOME}/lib/native/libjnetpcap.so; \
    PCAP_SO="$(ls /usr/lib/x86_64-linux-gnu/libpcap.so.0.8)"; \
    ln -sf "$PCAP_SO" /usr/lib/x86_64-linux-gnu/libpcap.so; \
    ldconfig; \
    ldd ${APP_HOME}/lib/native/libjnetpcap.so; \
    if ldd ${APP_HOME}/lib/native/libjnetpcap.so | grep -q "not found"; then echo "unresolved native deps" >&2; exit 1; fi; \
    rm -f ${APP_HOME}/lib/native/*.dll; \
    chmod +x ${APP_HOME}/bin/cfm ${APP_HOME}/bin/run-cfm.sh; \
    command -v editcap

# - absolute java.library.path (the start script's default "../lib/native" depends on the cwd);
#   JAVA_OPTS comes after DEFAULT_JVM_OPTS in the start script, so it takes precedence
# - console-only logging so the worker can run with a read-only root filesystem
# - size the heap from the container memory limit (docker run --memory)
ENV JAVA_OPTS="-Djava.library.path=/opt/cicflowmeter/lib/native -Dlog4j.configuration=file:/opt/cicflowmeter/conf/log4j.properties -XX:MaxRAMPercentage=75.0 -Djava.io.tmpdir=/tmp"

# /tmp is a tmpfs when pcap-watcher runs the worker with --read-only.
WORKDIR /tmp
ENTRYPOINT ["/opt/cicflowmeter/bin/run-cfm.sh"]
