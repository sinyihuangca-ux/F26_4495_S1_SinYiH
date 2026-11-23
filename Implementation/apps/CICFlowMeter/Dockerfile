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
    JAR_SRC=""; \
    for candidate in \
      "./jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar" \
      "./jnetpcap/linux/jnetpcap.jar" \
      "./jnetpcap/win/jnetpcap-1.4.r1425/jnetpcap.jar" \
      "./jnetpcap.jar"; do \
      if [ -f "$candidate" ]; then JAR_SRC="$candidate"; break; fi; \
    done; \
    test -n "$JAR_SRC"; \
    mkdir -p /root/.m2/repository/org/jnetpcap/jnetpcap/1.4.1; \
    cp "$JAR_SRC" /root/.m2/repository/org/jnetpcap/jnetpcap/1.4.1/jnetpcap-1.4.1.jar; \
    printf '<project><modelVersion>4.0.0</modelVersion><groupId>org.jnetpcap</groupId><artifactId>jnetpcap</artifactId><version>1.4.1</version></project>' \
      > /root/.m2/repository/org/jnetpcap/jnetpcap/1.4.1/jnetpcap-1.4.1.pom

RUN chmod +x ./gradlew && ./gradlew clean installDist --no-daemon

# --- Stage 2: Minimal Ubuntu 22.04 Runtime ---
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
ENV APP_HOME=/opt/cicflowmeter
ENV NATIVE_DIR=/opt/cicflowmeter/natives

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-8-jre-headless \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR ${APP_HOME}

COPY --from=builder /build/build/install/CICFlowMeter/ ${APP_HOME}/

RUN mkdir -p ${NATIVE_DIR}
COPY --from=builder /build/jnetpcap/ /tmp/jnetpcap-src/
RUN set -eux; \
    SO_FILE=$(find /tmp/jnetpcap-src -name "libjnetpcap.so*" -type f | head -n 1 || true); \
    if [ -n "$SO_FILE" ]; then cp "$SO_FILE" ${NATIVE_DIR}/libjnetpcap.so; fi; \
    rm -rf /tmp/jnetpcap-src; \
    chmod +x ${APP_HOME}/bin/*

ENV LD_LIBRARY_PATH=${NATIVE_DIR}
ENV JAVA_OPTS="-Djava.library.path=${NATIVE_DIR}"

RUN set -eux; \
    if [ -x "${APP_HOME}/bin/cfm" ]; then \
      ln -sf "${APP_HOME}/bin/cfm" /usr/local/bin/cfm-run; \
    elif [ -x "${APP_HOME}/bin/CICFlowMeter" ]; then \
      ln -sf "${APP_HOME}/bin/CICFlowMeter" /usr/local/bin/cfm-run; \
    else \
      SCRIPT=$(find "${APP_HOME}/bin" -maxdepth 1 -type f ! -name "*.bat" | head -n 1); \
      test -n "$SCRIPT"; \
      chmod +x "$SCRIPT"; \
      ln -sf "$SCRIPT" /usr/local/bin/cfm-run; \
    fi

WORKDIR ${APP_HOME}/bin
ENTRYPOINT ["/usr/local/bin/cfm-run"]