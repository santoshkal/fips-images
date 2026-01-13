### --- Stage 1: Build FIPS Provider from validated OpenSSL 3.1.2 ---
FROM alpine:latest AS fipsbuild

ARG FIPS_OPENSSL_VERSION=3.1.2
ARG BUILD_ARCH=linux-x86_64

ENV PATH=/usr/local/bin:$PATH

# Install build dependencies
RUN apk add --no-cache \
  build-base wget linux-headers perl coreutils

# Build ONLY the FIPS provider from validated OpenSSL 3.1.2
RUN wget https://github.com/openssl/openssl/releases/download/openssl-${FIPS_OPENSSL_VERSION}/openssl-${FIPS_OPENSSL_VERSION}.tar.gz \
  && tar -xf openssl-${FIPS_OPENSSL_VERSION}.tar.gz \
  && cd openssl-${FIPS_OPENSSL_VERSION} \
  && ./Configure ${BUILD_ARCH} enable-fips --prefix=/usr/local --libdir=lib \
  && make -j$(nproc) \
  && make install_fips \
  && cd .. && rm -rf openssl-${FIPS_OPENSSL_VERSION}*


### --- Stage 2: Build OpenSSL 3.5 LTS with FIPS support ---
FROM alpine:latest AS opensslbuild

ARG OPENSSL_VERSION=3.5.4
ARG BUILD_ARCH=linux-x86_64

ENV PATH=/usr/local/bin:$PATH
ENV LANG=C.UTF-8

# Install build dependencies
RUN apk add --no-cache \
  build-base wget linux-headers perl coreutils \
  bzip2-dev zlib-dev autoconf automake libtool cmake libintl ca-certificates

# Copy ONLY the FIPS provider module from validated 3.1.2 build
# (fipsmodule.cnf will be generated via fipsinstall in final stage)
COPY --from=fipsbuild /usr/local/lib/ossl-modules/fips.so /usr/local/lib/ossl-modules/

# Build OpenSSL 3.5 LTS (without building its own FIPS provider)
RUN wget https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz \
  && tar -xf openssl-${OPENSSL_VERSION}.tar.gz \
  && cd openssl-${OPENSSL_VERSION} \
  && ./Configure ${BUILD_ARCH} shared --prefix=/usr/local --libdir=lib \
  && make -j$(nproc) \
  && make install_sw \
  && cd .. && rm -rf openssl-${OPENSSL_VERSION}*

# Run fipsinstall to generate fipsmodule.cnf (per OpenSSL docs requirement)
ENV LD_LIBRARY_PATH=/usr/local/lib
RUN mkdir -p /usr/local/ssl \
  && /usr/local/bin/openssl fipsinstall \
      -out /usr/local/ssl/fipsmodule.cnf \
      -module /usr/local/lib/ossl-modules/fips.so

# Configure OpenSSL to use the validated FIPS provider
RUN printf '%s\n' \
  'config_diagnostics = 1' \
  'openssl_conf = openssl_init' \
  '.include /usr/local/ssl/fipsmodule.cnf' \
  '' \
  '[openssl_init]' \
  'providers = provider_sect' \
  'alg_section = algorithm_sect' \
  '' \
  '[provider_sect]' \
  'fips = fips_sect' \
  'base = base_sect' \
  '' \
  '[base_sect]' \
  'activate = 1' \
  '' \
  '[fips_sect]' \
  'activate = 1' \
  '' \
  '[algorithm_sect]' \
  'default_properties = fips=yes' \
  > /etc/ssl/openssl.cnf

# Verify FIPS provider loads correctly
ENV OPENSSL_CONF=/etc/ssl/openssl.cnf
ENV OPENSSL_MODULES=/usr/local/lib/ossl-modules
RUN /usr/local/bin/openssl list -providers | grep -i fips


### --- Stage 3: Python & Cryptography ---
FROM alpine:latest AS pythoncrypto

ARG PYTHON_VERSION=3.11.12

ENV PATH=/usr/local/bin:$PATH
ENV LANG=C.UTF-8
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN apk add --no-cache \
  build-base linux-headers perl coreutils pkgconfig libffi-dev \
  zlib-dev bzip2-dev sqlite-dev libxml2-dev libxslt-dev libintl \
  ca-certificates curl libgcc wget

# Download files BEFORE copying FIPS OpenSSL (uses system OpenSSL)
RUN wget -q https://bootstrap.pypa.io/get-pip.py \
  && wget https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz \
  && curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable \
  && ln -s /root/.cargo/bin/* /usr/local/bin/

# Copy OpenSSL 3.5 LTS with FIPS provider
COPY --from=opensslbuild /usr/local /usr/local
COPY --from=opensslbuild /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf

# Reinstall Rust symlinks (overwritten by COPY)
RUN ln -sf /root/.cargo/bin/* /usr/local/bin/

# Set environment for Python build
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
ENV LDFLAGS="-L/usr/local/lib -Wl,-rpath,/usr/local/lib"
ENV CPPFLAGS="-I/usr/local/include"
ENV CFLAGS="-I/usr/local/include"

# Verify OpenSSL is accessible
RUN /usr/local/bin/openssl version

# Build Python with OpenSSL 3.5 LTS
RUN tar -xf Python-${PYTHON_VERSION}.tgz \
  && cd Python-${PYTHON_VERSION} \
  && ./configure \
       --enable-optimizations \
       --enable-shared \
       --with-ensurepip=no \
       --with-openssl=/usr/local \
       --with-openssl-rpath=auto \
  && make -j$(nproc) \
  && make install \
  && cd .. && rm -rf Python-${PYTHON_VERSION}*

# Verify Python ssl module works
RUN python3 -c "import ssl; print('OpenSSL version:', ssl.OPENSSL_VERSION)"

# Enable FIPS mode for runtime
ENV OPENSSL_FIPS=1
ENV OPENSSL_CONF=/etc/ssl/openssl.cnf
ENV OPENSSL_MODULES=/usr/local/lib/ossl-modules

# Install pip and cryptography
RUN python3 get-pip.py \
  && rm get-pip.py \
  && pip install --no-binary cryptography cryptography

# Clean up to reduce image size
RUN strip --strip-unneeded /usr/local/bin/python3 || true \
  && strip --strip-unneeded /usr/local/lib/libpython3* || true \
  && strip --strip-unneeded /usr/local/lib/libssl.so* || true \
  && strip --strip-unneeded /usr/local/lib/libcrypto.so* || true \
  && find /usr/local -name '*.a' -delete \
  && find /usr/local -name '*.la' -delete \
  && rm -rf /usr/local/lib/python3.11/test


### --- Stage 4: Minimal Runtime ---
FROM alpine:latest

ENV PATH=/usr/local/bin:$PATH
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Copy runtime dependencies (excluding fipsmodule.cnf - will regenerate)
COPY --from=opensslbuild /usr/local /usr/local
COPY --from=pythoncrypto /usr/local/bin/python3 /usr/local/bin/
COPY --from=pythoncrypto /usr/local/bin/pip* /usr/local/bin/
COPY --from=pythoncrypto /usr/local/lib/libpython3* /usr/local/lib/
COPY --from=pythoncrypto /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=pythoncrypto /usr/lib/libgcc* /usr/lib/

# Run fipsinstall to generate fipsmodule.cnf for THIS container
# Per OpenSSL docs: "The FIPS module config file must be generated on every machine"
RUN mkdir -p /usr/local/ssl \
  && /usr/local/bin/openssl fipsinstall \
      -out /usr/local/ssl/fipsmodule.cnf \
      -module /usr/local/lib/ossl-modules/fips.so

# Create OpenSSL configuration that includes FIPS
RUN printf '%s\n' \
  'config_diagnostics = 1' \
  'openssl_conf = openssl_init' \
  '.include /usr/local/ssl/fipsmodule.cnf' \
  '' \
  '[openssl_init]' \
  'providers = provider_sect' \
  'alg_section = algorithm_sect' \
  '' \
  '[provider_sect]' \
  'fips = fips_sect' \
  'base = base_sect' \
  '' \
  '[base_sect]' \
  'activate = 1' \
  '' \
  '[fips_sect]' \
  'activate = 1' \
  '' \
  '[algorithm_sect]' \
  'default_properties = fips=yes' \
  > /etc/ssl/openssl.cnf

# Set FIPS environment variables
ENV OPENSSL_FIPS=1
ENV OPENSSL_CONF=/etc/ssl/openssl.cnf
ENV OPENSSL_MODULES=/usr/local/lib/ossl-modules

# Verify FIPS provider is properly loaded
RUN /usr/local/bin/openssl list -providers | grep -i fips

RUN apk add --no-cache shadow ca-certificates \
  && useradd -U -u 1000 appuser \
  && chown -R 1000:1000 /usr/local/lib/python3.11/site-packages /usr/local/bin

# Labels for image metadata
LABEL org.opencontainers.image.title="Python 3.11 with OpenSSL 3.5 LTS FIPS" \
      org.opencontainers.image.description="Python 3.11 with FIPS 140-3 validated OpenSSL provider" \
      org.opencontainers.image.version="3.11.12" \
      openssl.version="3.5.4" \
      openssl.fips.provider="3.1.2 (FIPS 140-3 Validated)"

USER 1000
