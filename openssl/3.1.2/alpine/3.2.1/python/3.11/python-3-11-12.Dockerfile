### --- Stage 1: OpenSSL Build ---
FROM alpine:latest AS opensslbuild

ARG OPENSSL_VERSION=3.1.2
ARG BUILD_ARCH=linux-x86_64

ENV PATH=/usr/local/bin:$PATH
ENV LANG=C.UTF-8
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Install base build deps
RUN apk add --no-cache \
  build-base wget linux-headers perl coreutils \
  bzip2-dev zlib-dev autoconf automake libtool cmake curl-dev libintl ca-certificates

# Build and install OpenSSL with FIPS (no docs)
RUN wget https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz \
  && tar -xf openssl-${OPENSSL_VERSION}.tar.gz \
  && cd openssl-${OPENSSL_VERSION} \
  && ./Configure ${BUILD_ARCH} enable-fips shared enable-ec_nistp_64_gcc_128 --prefix=/usr/local --libdir=lib \
  && make -j$(nproc) \
  && make install_sw \
  && make install_fips \
  && cd .. && rm -rf openssl-${OPENSSL_VERSION}*

# Configure OpenSSL FIPS
RUN printf '%s\n' \
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


### --- Stage 2: Python & Cryptography ---
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

# Now copy FIPS OpenSSL (after downloads complete)
COPY --from=opensslbuild /usr/local /usr/local
COPY --from=opensslbuild /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf

# Reinstall Rust symlinks (overwritten by COPY)
RUN ln -sf /root/.cargo/bin/* /usr/local/bin/

# Set environment for Python build (NOT for system tools)
# Use LD_LIBRARY_PATH instead of modifying system-wide musl config
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
ENV LDFLAGS="-L/usr/local/lib -Wl,-rpath,/usr/local/lib"
ENV CPPFLAGS="-I/usr/local/include"
ENV CFLAGS="-I/usr/local/include"

# Verify FIPS OpenSSL is accessible (using LD_LIBRARY_PATH, not system-wide config)
RUN /usr/local/bin/openssl version

# Build Python with FIPS OpenSSL
# Note: Do NOT set OPENSSL_FIPS=1 during build - it can cause issues
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

# Now enable FIPS mode for runtime
ENV OPENSSL_FIPS=1
ENV OPENSSL_CONF=/etc/ssl/openssl.cnf
ENV OPENSSL_MODULES=/usr/local/lib/ossl-modules

# Install pip and cryptography
RUN python3 get-pip.py \
  && rm get-pip.py \
  && pip install --no-binary cryptography cryptography

# Clean up unnecessary files to reduce image size
RUN strip --strip-unneeded /usr/local/bin/python3 || true \
  && strip --strip-unneeded /usr/local/lib/libpython3* || true \
  && strip --strip-unneeded /usr/local/lib/libssl.so* || true \
  && strip --strip-unneeded /usr/local/lib/libcrypto.so* || true \
  && find /usr/local -name '*.a' -delete \
  && find /usr/local -name '*.la' -delete \
  && rm -rf /usr/local/lib/python3.11/test


### --- Stage 3: Minimal Runtime ---
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

USER 1000
