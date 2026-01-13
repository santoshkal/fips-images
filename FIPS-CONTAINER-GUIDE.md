# Building FIPS-Compliant Container Images: A Complete Guide

This guide documents the process of building FIPS 140-3 compliant container images with Python and OpenSSL, based on practical experience and official OpenSSL documentation.

## Table of Contents

1. [Understanding FIPS Compliance](#understanding-fips-compliance)
2. [OpenSSL 3.x Provider Architecture](#openssl-3x-provider-architecture)
3. [FIPS Provider Portability](#fips-provider-portability)
4. [Building FIPS-Compliant Images](#building-fips-compliant-images)
5. [Key Complexities and Pitfalls](#key-complexities-and-pitfalls)
6. [Verification Procedures](#verification-procedures)
7. [References](#references)

---

## Understanding FIPS Compliance

### What is FIPS 140-3?

FIPS 140-3 (Federal Information Processing Standard) is a U.S. government security standard for cryptographic modules. It defines requirements for:

- Approved cryptographic algorithms (AES, SHA-2, RSA, ECDSA, etc.)
- Key management
- Self-testing of cryptographic functions
- Physical security (for hardware modules)

### What Makes an Image "FIPS-Compliant"?

A FIPS-compliant container image must:

1. **Use a validated cryptographic module** - Only NIST-certified modules count for compliance
2. **Enforce FIPS mode** - Non-approved algorithms (MD5, SHA-1 for signing, etc.) must be blocked
3. **Run self-tests** - The FIPS module must verify its integrity on each load
4. **Generate machine-specific configuration** - The `fipsmodule.cnf` must be generated on each deployment target

### Currently Validated OpenSSL Versions

| Version | FIPS Status | Certificate | Support Until |
|---------|-------------|-------------|---------------|
| OpenSSL 3.1.2 | FIPS 140-3 Validated | [#4282](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4282) | N/A |
| OpenSSL 3.0.9 | FIPS 140-3 Validated | Earlier cert | Sept 2026 (LTS) |
| OpenSSL 3.5.4 | In Validation Process | Pending | April 2030 (LTS) |

---

## OpenSSL 3.x Provider Architecture

### What Changed from OpenSSL 1.x to 3.x?

OpenSSL 3.0 introduced a **provider-based architecture** that fundamentally changed how cryptography is handled:

```
OpenSSL 1.x:                    OpenSSL 3.x:
┌─────────────────┐             ┌─────────────────┐
│   Application   │             │   Application   │
├─────────────────┤             ├─────────────────┤
│  OpenSSL API    │             │  OpenSSL API    │
├─────────────────┤             ├─────────────────┤
│  Crypto Impl    │             │ Provider Layer  │
│  (monolithic)   │             ├────┬────┬───────┤
└─────────────────┘             │FIPS│Base│Default│
                                └────┴────┴───────┘
```

### What is a Provider?

A **provider** is a dynamically loadable module (`.so` or `.dll`) that implements cryptographic algorithms. OpenSSL 3.x includes several providers:

| Provider | File | Purpose |
|----------|------|---------|
| **default** | `default.so` | Standard crypto algorithms (loaded by default) |
| **fips** | `fips.so` | FIPS 140-3 validated algorithms only |
| **base** | `base.so` | Encoding/decoding, no crypto (always needed) |
| **legacy** | `legacy.so` | Deprecated algorithms (MD4, RC4, etc.) |

### How Providers Work

```
┌─────────────────────────────────────────────────────────┐
│                    openssl.cnf                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │ [provider_sect]                                   │  │
│  │ fips = fips_sect      ──► Load fips.so            │  │
│  │ base = base_sect      ──► Load base.so            │  │
│  │                                                   │  │
│  │ [fips_sect]                                       │  │
│  │ activate = 1          ──► Enable FIPS provider    │  │
│  │                                                   │  │
│  │ [algorithm_sect]                                  │  │
│  │ default_properties = fips=yes  ──► FIPS only!    │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              /usr/local/lib/ossl-modules/               │
│  ┌─────────┐  ┌─────────┐  ┌───────────┐               │
│  │ fips.so │  │ base.so │  │ default.so│               │
│  └─────────┘  └─────────┘  └───────────┘               │
└─────────────────────────────────────────────────────────┘
```

### The fipsmodule.cnf File

The `fipsmodule.cnf` file is **critical** for FIPS compliance. It contains:

```ini
[fips_sect]
activate = 1
install-version = 1
conditional-errors = 1
security-checks = 1
module-mac = 7A:B3:C4:...  # HMAC of the fips.so module
install-mac = 8D:E5:F6:...  # HMAC computed during fipsinstall
install-status = INSTALL_SELF_TEST_KATS_RUN
```

**Important**: This file contains machine-specific MACs (Message Authentication Codes) that verify:
1. The FIPS module hasn't been tampered with
2. Self-tests passed on this specific machine

---

## FIPS Provider Portability

### The Key Insight: Providers are Portable

One of the most powerful features of OpenSSL 3.x is that **the FIPS provider can be used with different OpenSSL versions**:

```
┌─────────────────────────────────────────────────────────┐
│                  FIPS Provider (fips.so)                │
│                  Built from OpenSSL 3.1.2               │
│                  (FIPS 140-3 Validated)                 │
└─────────────────────────────────────────────────────────┘
                           │
           Can be used with any of these:
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
   OpenSSL 3.0        OpenSSL 3.4        OpenSSL 3.5
   OpenSSL 3.1        OpenSSL 3.3        (Future 3.x)
```

### Why This Matters

1. **Use Latest Features**: Run OpenSSL 3.5 LTS (with post-quantum crypto) while maintaining FIPS compliance
2. **Security Updates**: Update OpenSSL for security patches without re-validating FIPS
3. **Long-Term Support**: Use LTS versions while keeping validated FIPS provider

### How to Use Validated Provider with Newer OpenSSL

Per the [OpenSSL FIPS README](https://github.com/openssl/openssl/blob/master/README-FIPS.md):

> "Other OpenSSL Releases MAY use the validated FIPS provider, but MUST NOT build and use their own FIPS provider."

**Process**:
```
1. Build validated OpenSSL (e.g., 3.1.2) with enable-fips
   └── Extract: fips.so

2. Build newer OpenSSL (e.g., 3.5.4) WITHOUT enable-fips
   └── Get: libssl.so, libcrypto.so, openssl binary

3. Combine:
   └── Use fips.so from step 1
   └── Use everything else from step 2

4. Run fipsinstall to generate fipsmodule.cnf
```

---

## Building FIPS-Compliant Images

### Multi-Stage Build Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Stage 1: FIPS Provider Build                            │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ FROM alpine:latest AS fipsbuild                     │ │
│ │                                                     │ │
│ │ • Download OpenSSL 3.1.2 (validated version)        │ │
│ │ • ./Configure enable-fips --prefix=/usr/local       │ │
│ │ • make && make install_fips                         │ │
│ │                                                     │ │
│ │ Output: /usr/local/lib/ossl-modules/fips.so         │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 2: OpenSSL Build (Latest LTS)                     │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ FROM alpine:latest AS opensslbuild                  │ │
│ │                                                     │ │
│ │ • COPY fips.so from Stage 1                         │ │
│ │ • Download OpenSSL 3.5.4 (LTS)                      │ │
│ │ • ./Configure shared (NO enable-fips!)              │ │
│ │ • make && make install_sw                           │ │
│ │ • Run: openssl fipsinstall                          │ │
│ │                                                     │ │
│ │ Output: Complete OpenSSL + validated FIPS provider  │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 3: Application Build (Python)                     │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ FROM alpine:latest AS pythoncrypto                  │ │
│ │                                                     │ │
│ │ • Download dependencies BEFORE copying OpenSSL      │ │
│ │ • COPY OpenSSL from Stage 2                         │ │
│ │ • Build Python with --with-openssl=/usr/local       │ │
│ │ • Install cryptography package                      │ │
│ │                                                     │ │
│ │ Output: Python linked to FIPS OpenSSL               │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 4: Minimal Runtime                                │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ FROM alpine:latest                                  │ │
│ │                                                     │ │
│ │ • COPY OpenSSL libraries + fips.so                  │ │
│ │ • COPY Python runtime                               │ │
│ │ • Run: openssl fipsinstall (CRITICAL!)              │ │
│ │ • Create openssl.cnf with FIPS config               │ │
│ │ • Set ENV variables                                 │ │
│ │                                                     │ │
│ │ Output: Minimal FIPS-compliant image                │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Critical Build Steps

#### Step 1: Build FIPS Provider from Validated Source

```dockerfile
FROM alpine:latest AS fipsbuild

ARG FIPS_OPENSSL_VERSION=3.1.2
ARG BUILD_ARCH=linux-x86_64

RUN apk add --no-cache build-base wget linux-headers perl coreutils

# Build ONLY the FIPS provider
RUN wget https://github.com/openssl/openssl/releases/download/openssl-${FIPS_OPENSSL_VERSION}/openssl-${FIPS_OPENSSL_VERSION}.tar.gz \
  && tar -xf openssl-${FIPS_OPENSSL_VERSION}.tar.gz \
  && cd openssl-${FIPS_OPENSSL_VERSION} \
  && ./Configure ${BUILD_ARCH} enable-fips --prefix=/usr/local --libdir=lib \
  && make -j$(nproc) \
  && make install_fips
```

**Key flags**:
- `enable-fips`: Build the FIPS provider
- `--libdir=lib`: Ensure consistent library path (not lib64)

#### Step 2: Build OpenSSL LTS and Run fipsinstall

```dockerfile
FROM alpine:latest AS opensslbuild

ARG OPENSSL_VERSION=3.5.4

# Copy ONLY fips.so (not fipsmodule.cnf!)
COPY --from=fipsbuild /usr/local/lib/ossl-modules/fips.so /usr/local/lib/ossl-modules/

# Build OpenSSL WITHOUT enable-fips
RUN wget https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz \
  && tar -xf openssl-${OPENSSL_VERSION}.tar.gz \
  && cd openssl-${OPENSSL_VERSION} \
  && ./Configure ${BUILD_ARCH} shared --prefix=/usr/local --libdir=lib \
  && make -j$(nproc) \
  && make install_sw

# Generate fipsmodule.cnf for this build environment
ENV LD_LIBRARY_PATH=/usr/local/lib
RUN mkdir -p /usr/local/ssl \
  && /usr/local/bin/openssl fipsinstall \
      -out /usr/local/ssl/fipsmodule.cnf \
      -module /usr/local/lib/ossl-modules/fips.so
```

**Critical**: Do NOT use `enable-fips` when building newer OpenSSL - we're using the validated provider!

#### Step 3: Build Application (Python Example)

```dockerfile
FROM alpine:latest AS pythoncrypto

# Download files BEFORE copying FIPS OpenSSL
# (Uses system OpenSSL which is compatible with system curl/wget)
RUN wget https://www.python.org/ftp/python/3.11.12/Python-3.11.12.tgz

# NOW copy FIPS OpenSSL
COPY --from=opensslbuild /usr/local /usr/local

# Set build environment
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
ENV LDFLAGS="-L/usr/local/lib -Wl,-rpath,/usr/local/lib"
ENV CPPFLAGS="-I/usr/local/include"

# Build Python with FIPS OpenSSL
RUN tar -xf Python-3.11.12.tgz \
  && cd Python-3.11.12 \
  && ./configure \
       --enable-shared \
       --with-openssl=/usr/local \
       --with-openssl-rpath=auto \
  && make -j$(nproc) \
  && make install
```

#### Step 4: Create Runtime Image with fipsinstall

```dockerfile
FROM alpine:latest

ENV PATH=/usr/local/bin:$PATH
ENV LD_LIBRARY_PATH=/usr/local/lib

# Copy runtime dependencies
COPY --from=opensslbuild /usr/local /usr/local
COPY --from=pythoncrypto /usr/local/lib/python3.11 /usr/local/lib/python3.11

# CRITICAL: Run fipsinstall for THIS container
# Per OpenSSL docs: "The FIPS module config file must be generated on every machine"
RUN mkdir -p /usr/local/ssl \
  && /usr/local/bin/openssl fipsinstall \
      -out /usr/local/ssl/fipsmodule.cnf \
      -module /usr/local/lib/ossl-modules/fips.so

# Create FIPS-enabled OpenSSL configuration
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

# Set FIPS environment
ENV OPENSSL_FIPS=1
ENV OPENSSL_CONF=/etc/ssl/openssl.cnf
ENV OPENSSL_MODULES=/usr/local/lib/ossl-modules
```

---

## Key Complexities and Pitfalls

### 1. Alpine Linux (musl libc) Issues

**Problem**: Alpine uses musl libc instead of glibc. The `ldconfig` command doesn't work.

**Symptoms**:
```
Error relocating /usr/local/bin/openssl: EVP_CIPHER_free: symbol not found
```

**Solution**: Use `LD_LIBRARY_PATH` instead of modifying system library paths:
```dockerfile
ENV LD_LIBRARY_PATH=/usr/local/lib
```

**DON'T** modify `/etc/ld-musl-*.path` - it can break system tools!

### 2. Download Order Matters

**Problem**: System tools (curl, wget) are linked against system OpenSSL. If you copy custom OpenSSL first, they break.

**Wrong**:
```dockerfile
COPY --from=opensslbuild /usr/local /usr/local  # Breaks wget!
RUN wget https://example.com/file.tgz           # FAILS
```

**Correct**:
```dockerfile
RUN wget https://example.com/file.tgz           # Uses system OpenSSL
COPY --from=opensslbuild /usr/local /usr/local  # Now safe to copy
```

### 3. fipsinstall Must Run on Target

**Problem**: The `fipsmodule.cnf` contains machine-specific MACs.

**Wrong**:
```dockerfile
# In build stage
RUN openssl fipsinstall -out /usr/local/ssl/fipsmodule.cnf ...

# In runtime stage
COPY --from=build /usr/local/ssl/fipsmodule.cnf /usr/local/ssl/
# This MAY work in Docker but violates FIPS requirements!
```

**Correct**:
```dockerfile
# In runtime stage - regenerate for this container
RUN openssl fipsinstall -out /usr/local/ssl/fipsmodule.cnf ...
```

### 4. FIPS Mode During Build

**Problem**: Setting `OPENSSL_FIPS=1` during build can cause failures if non-FIPS algorithms are used.

**Wrong**:
```dockerfile
ENV OPENSSL_FIPS=1
RUN ./configure && make  # May fail if MD5 checksums are used internally
```

**Correct**:
```dockerfile
# Build WITHOUT FIPS enforcement
RUN ./configure && make

# Enable FIPS AFTER build
ENV OPENSSL_FIPS=1
```

### 5. Missing Directories

**Problem**: `openssl fipsinstall` fails if output directory doesn't exist.

**Error**:
```
BIO routines:BIO_new_file:no such file
```

**Solution**:
```dockerfile
RUN mkdir -p /usr/local/ssl \
  && openssl fipsinstall -out /usr/local/ssl/fipsmodule.cnf ...
```

### 6. Provider Version Compatibility

**Problem**: FIPS provider from OpenSSL 3.1.2 may not work with OpenSSL 2.x or future 4.x.

**Rule**: FIPS provider works across 3.x versions only:
- 3.0.x, 3.1.x, 3.2.x, 3.3.x, 3.4.x, 3.5.x - Compatible
- 2.x, 1.x - NOT compatible
- 4.x (future) - Unknown

---

## Verification Procedures

### 1. Check FIPS Provider is Loaded

```bash
openssl list -providers
```

**Expected Output**:
```
Providers:
  base
    name: OpenSSL Base Provider
    version: 3.5.4
    status: active
  fips
    name: OpenSSL FIPS Provider
    version: 3.1.2
    status: active
```

### 2. Verify Non-FIPS Algorithms are Blocked

```bash
# MD5 should FAIL
echo "test" | openssl md5
# Expected: Error - algorithm not available

# SHA256 should WORK
echo "test" | openssl sha256
# Expected: SHA2-256(stdin)= 9f86d08...
```

### 3. Python Verification

```python
import hashlib

# Test FIPS enforcement
try:
    hashlib.md5(b'test', usedforsecurity=True)
    print("WARNING: MD5 allowed - FIPS may not be enforced")
except ValueError as e:
    print("GOOD: MD5 blocked -", e)

# Verify approved algorithms work
print("SHA256:", hashlib.sha256(b'test').hexdigest())
```

### 4. Check fipsmodule.cnf

```bash
cat /usr/local/ssl/fipsmodule.cnf
```

**Should contain**:
```ini
[fips_sect]
activate = 1
install-version = 1
module-mac = ...
install-mac = ...
install-status = INSTALL_SELF_TEST_KATS_RUN
```

### 5. Verify OpenSSL Configuration

```bash
openssl version -a
cat /etc/ssl/openssl.cnf
```

---

## References

### Official Documentation

- [OpenSSL README-FIPS](https://github.com/openssl/openssl/blob/master/README-FIPS.md)
- [OpenSSL fipsinstall Manual](https://docs.openssl.org/3.2/man1/openssl-fipsinstall/)
- [OpenSSL FIPS Module Manual](https://docs.openssl.org/3.3/man7/fips_module/)
- [NIST CMVP Certificate #4282](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4282)

### Version Information

- [OpenSSL Downloads](https://openssl-library.org/source/index.html)
- [OpenSSL 3.1.2 FIPS Validation Announcement](https://openssl-library.org/post/2025-03-11-fips-140-3/)

### Community Resources

- [Python FIPS Discussion](https://discuss.python.org/t/python-3-with-openssl-3-fips-enabled/20287)
- [Alpine FIPS Issues](https://github.com/openssl/openssl/issues/20595)
- [nginx/alpine-fips](https://github.com/nginx/alpine-fips)

---

## Quick Reference: openssl.cnf Template

```ini
# FIPS-Compliant OpenSSL Configuration
config_diagnostics = 1
openssl_conf = openssl_init

# Include the FIPS module configuration
.include /usr/local/ssl/fipsmodule.cnf

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect
base = base_sect

[base_sect]
activate = 1

[fips_sect]
activate = 1

[algorithm_sect]
# Enforce FIPS-approved algorithms only
default_properties = fips=yes
```

---

## Quick Reference: Environment Variables

```bash
# Required for FIPS operation
export OPENSSL_CONF=/etc/ssl/openssl.cnf
export OPENSSL_MODULES=/usr/local/lib/ossl-modules
export LD_LIBRARY_PATH=/usr/local/lib

# Optional: explicit FIPS mode flag
export OPENSSL_FIPS=1
```

---

*Document Version: 1.0*
*Last Updated: January 2025*
*Based on: OpenSSL 3.1.2 (FIPS), OpenSSL 3.5.4 (LTS), Python 3.11.12, Alpine Linux*
