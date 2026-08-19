# Deliberately weak TLS test target for VulnVista's weak_tls detector.
#
# Uses an older nginx/OpenSSL build (2019-era) on purpose: modern OpenSSL
# increasingly refuses to negotiate TLSv1.0/1.1 or RC4/3DES/MD5 ciphers at
# all, even when explicitly configured via ssl_protocols/ssl_ciphers — the
# restriction lives below the nginx config layer, in OpenSSL's own security
# level. An older build still negotiates them natively, no config fighting
# required.
FROM nginx:1.16.1

# This image's Debian Buster base reached EOL — its regular repos 404 now, so
# point apt at the archive instead before installing anything.
RUN sed -i \
    -e 's|deb.debian.org/debian |archive.debian.org/debian |g' \
    -e 's|security.debian.org/debian-security|archive.debian.org/debian-security|g' \
    -e '/buster-updates/d' \
    /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

# SHA-1 signature — flagged by the weak_tls detector (CWE-327, deprecated
# signature algorithm), on top of it being self-signed (CWE-295). The key
# itself is 2048-bit: OpenSSL's own security level refuses to even *load* a
# genuinely undersized (1024-bit) cert at the SSL_CTX level — that check
# happens before nginx's ssl_ciphers/SECLEVEL override can apply, so a truly
# undersized key isn't achievable here without patching OpenSSL's own
# security policy. The protocol/cipher weaknesses below are the ones that
# matter most anyway.
RUN openssl req -x509 -newkey rsa:2048 -sha1 -days 3650 -nodes \
    -keyout /etc/nginx/weak.key -out /etc/nginx/weak.crt \
    -subj "/C=US/ST=Test/L=Test/O=VulnVista Lab/CN=tls-test"

COPY nginx.conf /etc/nginx/nginx.conf
COPY index.html /usr/share/nginx/html/index.html

EXPOSE 443
