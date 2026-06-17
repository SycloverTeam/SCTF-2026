FROM debian:bookworm-slim AS readflag-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

COPY bin/readflag.c /tmp/readflag.c
RUN gcc -O2 -Wall -Wextra -fstack-protector-strong -o /readflag /tmp/readflag.c && \
    strip /readflag

FROM php:8.4.22-apache

ARG PHP_VERSION=8.4.22
ARG PHP_SHA256=696c0f6ad92e94c59059c1eb6e300842b8d050934226efcdf00f2a413cb083cf

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        apache2-dev \
        libargon2-dev \
        libcurl4-openssl-dev \
        libonig-dev \
        libreadline-dev \
        libsodium-dev \
        libssl-dev \
        libxml2-dev \
        xz-utils \
        zlib1g-dev \
    ; \
    rm -rf /var/lib/apt/lists/*

COPY php-${PHP_VERSION}.tar.xz /tmp/php-src.tar.xz

RUN set -eux; \
    echo "${PHP_SHA256}  /tmp/php-src.tar.xz" | sha256sum -c -; \
    rm -rf /usr/src/php; \
    mkdir -p /usr/src/php; \
    tar -xJf /tmp/php-src.tar.xz --strip-components=1 -C /usr/src/php; \
    rm -f /tmp/php-src.tar.xz; \
    cd /usr/src/php; \
    gnu_arch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)"; \
    multiarch="$(dpkg-architecture --query DEB_HOST_MULTIARCH)"; \
    ./configure \
        --build="$gnu_arch" \
        --sysconfdir=/usr/local/etc \
        --with-config-file-path=/usr/local/etc/php \
        --with-config-file-scan-dir=/usr/local/etc/php/conf.d \
        --enable-option-checking=fatal \
        --with-mhash \
        --with-pic \
        --enable-mbstring \
        --enable-mysqlnd \
        --with-password-argon2 \
        --with-sodium=shared \
        --without-pdo-sqlite \
        --without-sqlite3 \
        --with-curl \
        --with-iconv \
        --with-openssl \
        --with-readline \
        --with-zlib \
        --disable-phpdbg \
        --with-pear \
        --with-libdir="lib/$multiarch" \
        --disable-cgi \
        --with-apxs2; \
    make -j"$(nproc)"; \
    make install; \
    rm -rf /usr/src/php; \
    rm -rf /tmp/pear ~/.pearrc

ADD all.tar.gz /opt/phpstilalive
COPY --from=readflag-builder /readflag /readflag

RUN a2dismod -f status alias autoindex cgi cgid || true && \
    a2disconf serve-cgi-bin || true && \
    printf '\nServerTokens Prod\nServerSignature Off\n' >> /etc/apache2/apache2.conf && \
    cp /opt/phpstilalive/config/php.ini /usr/local/etc/php/conf.d/zz-challenge.ini && \
    cp /opt/phpstilalive/config/challenge.conf /etc/apache2/conf-enabled/challenge.conf && \
    rm -rf /var/www/html/* && \
    cp -r /opt/phpstilalive/index.php /var/www/html/ && \
    cp /opt/phpstilalive/start.sh /start.sh && \
    cp /opt/phpstilalive/pushflag.sh /pushflag.sh && \
    cp /opt/phpstilalive/flag /lfag-9f1d7c2e-6a2c-4e54-9d7e-6cb10c4b8f9a && \
    chown -R root:root /var/www/html /readflag /pushflag.sh /start.sh /lfag-9f1d7c2e-6a2c-4e54-9d7e-6cb10c4b8f9a && \
    chmod -R 0555 /var/www/html && \
    chmod 0555 /tmp && \
    chmod 0755 /pushflag.sh /start.sh && \
    chmod 4755 /readflag && \
    chmod 0400 /lfag-9f1d7c2e-6a2c-4e54-9d7e-6cb10c4b8f9a && \
    rm -rf /opt/phpstilalive

EXPOSE 80
CMD ["/start.sh"]
