FROM gcc:12-bookworm AS readflag-builder

COPY bin/readflag.c /tmp/readflag.c
RUN gcc -O2 -static -s -o /readflag /tmp/readflag.c

FROM eclipse-temurin:21-jre-jammy

WORKDIR /opt/great-sql

COPY bin/great-sql.jar /opt/great-sql/great-sql.jar
COPY bin/start.sh /start.sh
COPY bin/pushflag.sh /pushflag.sh
COPY bin/flag /flag
COPY --from=readflag-builder /readflag /readflag

RUN groupadd -r greatsql && \
    useradd -r -g greatsql -d /nonexistent -s /usr/sbin/nologin greatsql && \
    chown -R greatsql:greatsql /opt/great-sql && \
    chmod 500 /opt/great-sql && \
    chmod 400 /opt/great-sql/great-sql.jar && \
    chown root:root /start.sh /pushflag.sh /flag /readflag && \
    chmod 500 /start.sh /pushflag.sh && \
    chmod 400 /flag && \
    chmod 4555 /readflag

ENV PORT=8080

EXPOSE 8080

CMD ["/bin/bash", "/start.sh"]
