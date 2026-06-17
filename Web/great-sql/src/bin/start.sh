#!/bin/bash
set -euo pipefail

mkdir -p /tmp

su -s /bin/bash greatsql -c \
  'exec /opt/java/openjdk/bin/java -Dfile.encoding=UTF-8 -jar /opt/great-sql/great-sql.jar' \
  >/tmp/great-sql.log 2>&1 &

tail -f /dev/null
