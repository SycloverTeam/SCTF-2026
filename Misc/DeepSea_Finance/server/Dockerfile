FROM syc-ctf-server:latest

# Remove old app files
RUN rm -rf /app

WORKDIR /app

# Copy new challenge and server code
COPY . /app

ENV FOUNDRY_BIN=/usr/local/bin
ENV PYTHONPATH=/app/server

# Pre-compile the DeepSea Finance challenge
RUN forge build --root /app/challenges/deepsea_finance

# Port 1337 for nc (mapped to 6000); 6001-6050 for player RPC proxies
EXPOSE 1337
EXPOSE 6001-6050

RUN chmod +x /app/server/start.sh

CMD ["/app/server/start.sh"]
