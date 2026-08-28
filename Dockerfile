# The gateway, as the customer zone runs it.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# The licence travels with the distribution. An image is a way of shipping this
# software, and Apache-2.0 asks that recipients get a copy.
COPY LICENSE NOTICE ./
COPY gateway/ ./gateway/

# python:3.12-slim defines no non-root user. Nothing past the install step needs
# root, and this process listens on a network for agents it is placed in front
# of precisely because they are not trusted.
RUN useradd --system --no-create-home --uid 10001 railgateway
USER 10001

EXPOSE 8080

# Exec form: uvicorn is PID 1 and receives SIGTERM directly, so a stop is a
# graceful shutdown rather than a ten-second wait and a kill.
CMD ["python", "-m", "uvicorn", "--factory", "gateway.server:build_app", "--host", "0.0.0.0", "--port", "8080"]
