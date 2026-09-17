# One image for every Python service (gateway, fleet, publisher, attacks). Compose picks the command.
FROM python:3.11.9-slim AS build
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir .

FROM python:3.11.9-slim
RUN useradd -m app && mkdir -p /app/fleet-state /app/contracts/deployments && chown -R app /app
COPY --from=build /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=build /usr/local/bin/verigate-* /usr/local/bin/
COPY --chown=app models /app/models
COPY --chown=app tests/fixtures /app/fixtures
WORKDIR /app
USER app
EXPOSE 8000
CMD ["verigate-gateway"]
