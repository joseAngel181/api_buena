# Etapa 1: Compilación
FROM rust:latest AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Etapa 2: Ejecución
FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y ca-certificates sqlite3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/api_buena .
EXPOSE 8080
CMD ["./api_buena"]