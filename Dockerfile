FROM rust:alpine as builder

WORKDIR /app

RUN apk add build-base ca-certificates
RUN update-ca-certificates

COPY . .

RUN cargo build --release

FROM scratch

WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/target/release/aws-workload-credentials-provider .

ENTRYPOINT [ "./aws-workload-credentials-provider", "sm", "start" ]
