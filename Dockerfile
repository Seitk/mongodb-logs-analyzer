FROM golang:1.20-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/
RUN go build -ldflags '-s -w' -o /mla ./cmd/mla

FROM alpine:3.18
COPY --from=builder /mla /usr/local/bin/mla
ENTRYPOINT ["mla"]
