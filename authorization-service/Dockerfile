FROM golang:1.21-alpine as builder

WORKDIR /app

COPY . .

RUN go build -o /app/authorization-service

FROM scratch

ENV PORT=3000

EXPOSE ${PORT}

COPY --from=builder /app/authorization-service /app/authorization-service

ENTRYPOINT [ "/app/authorization-service" ]