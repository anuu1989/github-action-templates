FROM public.ecr.aws/docker/library/golang:1.23 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/app ./cmd/app

FROM build AS test
RUN go test ./...

FROM cgr.dev/chainguard/static:latest-glibc
COPY --from=build /out/app /app
USER 65532
ENTRYPOINT ["/app"]
