# syntax=docker/dockerfile:1

FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
ARG TARGETARCH TARGETVARIANT
WORKDIR /app
COPY --chmod=755 fakecd-$TARGETARCH$TARGETVARIANT ./fakecd
RUN set -ex \
    && apk add --no-cache --update \
        docker-cli \
        docker-cli-compose \
        tzdata
ENV TZ=Asia/Shanghai
ENTRYPOINT ["./fakecd"]
