FROM node:22-alpine AS admin-build

WORKDIR /src/admin-ui
COPY admin-ui/package.json admin-ui/pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY admin-ui/ ./
RUN pnpm build

FROM golang:1.25-alpine AS server-build

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /selkie-server ./cmd/control-server

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata iproute2 wireguard-tools libcap \
    && adduser -D -u 10001 selkie

# Grant cap_net_admin on the file capabilities so non-root uid 10001 can run
# `ip` and `wg` (NET_ADMIN must be in the container bounding set via cap_add).
RUN setcap cap_net_admin+eip /sbin/ip \
    && setcap cap_net_admin+eip /usr/bin/wg \
    && getcap /sbin/ip /usr/bin/wg | grep -q cap_net_admin

COPY --from=server-build /selkie-server /usr/local/bin/selkie-server
COPY --from=admin-build /src/admin-ui/dist /app/admin-ui/dist
COPY migrations /app/migrations
COPY assets /app/assets
COPY web /app/web

WORKDIR /app
EXPOSE 8080

USER selkie

ENTRYPOINT ["selkie-server"]
