FROM golang:1.23.0 AS build_gocci 
ENV CGO_ENABLED=0
ARG BUILD_REF


COPY . /gocci

WORKDIR /gocci/cmd/gocci/
RUN go build -ldflags="-X main.build=${BUILD_REF}" -o gocci main.go


FROM alpine:3.20
ARG BUILD_DATE
ARG BUILD_REF

COPY --from=build_gocci /gocci/cmd/gocci/gocci /service/gocci
COPY --from=build_gocci /gocci/static/. /service/static/. 
WORKDIR /service

CMD [ "./gocci" ]