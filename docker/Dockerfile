FROM golang:latest

ENV GO111MODULE=on \
    GOPROXY=https://goproxy.cn,direct

COPY source/ /scanMaster

WORKDIR /scanMaster
RUN go build . 

ENTRYPOINT ["./ScanMaster"]