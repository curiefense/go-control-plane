FROM golang:1.16.6

WORKDIR /go/src/dyplomat
COPY . /go/src/dyplomat

RUN go install -v ./...
CMD ["dyplomat"]
