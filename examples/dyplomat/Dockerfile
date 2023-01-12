FROM golang:1.18.9

WORKDIR /go/src/dyplomat
COPY . /go/src/dyplomat

RUN go install -v ./...
CMD ["dyplomat"]
