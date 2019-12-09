FROM golang:1.13-alpine

WORKDIR /usr/src/app

COPY server /usr/src/app/
RUN chmod +x server

CMD ["./server"]