## Broker server

A server that combine the get audit log and server time request into one to simply the client side logic



## How to run

`PORT=9090 go run server.go`

The server will then run at port `9090` ( Note default server port `9090` if no port is given )



Deploy to heroku

1. Make sure you are logged in to your heroku container system
2. To build Heroku image `heroku container:push web -a your_heroku_app_name`
3. To deploy in Heroku and `heroku container:release web -a your_heroku_app_name`