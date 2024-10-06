# Base Image 
FROM golang:1.22.5-alpine

# Set Working Dir
WORKDIR /app

# Copy go mod and go sum file
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source from the current directory to the working directory inside the container

COPY . .

# Set ENV variables for Render Deployment

ENV DB_HOST=pgdb
ENV DB_PORT=5432
ENV DB_NAME=gosampledb
ENV DB_USER=gosampledb_user
ENV DB_PASSWORD=TzHHTg8FLga0aWAK9UVzuHnq3P2tzioL
ENV DB_SSLMODE=disable
ENV DB_TIMEZONE=UTC
ENV DB_CONNECT_TIMEOUT=5
ENV JWT_SECRET=verysecret
ENV JWT_ISSUER=example.com
ENV JWT_AUDIENCE=example.com
ENV COOKIE_DOMAIN=localhost
ENV DOMAIN=localhost
ENV API_KEY=b41447e6319d1cd467306735632ba733

# Build app
RUN go build -o main ./cmd/api

# Make file executable
RUN chmod +x main

# Expose the port to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./main"]