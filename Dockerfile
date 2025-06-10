# Step 1: Build Stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go modules files first (better caching)
COPY go.mod go.sum ./

# Download dependencies and update go.mod
RUN go mod download && go mod tidy

# Copy source code
COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o vilesql .

# Step 2: Run Stage (Uses Small Final Image)
FROM alpine:latest

WORKDIR /app

# Copy built binary from builder stage
COPY --from=builder /app/vilesql .

# Copy .env file from the host to the final image
COPY .env .

# Expose the application port
EXPOSE 5000

# Run the application
CMD ["./vilesql"]
