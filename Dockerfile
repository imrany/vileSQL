# Multi-stage build for smaller final image
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o vilesql .

# Final stage - minimal image
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata sqlite

# Create non-root user
RUN addgroup -g 1001 -S vilesql && \
    adduser -u 1001 -S vilesql -G vilesql

# Create directories
RUN mkdir -p /var/lib/vilesql && \
    mkdir -p /etc/vilesql && \
    chown -R vilesql:vilesql /var/lib/vilesql /etc/vilesql

# Copy binary from builder stage
COPY --from=builder /app/vilesql /usr/local/bin/vilesql

# Copy configuration files
COPY --from=builder /app/.env /etc/vilesql/.env
COPY --from=builder /app/scripts/ /usr/local/share/vilesql/scripts/

# Set proper permissions
RUN chmod +x /usr/local/bin/vilesql && \
    chown vilesql:vilesql /etc/vilesql/.env

# Switch to non-root user
USER vilesql

# Set working directory
WORKDIR /var/lib/vilesql

# Copy .env file to working directory
# COPY --from=builder /app/.env /var/lib/vilesql/.env

# Environment variables
ENV VILESQL_DATA_DIR=/var/lib/vilesql
ENV PORT=5000
ENV HOST=0.0.0.0
ENV SESSION_KEY=your_session_key_here
ENV COOKIE_STORE_KEY=your-cookie-store-key

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:5000/ || exit 1

# Expose port
EXPOSE 5000

# Volume for persistent data
VOLUME ["/var/lib/vilesql"]

# Command to run the application
CMD ["vilesql", "--host=0.0.0.0", "--port=5000"]