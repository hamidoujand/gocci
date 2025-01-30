# Gocci - Distributed Chat Server

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)
![Redis](https://img.shields.io/badge/Redis-7.0+-DC382D?logo=redis)
![WebSocket](https://img.shields.io/badge/WebSocket-Enabled-brightgreen)
![Nginx](https://img.shields.io/badge/Nginx-1.23+-269539?logo=nginx)

Gocci is a distributed real-time chat application built with Go, Redis pub/sub, and JWT authentication. Designed for horizontal scaling, it leverages Redis for message broadcasting and presence tracking across multiple instances. The system is fronted by Nginx for load balancing and WebSocket proxy capabilities.

## Features

- 🚀 Distributed architecture with Redis pub/sub
- 🔒 JWT-based authentication/authorization
- 👥 Real-time online users tracking
- 💬 WebSocket-based chat messaging
- 📡 Horizontal scaling with Docker + Nginx
- ⚡️ Low-latency communication
- 🔄 Nginx load balancing and reverse proxy

## Tech Stack

- **Language**: Go 1.21+
- **Broker**: Redis 7+
- **WebSocket**: Gorilla WebSocket
- **Auth**: JWT (JSON Web Tokens)
- **Proxy/Load Balancer**: Nginx 1.23+
- **Containerization**: Docker + Docker Compose

## Getting Started

### Prerequisites
- Go 1.21+
- Redis server
- Nginx (for production deployment)
- Docker (optional)

### Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/gocci.git
cd gocci


export REDIS_ADDR=localhost:6379
export JWT_SECRET=your-secure-key-here
```
2. The system uses the following Docker images:
```bash
docker pull redis:7.4.0
docker pull nginx:alpine

make up
