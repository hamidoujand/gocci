package websocket

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(_ *http.Request) bool {
		return true //in development allow all origins
	},
}

// Client represents a chat client in our server
type Client struct {
	conn *websocket.Conn
}

// Pool represents a pool of clients.
type Pool struct {
	clients map[*Client]bool
	mu      sync.Mutex
	log     *slog.Logger
	redis   *redis.Client
	//redis pubsub connection
	pubsub  *redis.PubSub
	channel string
}

// NewPool creates a new pool.
func NewPool(l *slog.Logger, redisClient *redis.Client, channel string) *Pool {
	return &Pool{
		clients: make(map[*Client]bool),
		log:     l,
		redis:   redisClient,
		channel: channel,
	}
}

// HandleWebsocket upgrades the http conn to websocket conn.
func (p *Pool) HandleWebsocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		p.log.Error("upgrade ws", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer conn.Close()

	client := Client{conn: conn}
	p.addClient(&client)
	defer p.deleteClient(&client)

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			p.log.Error("read message", "err", err.Error())
			break
		}

		// When a message is received from a client, it’s published to Redis.
		// All server instances subscribed to the Redis channel receive the message and broadcast it to their local clients.
		if err := p.redis.Publish(r.Context(), p.channel, msg).Err(); err != nil {
			p.log.Error("publish message", "err", err.Error())
		}
	}
}

func (p *Pool) addClient(client *Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients[client] = true
	p.log.Info("add client", "status", fmt.Sprintf("new client %s added", client.conn.RemoteAddr().String()))
}

func (p *Pool) deleteClient(client *Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.clients, client)
	p.log.Info("delete client", "status", fmt.Sprintf("client %s removed", client.conn.RemoteAddr().String()))
}

func (p *Pool) broadcast(msg []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for client := range p.clients {
		if err := client.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			p.log.Error("broadcast message", "err", err.Error())
		}
	}
}

// StartRedisListener start listening for redis pub/sub in background.
func (p *Pool) StartRedisListener(ctx context.Context) {
	p.pubsub = p.redis.Subscribe(ctx, p.channel)

	//goroutine to receive messages from redis
	go func() {
		for msg := range p.pubsub.Channel() {
			//broadcast
			p.broadcast([]byte(msg.Payload))
		}
	}()
}

// Close closes the pubsub channel.
func (p *Pool) Close() error {
	if err := p.pubsub.Close(); err != nil {
		return fmt.Errorf("closing pubsub: %w", err)
	}
	return nil
}
