package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hamidoujand/gocci/internal/auth"
	"github.com/redis/go-redis/v9"
)

const (
	systemMessage   = "system"
	userMessage     = "message"
	presenceMessage = "presence"
	errorMessage    = "error"
)

const (
	joinAction      = "join"
	leftAction      = "left"
	broadcastAction = "broadcast"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(_ *http.Request) bool {
		return true //in development allow all origins
	},
}

// Client represents a chat client in our server
type Client struct {
	conn     *websocket.Conn
	username string
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
	jwtKey  string
}

type message struct {
	Type     string    `json:"type"`     // message|presence|system|error
	Action   string    `json:"action"`   // join|leave
	Username string    `json:"username"` //sender
	Content  string    `json:"content"`  // payload
	Time     time.Time `json:"time"`     //server timestamp
	Users    []string  `json:"users"`    //online users
}

// NewPool creates a new pool.
func NewPool(l *slog.Logger, redisClient *redis.Client, channel string, jwtKey string) *Pool {
	return &Pool{
		clients: make(map[*Client]bool),
		log:     l,
		redis:   redisClient,
		channel: channel,
		jwtKey:  jwtKey,
	}
}

// HandleWebsocket upgrades the http conn to websocket conn.
func (p *Pool) HandleWebsocket(w http.ResponseWriter, r *http.Request) {
	//Extract jwt token from query params
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims, err := auth.ValidateToken(token, p.jwtKey)
	if err != nil {
		p.log.Error("validate token", "err", err.Error())
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		p.log.Error("upgrade ws", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer conn.Close()

	client := Client{conn: conn, username: claims.Username}

	p.addClient(r.Context(), &client)
	defer p.deleteClient(r.Context(), &client)

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			p.log.Error("read message", "err", err.Error())
			break
		}

		p.publishMessage(r.Context(), userMessage, broadcastAction, client.username, string(msg))
	}
}

func (p *Pool) publishMessage(ctx context.Context, msgType, action, username, content string) {
	msg := message{
		Type:     msgType,
		Action:   action,
		Username: username,
		Content:  content,
		Time:     time.Now(),
	}

	if msgType == presenceMessage {
		users, err := p.getOnlineUsers(ctx)
		if err != nil {
			p.publishMessage(ctx, errorMessage, broadcastAction, username, err.Error())
			return
		}
		msg.Users = users
	}

	bs, err := json.Marshal(msg)
	if err != nil {
		p.log.Error("marshaling message", "err", err)
		p.publishMessage(ctx, errorMessage, broadcastAction, username, err.Error())

		return
	}

	if err := p.redis.Publish(ctx, p.channel, bs).Err(); err != nil {
		p.publishMessage(ctx, errorMessage, broadcastAction, username, err.Error())
		p.log.Error("publish message to redis", "err", err.Error())
	}
}

func (p *Pool) addClient(ctx context.Context, client *Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients[client] = true

	//add user to redis set
	p.redis.SAdd(ctx, "online_users", client.username)
	//also broadcast it
	p.publishMessage(ctx, systemMessage, joinAction, client.username, fmt.Sprintf("%s, joined the chat", client.username))
	p.log.Info("add client", "status", fmt.Sprintf("new client %s added", client.conn.RemoteAddr().String()))
}

func (p *Pool) deleteClient(ctx context.Context, client *Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.clients, client)

	//remove the user from redis set
	if err := p.redis.SRem(ctx, "online_users", client.username).Err(); err != nil {
		p.log.Error("removing client from online_users", "err", err)
		p.publishMessage(ctx, errorMessage, broadcastAction, client.username, err.Error())
		return
	}
	//also broadcast a system message
	p.publishMessage(ctx, systemMessage, leftAction, client.username, fmt.Sprintf("%s left the chat", client.username))
	//also delete from redis
	if err := auth.DeletUserCredentials(ctx, p.redis, client.username); err != nil {
		p.log.Error("failed to delete user credentials", "err", err)
		p.publishMessage(ctx, errorMessage, broadcastAction, client.username, err.Error())

		return
	}
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

func (p *Pool) Login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if err := auth.Login(r.Context(), p.redis, username, password); err != nil {
		p.log.Error("invalid credentials", "msg", err.Error())
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := auth.GenerateToken(username, p.jwtKey)
	if err != nil {
		p.log.Error("token generation", "err", err)
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]string{
		"token": token,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (p *Pool) Register(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" || len(password) < 4 {
		http.Error(w, "username can not be empty and password must be greater than 4", http.StatusBadRequest)
		return
	}

	if err := auth.RegisterUser(r.Context(), p.redis, username, password); err != nil {
		p.log.Error("register failed", "err", err)
		http.Error(w, fmt.Sprintf("registeration failed: %s", err), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (p *Pool) getOnlineUsers(ctx context.Context) ([]string, error) {
	return p.redis.SMembers(ctx, "online_users").Result()
}

func (p *Pool) OnlineUsers(w http.ResponseWriter, r *http.Request) {
	users, err := p.getOnlineUsers(r.Context())
	if err != nil {
		p.log.Error("getting online users", "err", err)
		http.Error(w, "failed to get online users", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"count": len(users),
		"users": users,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}
