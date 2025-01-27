package websocket

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
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
}

// NewPool creates a new pool.
func NewPool(l *slog.Logger) *Pool {
	return &Pool{
		clients: make(map[*Client]bool),
		log:     l,
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
		p.broadcast(msg)
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
