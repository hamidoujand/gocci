package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/hamidoujand/gocci/api/websocket"
	"github.com/redis/go-redis/v9"
)

var build string = "development"

func main() {
	//logger setup
	logger := slog.New(logHandler(os.Stdout, build, slog.LevelDebug,
		slog.String("build", build),
		slog.String("service", "gocci"),
	))
	if err := run(logger); err != nil {
		logger.Error("run failed", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	//==========================================================================
	// GOMAXPROCS
	log.Info("startup", "GOMAXPROCS", runtime.GOMAXPROCS(0))
	//==========================================================================
	// Environment Variables
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		return fmt.Errorf("REDIS_ADDR is a required env")
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return fmt.Errorf("JWT_SECRET is a required env")
	}

	//==========================================================================
	// Redis setup
	redisOpts := redis.Options{
		Addr:     redisAddr, //docker container name
		Password: "",
		DB:       0,
	}
	redisClient := redis.NewClient(&redisOpts)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	status := redisClient.Ping(ctx)
	if status.Err() != nil {
		return fmt.Errorf("ping: %w", status.Err())
	}
	//==========================================================================
	// Websocket Pool
	pool := websocket.NewPool(log, redisClient, "chat_messages", jwtSecret)
	pool.StartRedisListener(context.Background())
	defer pool.Close()

	//==========================================================================
	// Mux setup
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("./static")))

	//websocket endpoint
	mux.HandleFunc("/ws", pool.HandleWebsocket)
	mux.HandleFunc("/login", pool.Login)
	mux.HandleFunc("/register", pool.Register)
	mux.HandleFunc("/online-users", pool.OnlineUsers)

	//==========================================================================
	// Server setup
	server := &http.Server{
		Addr:    ":8000",
		Handler: logMiddleware(log)(mux),
	}

	serverErrs := make(chan error, 1)

	go func() {
		log.Info("startup", "status", "web server is running", "port", ":8000")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrs <- fmt.Errorf("listen and serve: %w", err)
		}
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrs:
		return fmt.Errorf("server error: %w", err)
	case sig := <-shutdown:
		log.Info("shutdown", "status", "shutting down the web server", "signal", sig)
		defer log.Info("shutdown", "status", "shutdown completed")
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			_ = server.Close()
			return fmt.Errorf("shutdonw web server: %w", err)
		}
	}

	return nil
}

func logHandler(w io.Writer, build string, level slog.Level, attrs ...slog.Attr) slog.Handler {
	var handler slog.Handler
	fn := func(groups []string, attr slog.Attr) slog.Attr {
		if attr.Key == slog.SourceKey {
			source, ok := attr.Value.Any().(*slog.Source)
			if ok {
				filename := fmt.Sprintf("%s:%d", filepath.Base(source.File), source.Line)
				return slog.Attr{Key: slog.SourceKey, Value: slog.StringValue(filename)}
			}
		}
		return attr
	}

	if build == "development" {
		//text handler
		handler = slog.NewTextHandler(w, &slog.HandlerOptions{
			Level:       level,
			AddSource:   true,
			ReplaceAttr: fn,
		})
	} else {
		//json handler
		handler = slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level:       level,
			AddSource:   true,
			ReplaceAttr: fn,
		})
	}
	handler = handler.WithAttrs(attrs)
	return handler
}

func logMiddleware(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Info("request", "remoteAddr", r.RemoteAddr, "path", r.URL.Path, "method", r.Method)
			next.ServeHTTP(w, r)
		})
	}
}
