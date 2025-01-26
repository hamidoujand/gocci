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
	// Mux setup
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("./static")))

	//==========================================================================
	// Server setup
	server := &http.Server{
		Addr:         ":8000",
		Handler:      mux,
		ReadTimeout:  time.Second * 10,
		WriteTimeout: time.Second * 10,
		IdleTimeout:  time.Second * 60,
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
