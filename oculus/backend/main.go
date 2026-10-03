package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"

	"reconvision/api"
	"reconvision/store"
)

func main() {
	port := flag.Int("port", 8080, "HTTP server port")
	flag.Parse()

	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			*port = p
		}
	}

	st := store.New()
	router := api.NewRouter(st)

	listener, actualPort, err := listenWithFallback(*port, 30)
	if err != nil {
		log.Fatalf("server error: %v", err)
	}

	addr := fmt.Sprintf(":%d", actualPort)
	log.Printf("========================================")
	log.Printf("ReconVision Backend v1.0.0")
	log.Printf("Listening on %s", addr)
	if actualPort != *port {
		log.Printf("Requested port :%d was busy, using %s instead", *port, addr)
	}
	log.Printf("========================================")

	srv := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func listenWithFallback(startPort int, fallbackRange int) (net.Listener, int, error) {
	var lastErr error
	for port := startPort; port <= startPort+fallbackRange; port++ {
		addr := fmt.Sprintf(":%d", port)
		listener, err := net.Listen("tcp", addr)
		if err == nil {
			return listener, port, nil
		}
		lastErr = err
		if port == startPort {
			log.Printf("Port %s unavailable, trying fallback ports: %v", addr, err)
		}
	}
	return nil, 0, fmt.Errorf("no free port found from %d to %d: %w", startPort, startPort+fallbackRange, lastErr)
}
