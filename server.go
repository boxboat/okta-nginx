package main

import (
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os"
)

const sock = "/var/run/auth.sock"

func removeSockIfExists() {
	_, err := os.Stat(sock)
	if err == nil {
		err = os.Remove(sock)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func main() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println(html.EscapeString(r.URL.Path))
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})

	removeSockIfExists()
	unixListener, err := net.Listen("unix", sock)
	if err != nil {
		log.Fatal(err)
	}
	defer removeSockIfExists()

	if err = os.Chmod(sock, 0777); err != nil {
		log.Fatal(err)
	}

	http.Serve(unixListener, nil)
}
