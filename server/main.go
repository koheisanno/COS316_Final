package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
)

const RECV_BUFFER_SIZE = 2048

/* TODO: server()
 * Open socket and wait for client to connect
 * Print received message to stdout
 */
func server(server_port string) {

	// Create TCP socket and listen for new connections
	listener, _ := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%s", server_port))
	writer := bufio.NewWriter(os.Stdout)

	// Loop waiting for connections
	for {

		// look for a client to connect
		conn, err := listener.Accept()

		if err != nil {
			log.Fatalf("Failed to accept client connection -- %v", err)
		}

		// create an input buffer
		message := make([]byte, RECV_BUFFER_SIZE)

		// loop waiting for client to send data
		for {
			// read the data sent by the client
			bytes_read, err := conn.Read(message)

			if err != nil {
				if err.Error() == "EOF" {
					// client disconnected
					break
				} else {
					log.Fatalf("Failed to read from socket -- %v!", err)
				}
			}

			fmt.Fprint(writer, "TESTING")
			// write the data to stdout
			fmt.Fprint(writer, string(message[:bytes_read]))
			writer.Flush()
		}

		// clean up/close the connection
		err = conn.Close()
		if err != nil {
			log.Fatalf("Error while closing the connection --%v", err)
		}
	}
}

// Main parses command-line arguments and calls server function
func main() {
	if len(os.Args) != 2 {
		log.Fatal("Usage: ./server [server port]")
	}
	server_port := os.Args[1]
	server(server_port)
}
