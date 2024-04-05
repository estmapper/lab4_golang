package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println(err)
		return
	}

	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter command: ")
		text, _ := reader.ReadString('\n')
		fmt.Fprintf(conn, text+"\n")

		for {
			message, _ := bufio.NewReader(conn).ReadString('\n')
			fmt.Print("Server reply: " + message)
			if strings.Contains(message, "ERROR") || strings.Contains(message, "successfully") {
				break
			}
			if strings.Contains(message, "End of messages.") || strings.Contains(message, "End of users.") {
				break
			}
		}
	}
}
