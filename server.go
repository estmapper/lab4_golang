package main

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net"
	"strings"
)

var db *sql.DB
var loggedInUsers = make(map[string]bool)

func init() {
	var err error
	db, err = sql.Open("sqlite3", "./chat.db")
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY,
			username TEXT,
			password TEXT
		);
		CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY,
			sender_id INTEGER,
			receiver_id INTEGER,
			message TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(sender_id) REFERENCES users(id),
			FOREIGN KEY(receiver_id) REFERENCES users(id)
		);
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func handleConnection(c net.Conn) {
	fmt.Printf("Serving %s\n", c.RemoteAddr().String())
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from ", r)
			for username := range loggedInUsers {
				delete(loggedInUsers, username)
				fmt.Fprintln(c, "User logged out successfully.")
				fmt.Println("User logged out successfully.")
			}
		}
	}()

	for {
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return
		}

		command := strings.TrimSpace(string(netData))
		if command == "" {
			continue
		}

		params := strings.Split(command, " ")
		switch params[0] {
		case "REGISTER":
			if len(params) != 3 {
				fmt.Fprintln(c, "ERROR: REGISTER command requires 2 parameters.")
				fmt.Println("ERROR: REGISTER command requires 2 parameters.")
				continue
			}

			username := params[1]
			password := hashPassword(params[2])
			_, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, password)
			if err != nil {
				fmt.Fprintln(c, "ERROR: Failed to register user.")
				fmt.Println("ERROR: Failed to register user.")
				continue
			}

			fmt.Fprintln(c, "User registered successfully.")
			fmt.Println("User registered successfully.")
		case "LOGIN":
			if len(params) != 3 {
				fmt.Fprintln(c, "ERROR: LOGIN command requires 2 parameters.")
				fmt.Println("ERROR: LOGIN command requires 2 parameters.")
				continue
			}

			username := params[1]
			password := hashPassword(params[2])

			var storedPassword string
			err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedPassword)
			if err != nil {
				fmt.Fprintln(c, "ERROR: User not found.")
				fmt.Println("ERROR: User not found.")
				continue
			}

			if password != storedPassword {
				fmt.Fprintln(c, "ERROR: Invalid password.")
				fmt.Println("ERROR: Invalid password.")
				continue
			}

			loggedInUsers[username] = true

			fmt.Fprintln(c, "User logged in successfully.")
			fmt.Println("User logged in successfully.")
		case "DELETE":
			if len(params) != 2 {
				fmt.Fprintln(c, "ERROR: DELETE command requires 1 parameter.")
				fmt.Println("ERROR: DELETE command requires 1 parameter.")
				continue
			}

			username := params[1]

			var userID int
			err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
			if err != nil {
				fmt.Fprintln(c, "ERROR: User not found.")
				fmt.Println("ERROR: User not found.")
				continue
			}

			_, err = db.Exec("DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?", userID, userID)
			if err != nil {
				fmt.Fprintln(c, "ERROR: Failed to delete user's messages.")
				fmt.Println("ERROR: Failed to delete user's messages.")
				continue
			}

			_, err = db.Exec("DELETE FROM users WHERE id = ?", userID)
			if err != nil {
				fmt.Fprintln(c, "ERROR: Failed to delete user.")
				fmt.Println("ERROR: Failed to delete user.")
				continue
			}

			delete(loggedInUsers, username)

			fmt.Fprintln(c, "User and their messages deleted successfully.")
			fmt.Println("User and their messages deleted successfully.")
		case "SEND":
			if len(params) != 4 {
				fmt.Fprintln(c, "ERROR: SEND command requires 3 parameters.")
				fmt.Println("ERROR: SEND command requires 3 parameters.")
				continue
			}

			senderUsername := params[1]
			receiverUsername := params[2]
			message := params[3]

			if !loggedInUsers[senderUsername] {
				fmt.Fprintln(c, "ERROR: Sender is not logged in.")
				fmt.Println("ERROR: Sender is not logged in.")
				continue
			}

			var senderID, receiverID int
			err := db.QueryRow("SELECT id FROM users WHERE username = ?", senderUsername).Scan(&senderID)
			if err != nil {
				fmt.Fprintln(c, "ERROR: Sender not found.")
				fmt.Println("ERROR: Sender not found.")
				continue
			}

			err = db.QueryRow("SELECT id FROM users WHERE username = ?", receiverUsername).Scan(&receiverID)
			if err != nil {
				fmt.Fprintln(c, "ERROR: Receiver not found.")
				fmt.Println("ERROR: Receiver not found.")
				continue
			}

			_, err = db.Exec("INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)", senderID, receiverID, message)
			if err != nil {
				fmt.Fprintln(c, "ERROR: Failed to send message.")
				fmt.Println("ERROR: Failed to send message.")
				continue
			}

			fmt.Fprintln(c, "Message sent successfully.")
			fmt.Println("Message sent successfully.")
		case "GET":
			if len(params) != 2 {
				fmt.Fprintln(c, "ERROR: GET command requires 1 parameter.")
				fmt.Println("ERROR: GET command requires 1 parameter.")
				continue
			}

			loggedInUsername := params[1]

			if !loggedInUsers[loggedInUsername] {
				fmt.Fprintln(c, "ERROR: User is not logged in.")
				fmt.Println("ERROR: User is not logged in.")
				continue
			}

			var loggedInUserID int
			err := db.QueryRow("SELECT id FROM users WHERE username = ?", loggedInUsername).Scan(&loggedInUserID)
			if err != nil {
				fmt.Fprintln(c, "ERROR: Logged in user not found.")
				fmt.Println("ERROR: Logged in user not found.")
				continue
			}

			rows, err := db.Query("SELECT sender_id, receiver_id, message FROM messages WHERE sender_id = ? OR receiver_id = ?", loggedInUserID, loggedInUserID)
			if err != nil {
				fmt.Fprintln(c, "ERROR: Failed to get messages.")
				fmt.Println("ERROR: Failed to get messages.")
				continue
			}
			defer rows.Close()

			fmt.Fprintln(c, "Messages:")
			fmt.Println("Messages:")
			for rows.Next() {
				var senderID, receiverID int
				var message string
				err = rows.Scan(&senderID, &receiverID, &message)
				if err != nil {
					fmt.Fprintln(c, "ERROR: Failed to read message.")
					fmt.Println("ERROR: Failed to read message.")
					continue
				}

				var senderUsername, receiverUsername string
				err = db.QueryRow("SELECT username FROM users WHERE id = ?", senderID).Scan(&senderUsername)
				if err != nil {
					fmt.Fprintln(c, "ERROR: Failed to get sender username.")
					fmt.Println("ERROR: Failed to get sender username.")
					continue
				}

				err = db.QueryRow("SELECT username FROM users WHERE id = ?", receiverID).Scan(&receiverUsername)
				if err != nil {
					fmt.Fprintln(c, "ERROR: Failed to get receiver username.")
					fmt.Println("ERROR: Failed to get receiver username.")
					continue
				}

				fmt.Fprintf(c, "From %s to %s: %s\n", senderUsername, receiverUsername, message)
				fmt.Printf("From %s to %s: %s\n", senderUsername, receiverUsername, message)
			}
			fmt.Fprintln(c, "End of messages.")
			fmt.Println("End of messages.")
		case "GETAM":
			if len(params) != 2 {
				fmt.Fprintln(c, "ERROR: GETAM command requires 1 parameter.")
				fmt.Println("ERROR: GETAM command requires 1 parameter.")
				continue
			}

			loggedInUsername := params[1]

			if !loggedInUsers[loggedInUsername] {
				fmt.Fprintln(c, "ERROR: User is not logged in.")
				fmt.Println("ERROR: User is not logged in.")
				continue
			}

			var loggedInUserID int
			err := db.QueryRow("SELECT id FROM users WHERE username = ?", loggedInUsername).Scan(&loggedInUserID)
			if err != nil {
				fmt.Fprintln(c, "ERROR: Logged in user not found.")
				fmt.Println("ERROR: Logged in user not found.")
				continue
			}

			rows, err := db.Query("SELECT sender_id, receiver_id, message FROM messages WHERE sender_id = ? OR receiver_id = ?", loggedInUserID, loggedInUserID)
			if err != nil {
				fmt.Fprintln(c, "ERROR: Failed to get messages.")
				fmt.Println("ERROR: Failed to get messages.")
				continue
			}
			defer rows.Close()

			fmt.Fprintln(c, "Messages:")
			fmt.Println("Messages:")
			for rows.Next() {
				var senderID, receiverID int
				var message string
				err = rows.Scan(&senderID, &receiverID, &message)
				if err != nil {
					fmt.Fprintln(c, "ERROR: Failed to read message.")
					fmt.Println("ERROR: Failed to read message.")
					continue
				}

				var senderUsername, receiverUsername string
				err = db.QueryRow("SELECT username FROM users WHERE id = ?", senderID).Scan(&senderUsername)
				if err != nil {
					fmt.Fprintln(c, "ERROR: Failed to get sender username.")
					fmt.Println("ERROR: Failed to get sender username.")
					continue
				}

				err = db.QueryRow("SELECT username FROM users WHERE id = ?", receiverID).Scan(&receiverUsername)
				if err != nil {
					fmt.Fprintln(c, "ERROR: Failed to get receiver username.")
					fmt.Println("ERROR: Failed to get receiver username.")
					continue
				}

				fmt.Fprintf(c, "From %s to %s: %s\n", senderUsername, receiverUsername, message)
				fmt.Printf("From %s to %s: %s\n", senderUsername, receiverUsername, message)
			}
			fmt.Fprintln(c, "End of messages.")
			fmt.Println("End of messages.")
		case "GETUSERS":
			rows, err := db.Query("SELECT username FROM users")
			if err != nil {

				fmt.Fprintln(c, "ERROR: Failed to get users.")
				fmt.Println("ERROR: Failed to get users.")
				continue
			}
			defer rows.Close()

			fmt.Fprintln(c, "Users:")
			fmt.Println("Users:")
			for rows.Next() {
				var username string
				err = rows.Scan(&username)
				if err != nil {
					fmt.Fprintln(c, "ERROR: Failed to read user.")
					fmt.Println("ERROR: Failed to read user.")
					continue
				}

				fmt.Fprintln(c, username)
				fmt.Println(username)
			}
			fmt.Fprintln(c, "End of users.")
			fmt.Println("End of users.")
		case "EXIT":
			if len(params) != 2 {
				fmt.Fprintln(c, "ERROR: EXIT command requires 1 parameter.")
				fmt.Println("ERROR: EXIT command requires 1 parameter.")
				continue
			}

			username := params[1]

			if !loggedInUsers[username] {
				fmt.Fprintln(c, "ERROR: User is not logged in.")
				fmt.Println("ERROR: User is not logged in.")
				continue
			}

			delete(loggedInUsers, username)

			fmt.Fprintln(c, "User logged out successfully.")
			fmt.Println("User logged out successfully.")
		default:
			fmt.Fprintln(c, "ERROR: Unknown command.")
			fmt.Println("ERROR: Unknown command.")
		}
	}
}

func main() {
	l, err := net.Listen("tcp4", ":8080")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		go handleConnection(c)
	}
}
