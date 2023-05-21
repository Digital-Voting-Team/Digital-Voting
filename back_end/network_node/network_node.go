package network_node

import (
	"digital-voting/block"
	"encoding/json"
	"github.com/gorilla/websocket"
	"log"
	"net/url"
)

type MsgType uint8

const (
	BlockValidation MsgType = iota
	BlockApproval
	BlockDenial
)

type Message struct {
	MessageType MsgType     `json:"message_type"`
	Block       block.Block `json:"block"`
}

func ReadMessages(conn *websocket.Conn) {
	done := make(chan struct{})

	// Start a goroutine to read messages from the WebSocket connection
	go func() {
		defer close(done)
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				log.Println("read:", err)
				return
			}

			var receivedMessage map[string]interface{}
			err = json.Unmarshal(message, &receivedMessage)
			if err != nil {
				log.Println("json unmarshal:", err)
				continue
			}

			//TODO Unmarshal to block and append to message list

			log.Printf("received: %+v", receivedMessage)
		}
	}()

	<-done
}

func SendBlock(conn *websocket.Conn, b block.Block, msgType MsgType) {
	// Marshal the JSON message
	msg := Message{
		MessageType: msgType,
		Block:       b,
	}
	jsonMessage, err := json.Marshal(msg)
	if err != nil {
		log.Println("json marshal:", err)
		return
	}

	// Send the JSON message
	err = conn.WriteMessage(websocket.TextMessage, jsonMessage)
	if err != nil {
		log.Println("write:", err)
		return
	}
}

func Connect(ip string, port string) (*websocket.Conn, error) {
	// IP address and port of the WebSocket server
	//TODO check if ip not empty (consider how it will connect)

	u := url.URL{Scheme: "ws", Host: ip + ":" + port, Path: "/ws"}
	log.Printf("connecting to %s", u.String())

	// Establish a WebSocket connection
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
