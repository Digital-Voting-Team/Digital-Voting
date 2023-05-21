package network_node

import (
	"digital-voting/block"
	"digital-voting/transaction/transaction_json"
	"encoding/json"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
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

// network node struct
type NetworkNode struct {
	upgrader        websocket.Upgrader
	BlockChannelIn  <-chan *block.Block
	BlockChannelOut chan<- *block.Block
}

// constructor for network node
func NewNetworkNode(blockChanIn <-chan *block.Block, blockChanOut chan<- *block.Block) *NetworkNode {
	nn := &NetworkNode{
		BlockChannelIn:  blockChanIn,
		BlockChannelOut: blockChanOut,
		upgrader:        websocket.Upgrader{},
	}

	http.HandleFunc("/block", nn.HandleWebSocketNewBlock)

	return nn
}

// Start start network node
func (n *NetworkNode) Start(port string) {
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func (n *NetworkNode) ReadMessages(conn *websocket.Conn) {
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

			var receivedMessage map[string]any
			err = json.Unmarshal(message, &receivedMessage)
			if err != nil {
				log.Println("json unmarshal:", err)
				continue
			}

			receivedBlock := &block.Block{}

			_ = json.Unmarshal(message, &receivedBlock)
			receivedBlock.Body.Transactions = nil

			for _, tx := range receivedMessage["body"].(map[string]any)["transactions"].([]any) {
				transaction := &transaction_json.JSONTransaction{}
				marshall, err := json.Marshal(tx)

				iTransaction, err := transaction.UnmarshallJSON(marshall)
				if err != nil {
					return
				}
				receivedBlock.Body.AddTransaction(iTransaction)
			}
			log.Printf("received message: %+v\n", receivedMessage)
			log.Printf("received block: %+v\n", receivedBlock)

			// send block to channel
			n.BlockChannelOut <- receivedBlock

			log.Printf("received: %+v", receivedMessage)
		}
	}()

	<-done
}

func (n *NetworkNode) SendBlock(conn *websocket.Conn, msgType MsgType) {
	// Marshal the JSON message
	msg := Message{
		MessageType: msgType,
		Block:       *<-n.BlockChannelIn,
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

func (n *NetworkNode) Connect(ip string, port string) (*websocket.Conn, error) {
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

func (n *NetworkNode) HandleWebSocketNewBlock(w http.ResponseWriter, r *http.Request) {
	conn, err := n.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade failed:", err)
		return
	}
	defer func(conn *websocket.Conn) {
		err = conn.Close()
		if err != nil {
			log.Println("Error closing connection:", err)
		}
	}(conn)

	n.ReadMessages(conn)
}
