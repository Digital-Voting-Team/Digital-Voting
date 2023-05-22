package network_node

import (
	"digital-voting/block"
	"digital-voting/validation"
	"encoding/json"
	"fmt"
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
	upgrader             websocket.Upgrader
	BlockChannelIn       <-chan *block.Block
	BlockChannelOut      chan<- *block.Block
	BlockApprovalChannel chan<- *block.Block
	ResponseChannel      <-chan validation.ResponseMessage
	NodeList             []string
}

// constructor for network node
func NewNetworkNode(
	blockChanIn <-chan *block.Block,
	blockChanOut chan<- *block.Block,
	blockApprovalChan chan<- *block.Block,
	responseChan <-chan validation.ResponseMessage,
) *NetworkNode {
	nn := &NetworkNode{
		BlockChannelIn:       blockChanIn,
		BlockChannelOut:      blockChanOut,
		BlockApprovalChannel: blockApprovalChan,
		ResponseChannel:      responseChan,
		upgrader:             websocket.Upgrader{},
	}

	http.HandleFunc("/block", nn.HandleWebSocketNewBlock)

	return nn
}

// Start start network node
func (n *NetworkNode) Start(port string) {
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func (n *NetworkNode) ReadMessages(conn *websocket.Conn) {
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

		marshalledBlock, _ := json.Marshal(receivedMessage["block"])
		receivedBlock, err := block.UnmarshallBlock(marshalledBlock)
		if err != nil {
			log.Println("block unmarshal:", err)
			return
		}

		//log.Printf("received message: %+v\n", receivedMessage)
		//log.Printf("received block: %+v\n", receivedBlock)

		// send block to channel
		n.BlockChannelOut <- receivedBlock
		responseMessage := <-n.ResponseChannel

		log.Println(responseMessage.VerificationSuccess)
		log.Println(receivedMessage["sender"])

		err = conn.WriteJSON(responseMessage)
		if err != nil {
			fmt.Println(err)
		}
	}
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
	err = conn.WriteJSON(jsonMessage)
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
