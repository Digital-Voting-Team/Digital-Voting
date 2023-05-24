package network_node

import (
	"bytes"
	"digital-voting/block"
	"digital-voting/signature/keys"
	signature "digital-voting/signature/signatures/single_signature"
	"digital-voting/validation"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const Threshold = 0.75

type MsgType uint8

const ResponseTime = 5

const (
	BlockValidation MsgType = iota
	BlockApproval
	BlockDenial
)

type Message struct {
	MessageType MsgType     `json:"message_type"`
	Block       block.Block `json:"block"`
}

type NetworkNode struct {
	upgrader             websocket.Upgrader
	ValidatorToNetwork   <-chan *block.Block
	NetworkToValidator   chan<- *block.Block
	BlockApprovalChannel chan<- *block.Block
	BlockDenialChannel   chan<- *block.Block
	ResponseChannel      <-chan validation.ResponseMessage
	ValidatorKeysChannel chan<- []keys.PublicKeyBytes

	NodeList    []string
	MyPublicKey keys.PublicKeyBytes
	Mutex       sync.Mutex

	hostname string
}

func NewNetworkNode(
	hostname string,
	valToNetChan <-chan *block.Block,
	netToValChan chan<- *block.Block,
	blockApprovalChan chan<- *block.Block,
	responseChan <-chan validation.ResponseMessage,
	validatorKeysChan chan<- []keys.PublicKeyBytes,
	validatorPublicKey keys.PublicKeyBytes,
) *NetworkNode {
	nn := &NetworkNode{
		ValidatorToNetwork:   valToNetChan,
		NetworkToValidator:   netToValChan,
		BlockApprovalChannel: blockApprovalChan,
		ResponseChannel:      responseChan,
		ValidatorKeysChannel: validatorKeysChan,
		MyPublicKey:          validatorPublicKey,
		upgrader:             websocket.Upgrader{},

		hostname: hostname,
	}

	// TODO : consider better naming
	http.HandleFunc("/block", nn.HandleWebSocketNewBlock)
	http.HandleFunc("/update", nn.HandleWebSocketUpdateNodeList)
	// ws endpoint for ping
	http.HandleFunc("/ping", nn.HandleWebSocketPing)

	go func() {
		for {
			nn.SendBlockValidation()
		}
	}()

	return nn
}

// Start start network node
func (n *NetworkNode) Start(port string, nodeConnectorHostname string) error {
	err := n.registerInNodeConnector(nodeConnectorHostname)
	if err != nil {
		return err
	}

	return http.ListenAndServe(":"+port, nil)
}

func (n *NetworkNode) registerInNodeConnector(nodeConnectorHostname string) error {
	s := struct {
		Hostname     string              `json:"hostname"`
		ValidatorKey keys.PublicKeyBytes `json:"validator_key"`
	}{
		Hostname:     n.hostname,
		ValidatorKey: n.MyPublicKey,
	}

	marshalled, err := json.Marshal(s)
	if err != nil {
		return err
	}
	println("Sending request to node connector")
	_, err = http.Post("http://"+nodeConnectorHostname+"/nodes", "application/json", bytes.NewBuffer(marshalled))
	if err != nil {
		return err
	}
	return nil
}

func (n *NetworkNode) ReadMessages(conn *websocket.Conn) {
	_, message, err := conn.ReadMessage()
	if err != nil {
		log.Println("read in ReadMessages:", err)
		return
	}

	var messageMap map[string]any
	err = json.Unmarshal(message, &messageMap)
	if err != nil {
		log.Println("json unmarshal:", err)
		return
	}

	receivedMessage := &Message{}
	_ = json.Unmarshal(message, receivedMessage)

	marshalledBlock, _ := json.Marshal(messageMap["block"])
	receivedBlock, err := block.UnmarshallBlock(marshalledBlock)
	if err != nil {
		log.Println("block unmarshal:", err)
		return
	}

	switch receivedMessage.MessageType {
	case BlockValidation:
		n.NetworkToValidator <- receivedBlock
		responseMessage := <-n.ResponseChannel

		//log.Println(responseMessage.VerificationSuccess)

		err = conn.WriteJSON(responseMessage)
		if err != nil {
			fmt.Println(err)
		}
	case BlockApproval:
		// TODO: consider denial and actions to restore correct state
		n.BlockApprovalChannel <- receivedBlock
	default:
		log.Printf("unknown message type %d", receivedMessage.MessageType)
		return
	}
}

func (n *NetworkNode) SendBlock(conn *websocket.Conn, message Message) {
	jsonMessage, err := json.Marshal(message)
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

// SendBlockValidation send block to all nodes in network
func (n *NetworkNode) SendBlockValidation() {
	message := Message{
		MessageType: BlockValidation,
		Block:       *<-n.ValidatorToNetwork,
	}

	// TODO: update node list
	n.Mutex.Lock()
	for _, node := range n.NodeList {
		conn, err := n.Connect(node, "8080")
		if err != nil {
			log.Println("connect:", err)
			continue
		}

		n.SendBlock(conn, message)
		responseMessage := n.WaitForResponse(conn)

		// If verification is true, publickey exists and signature is correct
		if responseMessage.VerificationSuccess &&
			!signature.NewECDSA().VerifyBytes(message.Block.GetHashString(), responseMessage.PublicKey, responseMessage.Signature) {
			message.Block.Sign(responseMessage.PublicKey, responseMessage.Signature)
		}

		err = conn.Close()
		if err != nil {
			log.Println("Error closing connection:", err)
		}
	}

	// TODO: Consider the case when we didn't update NodeList cause of Mutex lock and added to blockchain
	decision := (float32(len(message.Block.Witness.ValidatorsPublicKeys)) / float32(len(n.NodeList))) >= Threshold
	if decision {
		for _, node := range n.NodeList {
			conn, err := n.Connect(node, "8080")
			if err != nil {
				log.Println("connect:", err)
				continue
			}

			message.MessageType = BlockApproval
			n.SendBlock(conn, message)

			err = conn.Close()
			if err != nil {
				log.Println("Error closing connection:", err)
			}
		}
		n.BlockApprovalChannel <- &message.Block
	} else {
		n.BlockDenialChannel <- &message.Block
	}
	n.Mutex.Unlock()
}

func (n *NetworkNode) WaitForResponse(conn *websocket.Conn) validation.ResponseMessage {
	_ = conn.SetReadDeadline(time.Now().Add(time.Second * ResponseTime))
	_, message, err := conn.ReadMessage()
	responseMessage := validation.ResponseMessage{
		VerificationSuccess: false,
	}
	if err == nil {
		_ = json.Unmarshal(message, &responseMessage)
	}
	return responseMessage
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

func (n *NetworkNode) HandleWebSocketUpdateNodeList(w http.ResponseWriter, r *http.Request) {
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

	n.UpdateNodeList(conn)
}

func (n *NetworkNode) UpdateNodeList(conn *websocket.Conn) {
	_, message, err := conn.ReadMessage()
	if err != nil {
		log.Println("read in UpdateNodeList:", err)
		return
	}

	type DTOList struct {
		NodeList []struct {
			Hostname     string              `json:"hostname"`
			ValidatorKey keys.PublicKeyBytes `json:"validator_key"`
		} `json:"node_list"`
	}

	dtoList := &DTOList{}
	_ = json.Unmarshal(message, &dtoList)
	publicKeys := []keys.PublicKeyBytes{}
	log.Println("dtoList:", dtoList)
	n.Mutex.Lock()
	n.NodeList = []string{}
	for _, node := range dtoList.NodeList {
		if node.ValidatorKey == n.MyPublicKey {
			continue
		}
		n.NodeList = append(n.NodeList, node.Hostname)
		publicKeys = append(publicKeys, node.ValidatorKey)
	}
	n.Mutex.Unlock()

	n.ValidatorKeysChannel <- publicKeys
}

func (n *NetworkNode) HandleWebSocketPing(w http.ResponseWriter, r *http.Request) {
	conn, err := n.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade failed:", err)
		return
	}

	// set ping handler
	conn.SetPingHandler(func(appData string) error {
		log.Println("Received ping")

		err := conn.WriteControl(websocket.PongMessage, []byte{}, time.Now().Add(15*time.Second))
		if err != nil {
			log.Println("Error sending pong:", err)
		}

		return nil
	})

	defer func(conn *websocket.Conn) {
		err := conn.Close()
		println("closing connection")
		if err != nil {
			log.Println("Error closing connection11:", err)
		}
	}(conn)

	_, _, err = conn.ReadMessage()
	if err != nil {
		log.Println("Error reading message:", err)
		return
	}
}
