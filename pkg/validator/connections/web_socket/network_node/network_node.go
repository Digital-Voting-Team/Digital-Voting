package network_node

import (
	"bytes"
	"encoding/json"
	"fmt"
	blk "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/block"
	tx "github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/blockchain/transaction/transaction_json"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	ss "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/single_signature"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/indexed_votings"
	"github.com/gorilla/websocket"
	"log"
	"math"
	"net/http"
	"net/url"
	"strings"
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

func (mt MsgType) String() string {
	switch mt {
	case BlockValidation:
		return "BlockValidation"
	case BlockApproval:
		return "BlockApproval"
	case BlockDenial:
		return "BlockDenial"
	default:
		return fmt.Sprintf("%d", int(mt))
	}
}

type Message struct {
	MessageType MsgType   `json:"message_type"`
	Block       blk.Block `json:"block"`
}

type NetworkNode struct {
	upgrader websocket.Upgrader

	// TODO: consider optimizing or restructuring channels
	ValidatorToNetwork   <-chan *blk.Block
	NetworkToValidator   chan<- *blk.Block
	BlockApprovalChannel chan<- *blk.Block
	ApprovalResponseChan <-chan bool
	BlockDenialChannel   chan<- *blk.Block
	BlockResponseChannel <-chan validator.ResponseMessage
	ValidatorKeysChannel chan<- []keys.PublicKeyBytes

	TransactionChannel         chan<- tx.ITransaction
	TransactionResponseChannel <-chan bool

	VotingsChannel   <-chan []indexed_votings.VotingDTO
	PublicKeyChannel chan<- keys.PublicKeyBytes

	NodeList    []string
	MyPublicKey keys.PublicKeyBytes
	Mutex       sync.Mutex

	hostname string
}

func NewNetworkNode(
	hostname string,
	valToNetChan <-chan *blk.Block,
	netToValChan chan<- *blk.Block,
	blockApprovalChan chan<- *blk.Block,
	approvalResponseChan <-chan bool,
	blockResponseChan <-chan validator.ResponseMessage,
	validatorKeysChan chan<- []keys.PublicKeyBytes,
	transactionChannel chan<- tx.ITransaction,
	transactionResponseChannel <-chan bool,
	votingsChannel <-chan []indexed_votings.VotingDTO,
	publicKeyChannel chan<- keys.PublicKeyBytes,
	validatorPublicKey keys.PublicKeyBytes,
) *NetworkNode {
	nn := &NetworkNode{
		ValidatorToNetwork:         valToNetChan,
		NetworkToValidator:         netToValChan,
		BlockApprovalChannel:       blockApprovalChan,
		ApprovalResponseChan:       approvalResponseChan,
		BlockResponseChannel:       blockResponseChan,
		TransactionChannel:         transactionChannel,
		TransactionResponseChannel: transactionResponseChannel,
		PublicKeyChannel:           publicKeyChannel,
		VotingsChannel:             votingsChannel,

		ValidatorKeysChannel: validatorKeysChan,

		MyPublicKey: validatorPublicKey,
		upgrader:    websocket.Upgrader{},

		hostname: hostname,
	}

	// TODO : consider better naming
	http.HandleFunc("/block", nn.HandleWebSocketNewBlock)
	http.HandleFunc("/update", nn.HandleWebSocketUpdateNodeList)
	http.HandleFunc("/ping", nn.HandleWebSocketPing)
	http.HandleFunc("/transaction", nn.HandleWebSocketNewTransaction)
	http.HandleFunc("/get_votings", nn.HandleWebSocketGetVotings)

	go func() {
		for {
			nn.SendBlockValidation()
		}
	}()

	return nn
}

// Start start network repository
func (n *NetworkNode) Start(nodeConnectorHostname string) error {
	err := n.registerInNodeConnector(nodeConnectorHostname)
	if err != nil {
		return err
	}

	return http.ListenAndServe(n.hostname, nil)
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
	log.Println("Sending request to node connector")
	_, err = http.Post("http://"+nodeConnectorHostname+"/nodes", "application/json", bytes.NewBuffer(marshalled))
	if err != nil {
		return err
	}
	log.Println("Successfully registered in node connector")
	return nil
}

func (n *NetworkNode) ReadMessages(conn *websocket.Conn) {
	_, message, err := conn.ReadMessage()
	if err != nil {
		log.Println("read in ReadMessages:", err)
		return
	}

	messageMap := map[string]interface{}{}
	err = json.Unmarshal(message, &messageMap)
	if err != nil {
		log.Println("json unmarshal here:", err)
		return
	}

	receivedMessage := &Message{}
	_ = json.Unmarshal(message, receivedMessage)

	marshalledBlock, _ := json.Marshal(messageMap["block"])
	receivedBlock, err := blk.UnmarshallBlock(marshalledBlock)
	if err != nil {
		log.Println("block unmarshal:", err)
		return
	}

	log.Printf("Received block with hash %s MessageType: %s", receivedBlock.GetHashString(), receivedMessage.MessageType)

	switch receivedMessage.MessageType {
	case BlockValidation:
		n.NetworkToValidator <- receivedBlock
		responseMessage := <-n.BlockResponseChannel

		err = conn.WriteJSON(responseMessage)
		if err != nil {
			fmt.Println(err)
		}
	case BlockApproval:
		// TODO: consider denial and actions to restore correct state
		n.BlockApprovalChannel <- receivedBlock
		result := <-n.ApprovalResponseChan

		err = conn.WriteJSON(struct {
			Approved bool `json:"approved"`
		}{result})
		if err != nil {
			fmt.Println(err)
		}
	default:
		log.Printf("unknown message type %d", receivedMessage.MessageType)
		return
	}
}

func (n *NetworkNode) SendBlock(conn *websocket.Conn, message Message) {
	// Send the JSON message
	err := conn.WriteJSON(message)
	if err != nil {
		log.Println("write:", err)
		return
	}
}

// SendBlockValidation send blk to all nodes in network
func (n *NetworkNode) SendBlockValidation() {
	message := Message{
		MessageType: BlockValidation,
		Block:       *<-n.ValidatorToNetwork,
	}

	log.Printf("Sending block with hash: %s", message.Block.GetHashString())

	// TODO: update node list
	n.Mutex.Lock()
	for _, indexedData := range n.NodeList {
		address := strings.Split(indexedData, ":")
		conn, err := n.Connect(address[0], address[1], "block")
		if err != nil {
			log.Println("connect:", err)
			continue
		}

		n.SendBlock(conn, message)
		responseMessage := n.WaitForResponse(conn)

		// If verification is true, publickey exists and ss is correct
		if responseMessage.VerificationSuccess &&
			!ss.NewECDSA().VerifyBytes(message.Block.GetHashString(), responseMessage.PublicKey, responseMessage.Signature) {
			message.Block.Sign(responseMessage.PublicKey, responseMessage.Signature)
		}

		err = conn.Close()
		if err != nil {
			log.Println("Error closing connection:", err)
		}
	}

	// TODO: Consider the case when we didn't update NodeList cause of Mutex lock and added to blockchain
	desiredNumber := int(math.Floor(float64(len(n.NodeList)+1) * Threshold))
	log.Println("Desired number of approvals:", desiredNumber)
	decision := len(message.Block.Witness.ValidatorsPublicKeys) >= desiredNumber
	log.Println("Decision:", decision)
	if decision {
		for _, indexedData := range n.NodeList {
			address := strings.Split(indexedData, ":")
			conn, err := n.Connect(address[0], address[1], "block")
			if err != nil {
				log.Println("connect:", err)
				continue
			}

			message.MessageType = BlockApproval
			n.SendBlock(conn, message)

			_, responseMessage, err := conn.ReadMessage()
			if err != nil {
				log.Println("Error reading approval response:", err)
			}
			response := struct {
				Approved bool `json:"approved"`
			}{}
			_ = json.Unmarshal(responseMessage, &response)
			log.Println("Approval response:", response)

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

func (n *NetworkNode) WaitForResponse(conn *websocket.Conn) validator.ResponseMessage {
	_ = conn.SetReadDeadline(time.Now().Add(time.Second * ResponseTime))
	_, message, err := conn.ReadMessage()
	responseMessage := validator.ResponseMessage{
		VerificationSuccess: false,
	}
	if err == nil {
		_ = json.Unmarshal(message, &responseMessage)
	}
	return responseMessage
}

func (n *NetworkNode) Connect(ip string, port string, endpoint string) (*websocket.Conn, error) {
	// IP address and port of the WebSocket server
	//TODO check if ip not empty (consider how it will connect)

	u := url.URL{Scheme: "ws", Host: ip + ":" + port, Path: endpoint}
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
	//log.Println("dtoList:", dtoList)
	n.Mutex.Lock()
	n.NodeList = []string{}
	for _, indexedData := range dtoList.NodeList {
		publicKeys = append(publicKeys, indexedData.ValidatorKey)
		if indexedData.Hostname == n.hostname {
			continue
		}
		n.NodeList = append(n.NodeList, indexedData.Hostname)
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
		//log.Println("Received ping")

		err = conn.WriteControl(websocket.PongMessage, []byte{}, time.Now().Add(15*time.Second))
		if err != nil {
			log.Println("Error sending pong:", err)
		}

		return nil
	})

	defer func(conn *websocket.Conn) {
		err = conn.Close()
		//println("closing connection")
		if err != nil {
			log.Println("Error closing connection:", err)
		}
	}(conn)

	_, _, err = conn.ReadMessage()
	if err != nil {
		//log.Println("Error reading message:", err)
		return
	}
}

func (n *NetworkNode) HandleWebSocketNewTransaction(w http.ResponseWriter, r *http.Request) {
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

	n.addNewTransaction(conn)
}

func (n *NetworkNode) addNewTransaction(conn *websocket.Conn) {
	_, message, err := conn.ReadMessage()
	if err != nil {
		log.Println("read in ReadMessages:", err)
		return
	}

	newTxJson := &transaction_json.JSONTransaction{}
	transaction, err := newTxJson.UnmarshallJSON(message)
	if err != nil {
		log.Println("Error reading transaction from UserAPI")
		return
	}

	log.Printf("Received new transaction with hash: %s", transaction.GetHashString())
	n.TransactionChannel <- transaction
	success := <-n.TransactionResponseChannel
	log.Printf("Transaction with hash %s Verification status: %v", transaction, success)

	err = conn.WriteJSON(struct {
		Response bool `json:"response"`
	}{Response: success})
	if err != nil {
		log.Println("Error writing response")
		return
	}
}

func (n *NetworkNode) HandleWebSocketGetVotings(w http.ResponseWriter, r *http.Request) {
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

	n.getVotings(conn)
}

func (n *NetworkNode) getVotings(conn *websocket.Conn) {
	_, message, err := conn.ReadMessage()
	if err != nil {
		log.Println("read in getVotings:", err)
		return
	}

	publicKeyStruct := &struct {
		PublicKey keys.PublicKeyBytes `json:"public_key"`
	}{}
	err = json.Unmarshal(message, &publicKeyStruct)
	if err != nil {
		log.Println("Error unmarshalling getVotingsRequest")
		return
	}

	n.PublicKeyChannel <- publicKeyStruct.PublicKey
	votings := <-n.VotingsChannel

	err = conn.WriteJSON(struct {
		Votings []indexed_votings.VotingDTO `json:"votings"`
	}{Votings: votings})
	if err != nil {
		log.Println("Error writing response")
		return
	}
}
