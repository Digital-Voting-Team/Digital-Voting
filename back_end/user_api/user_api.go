package user_api

import (
	tx "digital-voting/transaction"
	"digital-voting/transaction/transaction_json"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
)

type UserApi struct {
	upgrader websocket.Upgrader
	hostname string

	TransactionChannel chan<- tx.ITransaction
	ResponseChannel    <-chan bool
}

func NewUserApi(
	hostname string,
	transactionChannel chan<- tx.ITransaction,
	responseChannel <-chan bool,
) *UserApi {
	ua := &UserApi{
		hostname:           hostname,
		TransactionChannel: transactionChannel,
		ResponseChannel:    responseChannel,
	}

	http.HandleFunc("/transaction", ua.HandleWebSocketNewTransaction)

	return ua
}

// Start start user api
func (ua *UserApi) Start() error {
	return http.ListenAndServe(ua.hostname, nil)
}

func (ua *UserApi) HandleWebSocketNewTransaction(w http.ResponseWriter, r *http.Request) {
	conn, err := ua.upgrader.Upgrade(w, r, nil)
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

	ua.addNewTransaction(conn)
}

func (ua *UserApi) addNewTransaction(conn *websocket.Conn) {
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

	ua.TransactionChannel <- transaction
	success := <-ua.ResponseChannel

	err = conn.WriteJSON(struct {
		Response bool `json:"response"`
	}{Response: success})
	if err != nil {
		log.Println("Error writing response")
		return
	}
}
