package signing

import (
	"encoding/json"

	"github.com/WebDelve/signet/keys"
)

type Signer interface {
	// Sign the transaction
	Sign() error

	// Verify the transaction
	Verify(tx Transaction) error

	// Set the transaction
	SetTransaction(txRaw []byte)

	// WithTransaction sets the transaction and returns the signer
	WithTransaction(txRaw []byte) Signer

	// Get the transaction
	GetTransaction() Transaction
}

type signet struct {
	key           keys.KeyHandler
	tx            Transaction
	inputStreams  []string
	outputStreams []string
}

type Transaction struct {
	Terriroriality string                 `json:"$territoriality,omitempty"`
	Transaction    TxBody                 `json:"$tx"`
	SelfSign       bool                   `json:"$selfsign,omitempty"`
	Signature      map[string]interface{} `json:"$sigs"`
}

// toString returns the JSON representation of the transaction
func (t Transaction) ToString() (string, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// toStringIndent returns the indented JSON representation of the transaction
func (t Transaction) ToStringIndent() (string, error) {
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

type TxBody struct {
	Namespace string                 `json:"$namespace"`
	Contract  string                 `json:"$contract"`
	Entry     string                 `json:"$entry,omitempty"`
	Input     map[string]interface{} `json:"$i"`
	Output    map[string]interface{} `json:"$o,omitempty"`
	ReadOnly  map[string]interface{} `json:"$r,omitempty"`
}

func New(key keys.KeyHandler) Signer {
	return &signet{
		key: key,
	}
}

func (s *signet) Sign() error {

	b, err := json.Marshal(s.tx.Transaction)
	if err != nil {
		return err
	}

	signature, _, err := s.key.Sign(b)
	if err != nil {
		return err
	}

	streamID := s.inputStreams[0]

	s.tx.Signature[streamID] = signature

	/* b, _ = json.MarshalIndent(s.tx, "", "  ")
	fmt.Println(string(b)) */
	return nil
}

func (s *signet) Verify(tx Transaction) error {
	return nil
}

func (s *signet) WithTransaction(txRaw []byte) Signer {
	s.SetTransaction(txRaw)
	return s
}

func (s *signet) GetTransaction() Transaction {
	return s.tx
}

func (s *signet) SetTransaction(txRaw []byte) {
	var tx Transaction
	if err := json.Unmarshal(txRaw, &tx); err != nil {
		return
	}

	tx.Signature = make(map[string]interface{})

	s.tx = tx
	s.getStreamIDs()

	/*
	   b, _ := json.MarshalIndent(tx, "", "  ")
	   fmt.Println(string(b))
	*/
}

// getStreamIDs parses the input and output data in the transaction and
// extracts the stream IDs
func (s *signet) getStreamIDs() {
	for k := range s.tx.Transaction.Input {
		s.inputStreams = append(s.inputStreams, k)
	}

	for k := range s.tx.Transaction.Output {
		s.outputStreams = append(s.outputStreams, k)
	}
}
