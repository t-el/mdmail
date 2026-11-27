package mailauth

import (
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
)

func messageHeader(h textproto.Header) message.Header { return message.Header{Header: h} }
