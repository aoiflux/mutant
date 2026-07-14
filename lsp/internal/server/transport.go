package server

import (
	"context"
	"encoding/json"
	"os"

	"github.com/sourcegraph/jsonrpc2"
	"github.com/tliron/glsp"
)

type stdioRWC struct{}

func (stdioRWC) Read(p []byte) (int, error) {
	return os.Stdin.Read(p)
}

func (stdioRWC) Write(p []byte) (int, error) {
	return os.Stdout.Write(p)
}

func (stdioRWC) Close() error {
	return nil
}

type rpcBridge struct {
	handler glsp.Handler
}

func (b rpcBridge) Handle(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) {
	var params json.RawMessage
	if req.Params != nil {
		params = *req.Params
	}

	callCtx := &glsp.Context{
		Method: req.Method,
		Params: params,
		Notify: func(method string, payload any) {
			_ = conn.Notify(ctx, method, payload)
		},
		Call: func(method string, payload any, result any) {
			_ = conn.Call(ctx, method, payload, result)
		},
	}

	result, validMethod, validParams, err := b.handler.Handle(callCtx)
	if err != nil {
		code := jsonrpc2.CodeInternalError
		if !validMethod {
			code = jsonrpc2.CodeMethodNotFound
		} else if !validParams {
			code = jsonrpc2.CodeInvalidParams
		}
		if !req.Notif {
			_ = conn.ReplyWithError(ctx, req.ID, &jsonrpc2.Error{Code: int64(code), Message: err.Error()})
		}
		return
	}

	if req.Notif {
		return
	}
	_ = conn.Reply(ctx, req.ID, result)
}

func runOverStdio(handler glsp.Handler) error {
	stream := jsonrpc2.NewBufferedStream(stdioRWC{}, jsonrpc2.VSCodeObjectCodec{})
	conn := jsonrpc2.NewConn(context.Background(), stream, jsonrpc2.AsyncHandler(rpcBridge{handler: handler}))
	<-conn.DisconnectNotify()
	return nil
}
