package main

import (
	"errors"
	"testing"

	"github.com/corazawaf/coraza/v3/types"
)

type bodyStub struct {
	writeErr, processErr error
	writeIt, processIt   *types.Interruption
	wrote                string
	processed            bool
}

func (tx *bodyStub) WriteRequestBody(data []byte) (*types.Interruption, int, error) {
	tx.wrote = string(data)
	return tx.writeIt, len(data), tx.writeErr
}

func (tx *bodyStub) ProcessRequestBody() (*types.Interruption, error) {
	tx.processed = true
	return tx.processIt, tx.processErr
}

func TestProcessRequestBody(t *testing.T) {
	failure := errors.New("isolated body failure")
	interruption := &types.Interruption{RuleID: 9900001, Status: 413}
	for _, test := range []struct {
		name          string
		data          string
		tx            bodyStub
		wantErr       error
		wantIt        *types.Interruption
		wantProcessed bool
	}{
		{name: "empty", wantProcessed: true},
		{name: "valid", data: "safe", wantProcessed: true},
		{name: "write-error", data: "safe", tx: bodyStub{writeErr: failure}, wantErr: failure},
		{name: "write-interruption", data: "safe", tx: bodyStub{writeIt: interruption}, wantIt: interruption},
		{name: "process-error-empty", tx: bodyStub{processErr: failure}, wantErr: failure, wantProcessed: true},
		{name: "process-error-body", data: "safe", tx: bodyStub{processErr: failure}, wantErr: failure, wantProcessed: true},
		{name: "process-interruption", data: "safe", tx: bodyStub{processIt: interruption}, wantIt: interruption, wantProcessed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			it, err := processRequestBody(&test.tx, test.data)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v; want %v", err, test.wantErr)
			}
			if it != test.wantIt {
				t.Fatalf("interruption = %v; want %v", it, test.wantIt)
			}
			if test.tx.wrote != test.data || test.tx.processed != test.wantProcessed {
				t.Fatalf("wrote=%q processed=%t; want wrote=%q processed=%t", test.tx.wrote, test.tx.processed, test.data, test.wantProcessed)
			}
		})
	}
}
