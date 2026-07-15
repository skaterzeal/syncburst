package http2

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestReadPeerSettingsHonorsExplicitZeroConcurrency(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverResult := make(chan error, 1)
	go func() {
		_ = server.SetDeadline(time.Now().Add(time.Second))
		payload := settingsPayload(
			[2]uint32{settingMaxConcurrent, 0},
			[2]uint32{settingInitialWindowSize, 32_768},
			[2]uint32{settingMaxFrameSize, 32_768},
		)
		if err := writeOnce(server, appendFrame(nil, frameSettings, 0, 0, payload)); err != nil {
			serverResult <- err
			return
		}
		ack, err := readFrame(server, maxFramePayload)
		if err == nil && (ack.Type != frameSettings || ack.Flags&flagAck == 0 || len(ack.Payload) != 0) {
			serverResult <- fmt.Errorf("unexpected SETTINGS ACK: %#v", ack)
			return
		}
		serverResult <- err
	}()

	e := New()
	e.ReadTimeout = time.Second
	peer, err := e.readPeerSettings(client, bufio.NewReader(client))
	if err != nil {
		t.Fatal(err)
	}
	if !peer.hasMaxConcurrent || peer.maxConcurrent != 0 {
		t.Fatalf("explicit zero concurrency was lost: %#v", peer)
	}
	if peer.initialWindowSize != 32_768 || peer.maxFrameSize != 32_768 {
		t.Fatalf("settings not applied: %#v", peer)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestReadLoopHandlesInformationalResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverResult := make(chan error, 1)
	go func() {
		_ = server.SetDeadline(time.Now().Add(time.Second))
		wire := appendFrame(nil, frameHeaders, flagEndHeaders, 1, appendLiteralHeader(nil, ":status", "103"))
		wire = appendFrame(wire, frameHeaders, flagEndHeaders|flagEndStream, 1, []byte{0x88})
		serverResult <- writeOnce(server, wire)
	}()

	state := &streamState{reqIndex: 0}
	streams := map[uint32]*streamState{1: state}
	e := New()
	if err := e.readLoop(client, bufio.NewReader(client), streams, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
	if state.err != nil || !state.done || state.status != 200 {
		t.Fatalf("unexpected final response state: %#v", state)
	}
}

func TestReadLoopReassemblesContinuation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverResult := make(chan error, 1)
	block := appendLiteralHeader(nil, ":status", "201")
	cut := len(block) / 2
	go func() {
		_ = server.SetDeadline(time.Now().Add(time.Second))
		wire := appendFrame(nil, frameHeaders, flagEndStream, 1, block[:cut])
		wire = appendFrame(wire, frameContinuation, flagEndHeaders, 1, block[cut:])
		serverResult <- writeOnce(server, wire)
	}()

	state := &streamState{reqIndex: 0}
	streams := map[uint32]*streamState{1: state}
	e := New()
	if err := e.readLoop(client, bufio.NewReader(client), streams, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
	if state.err != nil || !state.done || state.status != 201 {
		t.Fatalf("unexpected continuation state: %#v", state)
	}
}

func TestReadLoopRejectsUnexpectedContinuation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_ = server.SetDeadline(time.Now().Add(time.Second))
		_ = writeOnce(server, appendFrame(nil, frameContinuation, flagEndHeaders, 1, []byte{0x88}))
	}()

	streams := map[uint32]*streamState{1: {reqIndex: 0}}
	e := New()
	if err := e.readLoop(client, bufio.NewReader(client), streams, time.Now().Add(time.Second)); err == nil {
		t.Fatal("readLoop accepted an unexpected CONTINUATION")
	}
}
