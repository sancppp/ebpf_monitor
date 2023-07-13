package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/segmentio/kafka-go"
)

var (
	reader *kafka.Reader
)

func readKafka(ctx context.Context) {
	// create a new reader with the brokers and topic
	reader = kafka.NewReader(kafka.ReaderConfig{
		Brokers: []string{"localhost:9192"},
		Topic:   "test",
	})

	// read messages from kafka
	for {
		m, err := reader.ReadMessage(context.Background())
		if err != nil {
			log.Println("could not read message ", err)
			continue
		}
		fmt.Printf("message at topic/partition/offset %v/%v/%v: %s = %s\n", m.Topic, m.Partition, m.Offset, string(m.Key), string(m.Value))
	}
}

func listenSignal() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	sig := <-c
	fmt.Printf("signal: %v\n", sig.String())
	if reader != nil {
		reader.Close()
	}
	os.Exit(0)
}

func main() {
	ctx := context.Background()
	go listenSignal()
	readKafka(ctx)
}
