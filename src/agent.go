//go:build agent
// +build agent

package main

import (
	"context"
	"log"
	"os"

	"github.com/joho/godotenv"
	"google.golang.org/adk/cmd/launcher/adk"
	"google.golang.org/adk/cmd/launcher/full"
	"google.golang.org/adk/server/restapi/services"

	"foodvibe/src/places"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Printf("config: no .env file loaded: %v", err)
	} else {
		log.Println("config: loaded .env file")
	}

	ctx := context.Background()

	agent, err := places.NewClassifierAgent(ctx, places.ClassifierConfig{
		APIKey: os.Getenv("GOOGLE_API_KEY"),
	})
	if err != nil {
		log.Fatalf("Failed to create classifier agent: %v", err)
	}

	config := &adk.Config{
		AgentLoader: services.NewSingleAgentLoader(agent),
	}

	l := full.NewLauncher()
	err = l.Execute(ctx, config, os.Args[1:])
	if err != nil {
		log.Fatalf("run failed: %v\n\n%s", err, l.CommandLineSyntax())
	}
}
