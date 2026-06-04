package main

import openai "github.com/sashabaranov/go-openai"

func RunAgent() {
	for {
		resp := agent.step()
		if resp.Done {
			return
		}
	}
}
