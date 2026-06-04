package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "myapp",
	Short: "My CLI application",
	Long:  "A longer description of my CLI application",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("hello from root command")
	},
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the server",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("starting server")
		return nil
	},
}

func Execute() {
	rootCmd.AddCommand(serveCmd)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
