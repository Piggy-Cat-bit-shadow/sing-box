package main

import (
	"github.com/sagernet/sing-box/common/netns"

	"github.com/spf13/cobra"
)

var commandNetnsHolder = &cobra.Command{
	Use:    "netns-holder",
	Args:   cobra.NoArgs,
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		netns.Hold()
	},
}

func init() {
	// Withheld from the Jiejie macOS product; see cmd_product_macos.go for why
	if !productExcludesCommand("netns-holder") {
		mainCommand.AddCommand(commandNetnsHolder)
	}
}
