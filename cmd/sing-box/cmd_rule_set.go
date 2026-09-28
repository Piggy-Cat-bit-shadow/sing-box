package main

import (
	"github.com/spf13/cobra"
)

var commandRuleSet = &cobra.Command{
	Use:   "rule-set",
	Short: "Manage rule-sets",
}

func init() {
	// Withheld from the Jiejie macOS product; see cmd_product_macos.go for why
	if !productExcludesCommand("rule-set") {
		mainCommand.AddCommand(commandRuleSet)
	}
}
