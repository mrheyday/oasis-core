// Package registry implements the registry sub-commands.
package registry

import (
	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/registry/entity"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/registry/node"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/registry/runtime"
)

const (
	// SubcommandRegistry is the registry subcommand.
	CmdRegistry = "registry"
	// CmdEntity is the entity subcommand.
	CmdEntity = "entity"
	// CmdUpdate is the update subcommand.
	CmdUpdate = "update"
	// CmdInit is the init subcommand.
	CmdInit = "init"
)

var registryCmd = &cobra.Command{
	Use:        CmdRegistry,
	Short:      "registry backend utilities",
	Deprecated: "use the `oasis` CLI instead.",
}

// Register registers the registry sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	entity.Register(registryCmd)
	node.Register(registryCmd)
	runtime.Register(registryCmd)

	parentCmd.AddCommand(registryCmd)
}
