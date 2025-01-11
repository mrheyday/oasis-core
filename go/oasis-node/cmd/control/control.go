// Package control implements the control sub-commands.
package control

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

var (
	shutdownWait = false

	controlCmd = &cobra.Command{
		Use:   "control",
		Short: "node control interface utilities",
	}

	controlIsSyncedCmd = &cobra.Command{
		Use:   "is-synced",
		Short: "exit with 0 if the node completed initial syncing, 1 if not",
		Run:   doIsSynced,
	}

	controlWaitSyncCmd = &cobra.Command{
		Use:   "wait-sync",
		Short: "wait for the node to complete initial syncing",
		Run:   doWaitSync,
	}

	controlShutdownCmd = &cobra.Command{
		Use:   "shutdown",
		Short: "request node shutdown on next epoch transition",
		Run:   doShutdown,
	}

	controlClearDeregisterCmd = &cobra.Command{
		Use:   "clear-deregister",
		Short: "clear the forced node deregistration flag",
		Run:   doClearDeregister,
	}

	controlUpgradeBinaryCmd = &cobra.Command{
		Use:   "upgrade-binary <upgrade-descriptor>",
		Short: "submit an upgrade descriptor to the node and request shutdown",
		Args:  cobra.ExactArgs(1),
		Run:   doUpgradeBinary,
	}

	controlCancelUpgradeCmd = &cobra.Command{
		Use:   "cancel-upgrade <upgrade-name>",
		Short: "cancel a pending upgrade unless it is already in progress",
		Run:   doCancelUpgrade,
	}

	controlStatusCmd = &cobra.Command{
		Use:   "status",
		Short: "show node status",
		Run:   doStatus,
	}

	controlRuntimeStatsCmd = &cobra.Command{
		Use:        "runtime-stats <runtime-id> [<start-height> [<end-height>]]",
		Short:      "show runtime statistics",
		Run:        doRuntimeStats,
		Deprecated: "use the `oasis` CLI instead.",
	}

	logger = logging.GetLogger("cmd/control")
)

// DoConnect connects to the node's gRPC server.
func DoConnect(cmd *cobra.Command) (*grpc.ClientConn, control.NodeController) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	return doConnectOnly(cmd)
}

func doConnectOnly(cmd *cobra.Command) (*grpc.ClientConn, control.NodeController) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := control.NewNodeControllerClient(conn)

	return conn, client
}

func doIsSynced(cmd *cobra.Command, _ []string) {
	conn, client := DoConnect(cmd)
	defer conn.Close()

	logger.Debug("querying synced status")

	// Use background context to block until the result comes in.
	synced, err := client.IsSynced(context.Background())
	if err != nil {
		logger.Error("failed to query synced status",
			"err", err,
		)
		os.Exit(128)
	}
	if synced {
		fmt.Println("node completed initial syncing")
		os.Exit(0)
	}

	fmt.Println("node has not completed initial syncing")
	os.Exit(1)
}

func doWaitSync(cmd *cobra.Command, _ []string) {
	conn, client := DoConnect(cmd)
	defer conn.Close()

	logger.Debug("waiting for sync status")

	// Use background context to block until the result comes in.
	err := client.WaitSync(context.Background())
	if err != nil {
		logger.Error("failed to wait for sync status",
			"err", err,
		)
		os.Exit(1)
	}
}

func doShutdown(cmd *cobra.Command, _ []string) {
	conn, client := DoConnect(cmd)
	defer conn.Close()

	err := client.RequestShutdown(context.Background(), shutdownWait)
	if err != nil {
		logger.Error("failed to send shutdown request",
			"err", err,
		)
		os.Exit(1)
	}
}

func doClearDeregister(*cobra.Command, []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir := cmdCommon.DataDir()

	// Sigh, there does not appear to be a "open, but do not create"
	// badger option.  Instead, check to see if the persistent store
	// directory exists.
	dbPath := persistent.GetPersistentStoreDBDir(dataDir)
	fs, err := os.Stat(dbPath)
	if err != nil {
		logger.Error("failed to stat persistent store directory",
			"err", err,
		)
		os.Exit(1)
	}
	if !fs.IsDir() {
		logger.Error("persistent store directory, is not a directory")
		os.Exit(1)
	}

	commonStore, err := persistent.NewCommonStore(dataDir)
	if err != nil {
		logger.Error("failed to open common node store",
			"err", err,
		)
		os.Exit(1)
	}
	defer commonStore.Close()

	serviceStore := commonStore.GetServiceStore(registration.DBBucketName)

	if err = registration.SetForcedDeregister(serviceStore, false); err != nil {
		logger.Error("failed to clear persisted forced-deregister",
			"err", err,
		)
		os.Exit(1)
	}

	logger.Info("cleared persisted forced-deregister")
}

func doUpgradeBinary(cmd *cobra.Command, args []string) {
	conn, client := DoConnect(cmd)
	defer conn.Close()

	descriptorBytes, err := os.ReadFile(args[0])
	if err != nil {
		logger.Error("failed to read upgrade descriptor",
			"err", err,
		)
		os.Exit(1)
	}

	var desc upgrade.Descriptor
	if err = json.Unmarshal(descriptorBytes, &desc); err != nil {
		logger.Error("can't parse upgrade descriptor",
			"err", err,
		)
		os.Exit(1)
	}

	if err = desc.ValidateBasic(); err != nil {
		logger.Error("submitted upgrade descriptor is not valid",
			"err", err,
		)
		os.Exit(1)
	}

	if err = client.UpgradeBinary(context.Background(), &desc); err != nil {
		logger.Error("error while sending upgrade descriptor to the node",
			"err", err,
		)
		os.Exit(1)
	}
}

func doCancelUpgrade(cmd *cobra.Command, args []string) {
	conn, client := DoConnect(cmd)
	defer conn.Close()

	if len(args) == 0 {
		logger.Error("expected descriptor path")
		os.Exit(1)
	}

	descriptorBytes, err := os.ReadFile(args[0])
	if err != nil {
		logger.Error("failed to read upgrade descriptor",
			"err", err,
		)
		os.Exit(1)
	}

	var desc upgrade.Descriptor
	if err = json.Unmarshal(descriptorBytes, &desc); err != nil {
		logger.Error("can't parse upgrade descriptor",
			"err", err,
		)
		os.Exit(1)
	}

	err = client.CancelUpgrade(context.Background(), &desc)
	if err != nil {
		logger.Error("failed to send upgrade cancellation request",
			"err", err,
		)
		os.Exit(1)
	}
}

// DoFetchStatus connects to the node's gRPC server and fetches its status.
func DoFetchStatus(cmd *cobra.Command) *control.Status {
	conn, client := DoConnect(cmd)
	defer conn.Close()

	// Use background context to block until the result comes in.
	status, err := client.GetStatus(context.Background())
	if err != nil {
		logger.Error("failed to query status",
			"err", err,
		)
		os.Exit(128)
	}
	return status
}

func doStatus(cmd *cobra.Command, _ []string) {
	status := DoFetchStatus(cmd)

	prettyStatus, err := cmdCommon.PrettyJSONMarshal(status)
	if err != nil {
		logger.Error("failed to get pretty JSON of node status",
			"err", err,
		)
		os.Exit(1)
	}
	fmt.Println(string(prettyStatus))
}

// Register registers the client sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	controlCmd.PersistentFlags().AddFlagSet(cmdGrpc.ClientFlags)

	controlShutdownCmd.Flags().BoolVarP(&shutdownWait, "wait", "w", false, "wait for the node to finish shutdown")

	controlCmd.AddCommand(controlIsSyncedCmd)
	controlCmd.AddCommand(controlWaitSyncCmd)
	controlCmd.AddCommand(controlShutdownCmd)
	controlCmd.AddCommand(controlClearDeregisterCmd)
	controlCmd.AddCommand(controlUpgradeBinaryCmd)
	controlCmd.AddCommand(controlCancelUpgradeCmd)
	controlCmd.AddCommand(controlStatusCmd)
	controlCmd.AddCommand(controlRuntimeStatsCmd)
	parentCmd.AddCommand(controlCmd)
}
