package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	tmcli "github.com/tendermint/tendermint/libs/cli"
	"github.com/tendermint/tendermint/libs/log"
	dbm "github.com/tendermint/tm-db"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/config"
	"github.com/cosmos/cosmos-sdk/client/debug"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/client/rpc"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/server"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/cosmos/cosmos-sdk/snapshots"
	"github.com/cosmos/cosmos-sdk/store"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authcmd "github.com/cosmos/cosmos-sdk/x/auth/client/cli"
	"github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/crisis"
	genutilcli "github.com/cosmos/cosmos-sdk/x/genutil/client/cli"

	terraapp "github.com/terra-money/core/v2/app"
	"github.com/terra-money/core/v2/app/params"
	"github.com/terra-money/core/v2/app/wasmconfig"
)

// missing flag from cosmos-sdk
const flagIAVLCacheSize = "iavl-cache-size"

// NewRootCmd creates a new root command for terrad. It is called once in the
// main function.
func NewRootCmd() (*cobra.Command, params.EncodingConfig) {
	encodingConfig := terraapp.MakeEncodingConfig()

	sdkConfig := sdk.GetConfig()
	sdkConfig.SetCoinType(terraapp.CoinType)

	accountPubKeyPrefix := terraapp.AccountAddressPrefix + "pub"
	validatorAddressPrefix := terraapp.AccountAddressPrefix + "valoper"
	validatorPubKeyPrefix := terraapp.AccountAddressPrefix + "valoperpub"
	consNodeAddressPrefix := terraapp.AccountAddressPrefix + "valcons"
	consNodePubKeyPrefix := terraapp.AccountAddressPrefix + "valconspub"

	sdkConfig.SetBech32PrefixForAccount(terraapp.AccountAddressPrefix, accountPubKeyPrefix)
	sdkConfig.SetBech32PrefixForValidator(validatorAddressPrefix, validatorPubKeyPrefix)
	sdkConfig.SetBech32PrefixForConsensusNode(consNodeAddressPrefix, consNodePubKeyPrefix)
	sdkConfig.SetAddressVerifier(wasmtypes.VerifyAddressLen())
	sdkConfig.Seal()

	initClientCtx := client.Context{}.
		WithCodec(encodingConfig.Marshaler).
		WithInterfaceRegistry(encodingConfig.InterfaceRegistry).
		WithTxConfig(encodingConfig.TxConfig).
		WithLegacyAmino(encodingConfig.Amino).
		WithInput(os.Stdin).
		WithAccountRetriever(types.AccountRetriever{}).
		WithHomeDir(terraapp.DefaultNodeHome).
		WithViper("TERRA")

	rootCmd := &cobra.Command{
		Use:   "terrad",
		Short: "Stargate Terra App",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// set the default command outputs
			cmd.SetOut(cmd.OutOrStdout())
			cmd.SetErr(cmd.ErrOrStderr())

			initClientCtx, err := client.ReadPersistentCommandFlags(initClientCtx, cmd.Flags())
			if err != nil {
				return err
			}

			// unsafe-reset-all is not working without viper set
			viper.Set(tmcli.HomeFlag, initClientCtx.HomeDir)

			initClientCtx, err = config.ReadFromClientConfig(initClientCtx)
			if err != nil {
				return err
			}

			if err := client.SetCmdClientContextHandler(initClientCtx, cmd); err != nil {
				return err
			}

			terraAppTemplate, terraAppConfig := initAppConfig()

			return server.InterceptConfigsPreRunHandler(cmd, terraAppTemplate, terraAppConfig)
		},
	}

	initRootCmd(rootCmd, encodingConfig)

	return rootCmd, encodingConfig
}

func initRootCmd(rootCmd *cobra.Command, encodingConfig params.EncodingConfig) {
	// TODO check gaia before make release candidate
	// authclient.Codec = encodingConfig.Marshaler

	rootCmd.AddCommand(
		InitCmd(terraapp.ModuleBasics, terraapp.DefaultNodeHome),
		genutilcli.CollectGenTxsCmd(banktypes.GenesisBalancesIterator{}, terraapp.DefaultNodeHome),
		genutilcli.GenTxCmd(terraapp.ModuleBasics, encodingConfig.TxConfig, banktypes.GenesisBalancesIterator{}, terraapp.DefaultNodeHome),
		genutilcli.ValidateGenesisCmd(terraapp.ModuleBasics),
		AddGenesisAccountCmd(terraapp.DefaultNodeHome),
		tmcli.NewCompletionCmd(rootCmd, true),
		debug.Cmd(),
	)

	a := appCreator{encodingConfig}
	server.AddCommands(rootCmd, terraapp.DefaultNodeHome, a.newApp, a.appExport, addModuleInitFlags)

	// add keybase, auxiliary RPC, query, and tx child commands
	rootCmd.AddCommand(
		rpc.StatusCommand(),
		queryCommand(),
		txCommand(),
		keys.Commands(terraapp.DefaultNodeHome),
	)

	// add rosetta commands
	rootCmd.AddCommand(server.RosettaCommand(encodingConfig.InterfaceRegistry, encodingConfig.Marshaler))
}

func addModuleInitFlags(startCmd *cobra.Command) {
	crisis.AddModuleInitFlags(startCmd)
	wasmconfig.AddConfigFlags(startCmd)
}

func queryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "query",
		Aliases:                    []string{"q"},
		Short:                      "Querying subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		authcmd.GetAccountCmd(),
		rpc.ValidatorCommand(),
		rpc.BlockCommand(),
		authcmd.QueryTxsByEventsCmd(),
		authcmd.QueryTxCmd(),
	)

	terraapp.ModuleBasics.AddQueryCommands(cmd)
	cmd.PersistentFlags().String(flags.FlagChainID, "", "The network chain ID")

	return cmd
}

func txCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "tx",
		Short:                      "Transactions subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		authcmd.GetSignCommand(),
		authcmd.GetSignBatchCommand(),
		authcmd.GetMultiSignCommand(),
		authcmd.GetMultiSignBatchCmd(),
		authcmd.GetValidateSignaturesCommand(),
		flags.LineBreak,
		authcmd.GetBroadcastCommand(),
		authcmd.GetEncodeCommand(),
		authcmd.GetDecodeCommand(),
		flags.LineBreak,
		NewMultiSendCmd(),
	)

	terraapp.ModuleBasics.AddTxCommands(cmd)
	cmd.PersistentFlags().String(flags.FlagChainID, "", "The network chain ID")

	return cmd
}

type appCreator struct {
	encodingConfig params.EncodingConfig
}

// newApp is an AppCreator
func (a appCreator) newApp(logger log.Logger, db dbm.DB, traceStore io.Writer, appOpts servertypes.AppOptions) servertypes.Application {
	var cache sdk.MultiStorePersistentCache

	if cast.ToBool(appOpts.Get(server.FlagInterBlockCache)) {
		cache = store.NewCommitKVStoreCacheManager()
	}

	skipUpgradeHeights := make(map[int64]bool)
	for _, h := range cast.ToIntSlice(appOpts.Get(server.FlagUnsafeSkipUpgrades)) {
		skipUpgradeHeights[int64(h)] = true
	}

	pruningOpts, err := server.GetPruningOptionsFromFlags(appOpts)
	if err != nil {
		panic(err)
	}

	snapshotDir := filepath.Join(cast.ToString(appOpts.Get(flags.FlagHome)), "data", "snapshots")
	err = os.MkdirAll(snapshotDir, os.ModePerm)
	if err != nil {
		panic(err)
	}

	snapshotDB, err := sdk.NewLevelDB("metadata", snapshotDir)
	if err != nil {
		panic(err)
	}
	snapshotStore, err := snapshots.NewStore(snapshotDB, snapshotDir)
	if err != nil {
		panic(err)
	}

	return terraapp.NewTerraApp(
		logger, db, traceStore, true, skipUpgradeHeights,
		cast.ToString(appOpts.Get(flags.FlagHome)),
		cast.ToUint(appOpts.Get(server.FlagInvCheckPeriod)),
		a.encodingConfig,
		appOpts,
		wasmconfig.GetConfig(appOpts),
		baseapp.SetPruning(pruningOpts),
		baseapp.SetMinGasPrices(cast.ToString(appOpts.Get(server.FlagMinGasPrices))),
		baseapp.SetHaltHeight(cast.ToUint64(appOpts.Get(server.FlagHaltHeight))),
		baseapp.SetHaltTime(cast.ToUint64(appOpts.Get(server.FlagHaltTime))),
		baseapp.SetMinRetainBlocks(cast.ToUint64(appOpts.Get(server.FlagMinRetainBlocks))),
		baseapp.SetInterBlockCache(cache),
		baseapp.SetTrace(cast.ToBool(appOpts.Get(server.FlagTrace))),
		baseapp.SetIndexEvents(cast.ToStringSlice(appOpts.Get(server.FlagIndexEvents))),
		baseapp.SetSnapshotStore(snapshotStore),
		baseapp.SetSnapshotInterval(cast.ToUint64(appOpts.Get(server.FlagStateSyncSnapshotInterval))),
		baseapp.SetSnapshotKeepRecent(cast.ToUint32(appOpts.Get(server.FlagStateSyncSnapshotKeepRecent))),
		baseapp.SetIAVLCacheSize(int(cast.ToUint64(appOpts.Get(flagIAVLCacheSize)))),
	)
}

func (a appCreator) appExport(
	logger log.Logger, db dbm.DB, traceStore io.Writer, height int64, forZeroHeight bool, jailAllowedAddrs []string,
	appOpts servertypes.AppOptions) (servertypes.ExportedApp, error) {

	homePath, ok := appOpts.Get(flags.FlagHome).(string)
	if !ok || homePath == "" {
		return servertypes.ExportedApp{}, errors.New("application home not set")
	}

	var terraApp *terraapp.TerraApp
	if height != -1 {
		terraApp = terraapp.NewTerraApp(logger, db, traceStore, false, map[int64]bool{}, homePath, cast.ToUint(appOpts.Get(server.FlagInvCheckPeriod)), a.encodingConfig, appOpts, wasmconfig.DefaultConfig())

		if err := terraApp.LoadHeight(height); err != nil {
			return servertypes.ExportedApp{}, err
		}
	} else {
		terraApp = terraapp.NewTerraApp(logger, db, traceStore, true, map[int64]bool{}, homePath, cast.ToUint(appOpts.Get(server.FlagInvCheckPeriod)), a.encodingConfig, appOpts, wasmconfig.DefaultConfig())
	}

	return terraApp.ExportAppStateAndValidators(forZeroHeight, jailAllowedAddrs)
}

func parseCSV(path string) [][]string {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	records, err := csvReader.ReadAll()
	if err != nil {
		panic(err)
	}

	return records
}

// NewMultiSendCmd returns a CLI command for multi-send
func NewMultiSendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "multi-send [csv_file] [denom] [startIndex] [threshold]",
		Short:   "Execute multisend based on csv file",
		Example: `terrad tx multi-send "./airdrop.csv" aacre 0 100 --from=mykey --keyring-backend=test`,
		Args:    cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			sendMsgs := []banktypes.MsgSend{}
			amountRecords := parseCSV(args[0])

			for _, line := range amountRecords[1:] {
				addr, amountStr := line[0], line[1]
				amountDec := sdk.MustNewDecFromStr(amountStr)
				decimalReduction := sdk.NewInt(1000_000_000).Mul(sdk.NewInt(1000_000_000)) // 10^18
				amount := amountDec.Mul(sdk.NewDecFromBigInt(decimalReduction.BigInt())).TruncateInt()

				msg := banktypes.MsgSend{
					FromAddress: clientCtx.FromAddress.String(),
					ToAddress:   addr,
					Amount:      sdk.Coins{sdk.NewCoin(args[1], amount)},
				}
				sendMsgs = append(sendMsgs, msg)
			}

			startIndex, err := strconv.Atoi(args[2])
			if err != nil {
				return err
			}
			threshold, err := strconv.Atoi(args[3])
			if err != nil {
				return err
			}

			msgs := []sdk.Msg{}
			for index, msg := range sendMsgs {
				if index < startIndex {
					continue
				}
				msgs = append(msgs, &banktypes.MsgSend{
					FromAddress: msg.FromAddress,
					ToAddress:   msg.ToAddress,
					Amount:      msg.Amount,
				})
				if len(msgs) >= threshold || index+1 == len(sendMsgs) {
					err := tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msgs...)
					if err != nil {
						return err
					}
					fmt.Printf("executed batch %d/%d\n", index+1, len(sendMsgs))
					msgs = []sdk.Msg{}
				}
			}
			fmt.Println("finalized batch execution")

			return nil
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}
