package cmd

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Bandwidth/vault-shim/application"
	"github.com/Bandwidth/vault-shim/vault"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// Used for flags.
	workingDir            string
	awsConfigFileLocation string

	runCmd = &cobra.Command{
		Use:   "run-cmd",
		Short: "Proxy a run command",
		Long:  "Proxy an executable to allow for various pre-execution environmental configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			env := os.Environ()
			hasVaultEnvVariables := HasVaultEnvVariables(env)

			if hasVaultEnvVariables {
				err := GetVaultToken()
				if err != nil {
					logrus.Fatal(err)
				}

				envExchanger, err := vault.NewEnvironmentExchanger(vaultAddr, vaultToken, vaultRoleName, env, awsConfigFileLocation)
				if err != nil {
					logrus.Fatal(err)
				}
				exchangedEnv, err := envExchanger.ExchangeEnvironment()
				if err != nil {
					logrus.Fatal(err)
				}

				env = exchangedEnv
			}

			if len(args) == 0 {
				logrus.Fatal("you run command and all arguments must be placed after the \"--\" flag")
			}

			app := application.NewApplication()
			app.Executable = args[0] //executable
			app.Dir = workingDir
			app.Args = args[1:]
			app.Env = env
			if _, err := app.Run(); err != nil {
				logrus.Fatal(err)
			}
			return nil
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVar(&workingDir, "working-dir", "", "the working directory")
	viper.BindPFlag("working-dir", rootCmd.PersistentFlags().Lookup("working-dir"))
	rootCmd.PersistentFlags().StringVar(&awsConfigFileLocation, "aws-config-file", getConfigFilePath(), "the generated aws config file path")
	viper.BindPFlag("aws-config-file", rootCmd.PersistentFlags().Lookup("aws-config-file"))

	rootCmd.AddCommand(runCmd)
}

func getConfigFilePath() string {
	random_characters_size := 8

	b := make([]byte, random_characters_size)
	_, err := rand.Read(b)

	if err != nil {
		logrus.Fatal(err)
	}

	random_chars := fmt.Sprintf("%x", b)

	return filepath.Join(os.TempDir(), random_chars+"_aws_config")
}
