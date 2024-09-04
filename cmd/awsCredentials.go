package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/Bandwidth/vault-shim/vault"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	namespace         string
	secretPath        string
	accountID         string
	vaultStsRoleName  string
	awsAssumeRoleName string

	awsCredentials = &cobra.Command{
		Use:   "aws-credentials",
		Short: "Output aws credentials",
		Long:  "Prints the required values for the aws profile credential process",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := GetVaultToken()
			if err != nil {
				logrus.Fatal(err)
			}

			awsSecretOutput, err := vault.GetAwsCredentials(vaultToken, namespace, secretPath, accountID, vaultStsRoleName, awsAssumeRoleName, vaultAddr)
			if err != nil {
				logrus.Fatal(err)
			}

			json, err := json.Marshal(awsSecretOutput)
			if err != nil {
				logrus.Fatal(err)
			}

			fmt.Printf(string(json))

			return nil
		},
	}
)

func init() {
	awsCredentials.PersistentFlags().StringVar(&namespace, "namespace", "", "The vault namespace")
	awsCredentials.PersistentFlags().StringVar(&secretPath, "secret-path", "", "Vault path of the aws role")
	awsCredentials.PersistentFlags().StringVar(&accountID, "account-id", "", "AWS account ID")
	awsCredentials.PersistentFlags().StringVar(&vaultStsRoleName, "vault-sts-role-name", "", "The name of the vault sts role")
	awsCredentials.PersistentFlags().StringVar(&awsAssumeRoleName, "aws-assume-role-name", "", "The optional name of the role in AWS to assume")

	awsCredentials.MarkPersistentFlagRequired("secret-path")
	awsCredentials.MarkPersistentFlagRequired("account-id")
	awsCredentials.MarkPersistentFlagRequired("vault-sts-role-name")

	viper.BindPFlag("namespace", rootCmd.PersistentFlags().Lookup("namespace"))
	viper.BindPFlag("secret-path", rootCmd.PersistentFlags().Lookup("secret-path"))
	viper.BindPFlag("account-id", rootCmd.PersistentFlags().Lookup("account-id"))
	viper.BindPFlag("vault-sts-role-name", rootCmd.PersistentFlags().Lookup("vault-sts-role-name"))
	viper.BindPFlag("aws-assume-role-name", rootCmd.PersistentFlags().Lookup("aws-assume-role-name"))
	rootCmd.AddCommand(awsCredentials)
}
