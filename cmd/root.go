package cmd

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Bandwidth/vault-shim/vault"
	"github.com/davecgh/go-spew/spew"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// Used for flags.
	cfgFile               string
	vaultRoleName         string
	vaultAddr             string
	vaultToken            string
	vaultAwsAuthMount     string
	kubernetesJwtLocation string
	authType              string

	rootCmd = &cobra.Command{
		Use:          "vault-shim",
		Short:        "Various utility functions to configure initialize a process' environment",
		SilenceUsage: true,
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func getAwsAccountId() string {
	if viper.GetBool("verbose") {
		log.Printf("Verbose")

	}
	var err error = fmt.Errorf("Failed to get AWS account id... Are we running in AWS")
	if err != nil {
		fmt.Println("Failed to get AWS account id... Are we running in AWS?", err)
		os.Exit(1)
	}
	return "fooo"
}

func init() {
	cobra.OnInitialize(initConfig)

	//rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cobra.yaml)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().StringVar(&vaultRoleName, "vault-role", "", "the vault role name")
	rootCmd.PersistentFlags().StringVar(&vaultAddr, "vault-addr", GetVaultAddr(), "the vault address")
	rootCmd.PersistentFlags().StringVar(&vaultAwsAuthMount, "vault-aws-mount", "aws_iam", "the vault mount point for AWS auth")
	rootCmd.PersistentFlags().StringVar(&kubernetesJwtLocation, "kubernetes-jwt-location", "/var/run/secrets/kubernetes.io/serviceaccount/token", "the location of kubernetes jwt token")
	rootCmd.PersistentFlags().StringVar(&authType, "auth-type", "", "aws or kubernetes, for EKS use AWS")

	//rootCmd.PersistentFlags().Bool("viper", true, "use Viper for configuration")
	//if err := viper.ReadInConfig(); err != nil && !os.IsNotExist(err) {

	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.SetDefault("verbose", false)
	//viper.BindPFlag("useViper", rootCmd.PersistentFlags().Lookup("viper"))
	viper.BindPFlag("vault-role", rootCmd.PersistentFlags().Lookup("vault-role"))
	viper.BindPFlag("vault-addr", rootCmd.PersistentFlags().Lookup("vault-addr"))
	viper.BindPFlag("vault-aws-mount", rootCmd.PersistentFlags().Lookup("vault-aws-mount"))
	viper.BindPFlag("kubernetes-jwt-location", rootCmd.PersistentFlags().Lookup("kubernetes-jwt-location"))
	viper.BindPFlag("auth-type", rootCmd.PersistentFlags().Lookup("auth-type"))
}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".cobra" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".cobra")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
	if viper.GetBool("verbose") {
		fmt.Print("Config Map: ")
		spew.Dump(viper.AllSettings())
		fmt.Printf("\n")
	}
}

func awsAuth() error {
	token, err := vault.GetVaultTokenAwsAuth(vaultRoleName, vaultAddr, vaultAwsAuthMount)
	if err != nil {
		return fmt.Errorf("vault error aws auth: %w", err)
	}
	vaultToken = token
	return nil
}

func kubeAuth() error {
	if vault.IsKubeServiceAccountJwtOnFile(kubernetesJwtLocation) {
		token, err := vault.GetVaultTokenKubeJwtAuth(vaultRoleName, vaultAddr, kubernetesJwtLocation)
		if err != nil {
			return fmt.Errorf("vault error kube auth: %w", err)
		}
		vaultToken = token
	}
	return nil
}

func GetVaultToken() error {
	existingVaultToken := vault.GetExistingVaultToken()
	if len(existingVaultToken) != 0 && vault.IsTokenValid(existingVaultToken, vaultAddr) {
		vaultToken = existingVaultToken
		return nil
	}
	switch authType {
	case "aws":
		err := awsAuth()
		if err != nil {
			return err
		}
	case "kubernetes":
		err := kubeAuth()
		if err != nil {
			return err
		}
	default:
		if vault.IsKubeServiceAccountJwtOnFile(kubernetesJwtLocation) {
			err := kubeAuth()
			if err != nil {
				return err
			}
		}
		err := awsAuth()
		if err != nil {
			return err
		}
	}
	return nil
}

func GetVaultAddr() string {
	envVaultAddr := os.Getenv("VAULT_ADDR")
	if len(envVaultAddr) != 0 {
		return envVaultAddr
	}
	return "http://localhost:8200"
}

func HasVaultEnvVariables(env []string) bool {
	for i := range env {
		if strings.HasPrefix(env[i], vault.VAULT_ENV_PREFIX) {
			return true
		}
	}

	return false
}
