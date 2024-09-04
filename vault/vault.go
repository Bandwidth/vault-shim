package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/hashicorp/vault-client-go"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/exp/slices"
)

const VAULT_ENV_PREFIX = "VAULT__"
const iamServerIdHeader = "X-Vault-AWS-IAM-Server-ID"
const CredentialProcessOutputVersion = 1

// <namespace>::<mount>:<path>:<key>[@<version][::<export_name>]
const VAULT_SECRET_REGEX_PATTERN = "^([a-zA-Z0-9\\/_-]+)::([a-zA-Z0-9_-]+):([a-zA-Z0-9\\/_ -]+):([a-zA-Z0-9_ -]+)(?:@(\\d))?$"

var VaultRegex, _ = regexp.Compile(VAULT_SECRET_REGEX_PATTERN)

// AWS:<namespace>/<secret-path>:<aws-account-id>:<vault-sts-role>[:<aws-assume-role>][:vault-auth-role]
const AWS_SECRET_REGEX_PATTERN = "^AWS:([a-zA-Z0-9\\/_-]*)/([a-zA-Z0-9\\/_-]+):([0-9]+):([a-zA-Z0-9_-]+)(?:\\:([a-zA-Z0-9_-]+)?)?(?:\\:([a-zA-Z0-9_-]+))?$"

var AwsSecretRegex, _ = regexp.Compile(AWS_SECRET_REGEX_PATTERN)

const awsProfileTemplate = `
[profile {{.ProfileName}}]
credential_process = vault-shim aws-credentials --namespace="{{.Namespace}}" --secret-path="{{.SecretPath}}" --account-id="{{.AccountID}}" --vault-sts-role-name="{{.VaultStsRoleName}}" --aws-assume-role-name="{{.AwsAssumeRoleName}}" --vault-role="{{.VaultAuthRoleName}}"
`

type GenericSecret struct {
	value        string
	key          string
	path         string
	exportName   string
	originalName string
	mount        string
	//Optional
	version int
}

func (gS *GenericSecret) readSecret(client *vault.Client) error {
	data, err := gS.querySecret(client)
	if err != nil {
		return err
	}

	version, err := strconv.Atoi(data.Data["metadata"].(map[string]interface{})["version"].(json.Number).String())
	if err != nil {
		return err
	}

	value, ok := data.Data["data"].(map[string]interface{})[gS.key]

	if !ok {
		return errors.New(fmt.Sprintf("Secret key %s not found", gS.key))
	}

	gS.value = value.(string)
	gS.version = version

	return nil
}

func (gS *GenericSecret) exportSecret(_ string, env []string) ([]string, error) {
	return append(env, fmt.Sprintf("%s=%s", gS.exportName, gS.value)), nil
}

func (gS *GenericSecret) getSecretPathKey() string {
	return fmt.Sprintf("%s/%s@%d", gS.mount, gS.path, gS.version)
}

type AwsSecret struct {
	secretPath            string
	accountID             string
	vaultStsRoleName      string
	awsAssumeRoleName     string
	awsConfigFileLocation string
	accessKeyId           string
	secretAccessKey       string
	sessionToken          string
	profileName           string
	vaultAuthRole         string
	expiration            time.Time
}

type AwsSecretOutput struct {
	Version         int
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      string
}

func (aS *AwsSecret) readSecret(client *vault.Client) error {
	roleArn := "arn:aws:iam::" + aS.accountID + ":role/" + aS.awsAssumeRoleName
	path := "v1/" + aS.secretPath + "/sts/" + aS.vaultStsRoleName

	resp, err := client.Write(context.Background(), path, map[string]any{})
	if err != nil {
		return err
	}

	accessKey, ok := resp.Data["access_key"].(string)
	if !ok {
		return errors.New("Could not read access_key from vault response")
	}

	secretKey, ok := resp.Data["secret_key"].(string)
	if !ok {
		return errors.New("Could not read secret_key from vault response")
	}

	sessionToken, ok := resp.Data["security_token"].(string)
	if !ok {
		return errors.New("Could not read security_token from vault response")
	}

	expirationTtlNumber, ok := resp.Data["ttl"].(json.Number)
	if !ok {
		return errors.New("Could not read ttl from vault response")
	}
	expirationTtlFloat, err := expirationTtlNumber.Float64()
	if err != nil {
		return err
	}
	expiration := time.Now().Add(time.Duration(expirationTtlFloat * float64(time.Second)))

	if aS.awsAssumeRoleName != "" {
		creds := credentials.NewStaticCredentials(accessKey, secretKey, sessionToken)
		session, err := session.NewSession(&aws.Config{
			Credentials: creds,
		})
		if err != nil {
			return err
		}

		roleSessionName := aS.awsAssumeRoleName
		svc := sts.New(session)
		assumedRole, err := svc.AssumeRole(&sts.AssumeRoleInput{
			RoleArn:         &roleArn,
			RoleSessionName: &roleSessionName,
		})
		if err != nil {
			return err
		}

		aS.accessKeyId = *assumedRole.Credentials.AccessKeyId
		aS.secretAccessKey = *assumedRole.Credentials.SecretAccessKey
		aS.sessionToken = *assumedRole.Credentials.SessionToken
		aS.expiration = *assumedRole.Credentials.Expiration
	} else {
		aS.accessKeyId = accessKey
		aS.secretAccessKey = secretKey
		aS.sessionToken = sessionToken
		aS.expiration = expiration
	}
	return nil
}

func (aS *AwsSecret) exportSecret(namespace string, env []string) ([]string, error) {
	configFilePath := aS.awsConfigFileLocation
	err := aS.writeAwsProfile(namespace, configFilePath)
	if err != nil {
		return env, err
	}

	if !slices.Contains(env, "AWS_CONFIG_FILE") {
		env = append(env, fmt.Sprintf("%s=%s", "AWS_CONFIG_FILE", configFilePath))
	}
	return env, nil
}

func (aS *AwsSecret) getSecretPathKey() string {
	return fmt.Sprintf("%s/%s/%s/%s", aS.secretPath, aS.accountID, aS.vaultStsRoleName, aS.awsAssumeRoleName)
}

func (aS *AwsSecret) writeAwsProfile(namespace string, configFilePath string) error {
	t := template.Must(template.New("aws-profile-template").Parse(awsProfileTemplate))

	f, err := os.OpenFile(configFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	templateData := struct {
		Namespace         string
		SecretPath        string
		AccountID         string
		VaultStsRoleName  string
		AwsAssumeRoleName string
		ProfileName       string
		VaultAuthRoleName string
	}{
		Namespace:         namespace,
		SecretPath:        aS.secretPath,
		AccountID:         aS.accountID,
		VaultStsRoleName:  aS.vaultStsRoleName,
		AwsAssumeRoleName: aS.awsAssumeRoleName,
		ProfileName:       aS.profileName,
		VaultAuthRoleName: aS.vaultAuthRole,
	}

	err = t.Execute(f, templateData)
	if err != nil {
		return err
	}

	return nil
}

type SecretRequest struct {
	namespace string
	SecretRetriever
}

type SecretRetriever interface {
	readSecret(*vault.Client) error
	getSecretPathKey() string
	exportSecret(string, []string) ([]string, error)
}

type NamespaceRequest struct {
	vaultClient *vault.Client
	namespace   string
	// Map of mount+path to SecretRequests.
	// Avoid using the map key for HTTP calls as it does not take any `/data` intermediate paths into account.
	secretRequests map[string]map[*SecretRequest]bool // Mimic Map<String, Set<SecretRequest>>
}

type EnvironmentExchanger struct {
	namespaceRequests []*NamespaceRequest
	vaultToken        string
	vaultAddr         string
	vaultRole         string
	currentEnv        []string
}

// Creates a new EnvironmentExchanger.
func NewEnvironmentExchanger(vaultAddr string, vaultToken string, vaultRole string, currentEnv []string, awsConfigFileLocation string) (*EnvironmentExchanger, error) {
	var envExchanger = &EnvironmentExchanger{
		vaultAddr:  vaultAddr,
		vaultToken: vaultToken,
		vaultRole:  vaultRole,
		currentEnv: currentEnv,
	}
	var vaultEnvEntries, err = getVaultEnvEntries(currentEnv)
	if err != nil {
		return nil, fmt.Errorf("error generating Vault entries from current env: %w", err)
	}
	err = envExchanger.generateNamespaceRequests(vaultEnvEntries, awsConfigFileLocation)
	if err != nil {
		return nil, fmt.Errorf("error generating Vault namespace requests from current env: %w", err)
	}
	err = envExchanger.retrieveSecretValues()
	if err != nil {
		return nil, fmt.Errorf("error retrieving Vault secret values: %w", err)
	}

	return envExchanger, nil
}

func getVaultEnvEntries(currentEnv []string) ([]string, error) {
	var vaultEnvEntries []string
	for i := range currentEnv {
		if strings.HasPrefix(currentEnv[i], VAULT_ENV_PREFIX) {
			vaultEnvEntries = append(vaultEnvEntries, currentEnv[i])
		}
	}
	return vaultEnvEntries, nil
}

func getSecretRequest(vaultEnvEntry string, awsConfigFileLocation string, currentVaultAuthRole string) (*SecretRequest, error) {
	var split = strings.Split(vaultEnvEntry, "=")
	var rawKey = split[0]
	var rawValue = split[1]

	if strings.HasPrefix(rawValue, "AWS") {
		return getAwsSecretRequest(rawKey, rawValue, awsConfigFileLocation, currentVaultAuthRole)
	}

	return getGenericSecretRequest(rawKey, rawValue)
}

func getAwsSecretRequest(envKey string, envValue string, awsConfigFileLocation string, currentVaultAuthRole string) (*SecretRequest, error) {
	var match = AwsSecretRegex.FindStringSubmatch(envValue)
	if match == nil {
		return nil, fmt.Errorf("unmatched secret request '%s' found. AWS Secret Request strings must be of format 'AWS:<namespace>/<secret-path>:<aws-account-id>:<vault-sts-role>[:<aws-assume-role>][:vault-auth-role]']", envValue)
	}
	var vaultRole = currentVaultAuthRole
	if match[6] != "" {
		vaultRole = match[6]
	}

	return &SecretRequest{
		match[1],
		&AwsSecret{
			secretPath:            match[2],
			accountID:             match[3],
			vaultStsRoleName:      match[4],
			awsAssumeRoleName:     match[5],
			awsConfigFileLocation: awsConfigFileLocation,
			profileName:           strings.ReplaceAll(envKey, VAULT_ENV_PREFIX, ""),
			vaultAuthRole:         vaultRole,
		},
	}, nil
}

func getGenericSecretRequest(envKey string, envValue string) (*SecretRequest, error) {
	var match = VaultRegex.FindStringSubmatch(envValue)
	if match == nil {
		return nil, fmt.Errorf("unmatched secret request '%s' found. Secret Request strings must be of format '<namespace>::<mount>:<path>:<key>[@<version>']", envValue)
	}
	var version = -1
	var err error
	if len(match) > 4 && match[5] != "" {
		version, err = strconv.Atoi(match[5])
		if err != nil {
			return nil, fmt.Errorf("non-numerical version found '%s', %w", match[5], err)
		}
	}

	return &SecretRequest{
		match[1],
		&GenericSecret{
			mount:        match[2],
			path:         match[3],
			key:          match[4],
			exportName:   strings.ReplaceAll(envKey, VAULT_ENV_PREFIX, ""),
			originalName: envKey,
			//Optional
			version: version,
		},
	}, nil
}

func (a *EnvironmentExchanger) groupSecretRequests(secretRequests []SecretRequest) ([]*NamespaceRequest, error) {
	namespaceRequestsMap := make(map[string]*NamespaceRequest)
	for i := range secretRequests {
		secretRequest := secretRequests[i]
		existingNamespaceRequest, exists := namespaceRequestsMap[secretRequest.namespace]
		if !exists {
			client, err := GetVaultClient(a.vaultAddr)
			if err != nil {
				return nil, err
			}
			err = client.SetToken(a.vaultToken)
			if err != nil {
				return nil, err
			}
			err = client.SetNamespace(secretRequest.namespace)
			if err != nil {
				return nil, err
			}
			namespaceRequestsMap[secretRequest.namespace] = &NamespaceRequest{
				vaultClient: client,
				namespace:   secretRequest.namespace,
				// Map of mount+path to SecretRequests.
				// Avoid using the map key for HTTP calls as it does not take any `/data` intermediate paths into account.
				secretRequests: make(map[string]map[*SecretRequest]bool),
			}
			existingNamespaceRequest = namespaceRequestsMap[secretRequest.namespace]
		}
		versionPathKey := secretRequest.getSecretPathKey()
		_, exists = existingNamespaceRequest.secretRequests[versionPathKey]
		if !exists {
			existingNamespaceRequest.secretRequests[versionPathKey] = make(map[*SecretRequest]bool)
		}
		existingNamespaceRequest.secretRequests[versionPathKey][&secretRequest] = true

	}
	v := make([]*NamespaceRequest, 0, len(namespaceRequestsMap))
	for _, value := range namespaceRequestsMap {
		v = append(v, value)
	}
	a.namespaceRequests = v
	return a.namespaceRequests, nil
}

func (a *EnvironmentExchanger) generateNamespaceRequests(vaultEnvEntries []string, awsConfigFileLocation string) error {
	secretRequests := make([]SecretRequest, len(vaultEnvEntries))
	for i := range vaultEnvEntries {
		secretRequest, err := getSecretRequest(vaultEnvEntries[i], awsConfigFileLocation, a.vaultRole)
		if err != nil {
			return fmt.Errorf("error getting secret request: %w", err)
		}
		secretRequests[i] = *secretRequest
	}
	namespaceRequests, err := a.groupSecretRequests(secretRequests)
	if err != nil {
		return fmt.Errorf("error grouping secret requests: %w", err)
	}
	a.namespaceRequests = namespaceRequests

	return nil
}

func (gS *GenericSecret) querySecret(client *vault.Client) (*vault.Response[map[string]interface{}], error) {
	var queryParams = url.Values{}
	if gS.version >= 0 {
		queryParams["version"] = []string{strconv.Itoa(gS.version)}
	}
	requestPath := "/v1/{secret_mount_path}/data/{path}"
	requestPath = strings.Replace(requestPath, "{"+"secret_mount_path"+"}", url.PathEscape(gS.mount), -1)
	requestPath = strings.Replace(requestPath, "{"+"path"+"}", url.PathEscape(gS.path), -1)
	response, err := client.ReadWithParameters(
		context.Background(),
		requestPath,
		queryParams,
		vault.WithMountPath(gS.mount),
	)
	if err != nil {
		return nil, fmt.Errorf("error getting secrets for path %s/%s: %w", gS.mount, gS.path, err)
	}
	return response, nil
}

func (a *EnvironmentExchanger) retrieveSecretValues() error {
	for i := range a.namespaceRequests {
		namespaceRequest := a.namespaceRequests[i]
		for _, secretRequests := range namespaceRequest.secretRequests {
			for secretRequest := range secretRequests {
				err := secretRequest.readSecret(namespaceRequest.vaultClient)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (a *EnvironmentExchanger) ExchangeEnvironment() ([]string, error) {
	env := make([]string, 0)
	for i := range a.currentEnv {
		if !strings.HasPrefix(a.currentEnv[i], VAULT_ENV_PREFIX) {
			env = append(env, a.currentEnv[i])
		}
	}
	for i := range a.namespaceRequests {
		namespaceRequest := a.namespaceRequests[i]
		for _, requests := range namespaceRequest.secretRequests {
			for request := range requests {
				var err error
				env, err = request.exportSecret(namespaceRequest.namespace, env)
				if err != nil {
					return env, err
				}
			}
		}
	}
	env = append(env, fmt.Sprintf("%s=%s", "VAULT_TOKEN", a.vaultToken))
	env = append(env, fmt.Sprintf("%s=%s", "VAULT_ADDR", a.vaultAddr))
	return env, nil
}

func GetVaultClient(vaultAddr string) (*vault.Client, error) {
	client, err := vault.New(
		vault.WithAddress(vaultAddr),
		vault.WithRequestTimeout(30*time.Second),
	)
	return client, err
}

func GetVaultTokenAwsAuth(vaultRoleName string, vaultAddr string, authMount string) (string, error) {
	client, err := GetVaultClient(vaultAddr)
	if err != nil {
		return "", err
	}
	loginData, err := GenerateLoginData("", os.Getenv("AWS_REGION"), vaultRoleName)
	if err != nil {
		return "", err
	}
	if loginData == nil {
		return "", fmt.Errorf("got nil response from GenerateLoginData")
	}

	path := fmt.Sprintf("auth/%s/login", authMount)
	secret, err := client.Write(context.Background(), path, loginData)
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", fmt.Errorf("empty response from credential provider")
	}
	return secret.Auth.ClientToken, nil
}

func GetVaultTokenKubeJwtAuth(vaultRoleName string, vaultAddr string, kubernetesJwtLocation string) (string, error) {
	client, err := GetVaultClient(vaultAddr)
	if err != nil {
		return "", err
	}

	b, err := os.ReadFile(kubernetesJwtLocation)
	if err != nil {
		return "", err
	}

	jwt := string(b)

	jwtLoginRequest := make(map[string]interface{})
	if vaultRoleName != "" {
		jwtLoginRequest["role"] = vaultRoleName
	} else {
		jwtLoginRequest["role"] = "default"
	}
	jwtLoginRequest["jwt"] = jwt

	path := fmt.Sprintf("auth/%s/login", "kubernetes")
	secret, err := client.Write(context.Background(), path, jwtLoginRequest)
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", fmt.Errorf("empty response from credential provider")
	}

	return secret.Auth.ClientToken, nil
}

func IsTokenValid(token string, vaultAddr string) bool {
	client, err := GetVaultClient(vaultAddr)
	if err != nil {
		return false
	}

	err = client.SetToken(token)
	if err != nil {
		return false
	}

	_, err = client.Auth.TokenLookUpSelf(context.Background())
	if err != nil {
		return false
	}

	return true
}

func GenerateLoginData(headerValue, configuredRegion string, vaultRoleName string) (map[string]interface{}, error) {
	loginData := make(map[string]interface{})

	// Use the credentials we've found to construct an STS session
	region, err := awsutil.GetRegion(configuredRegion)
	if err != nil {
		region = awsutil.DefaultRegion
	}
	stsSession, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config: aws.Config{
			CredentialsChainVerboseErrors: aws.Bool(true),
			Region:                        &region,
		},
	})
	if err != nil {
		return nil, err
	}

	var params *sts.GetCallerIdentityInput
	svc := sts.New(stsSession)
	stsRequest, response := svc.GetCallerIdentityRequest(params)

	// Inject the required auth header value, if supplied, and then sign the request including that header
	if headerValue != "" {
		stsRequest.HTTPRequest.Header.Add(iamServerIdHeader, headerValue)
	}
	err = stsRequest.Sign()
	if err != nil {
		return nil, err
	}

	// Now extract out the relevant parts of the request
	headersJson, err := json.Marshal(stsRequest.HTTPRequest.Header)
	if err != nil {
		return nil, err
	}
	requestBody, err := ioutil.ReadAll(stsRequest.HTTPRequest.Body)
	if err != nil {
		return nil, err
	}
	if len(stsRequest.HTTPRequest.Header["Authorization"]) == 0 {
		return nil, fmt.Errorf("no valid AWS credentials found in credential chain")
	}
	loginData["iam_http_request_method"] = stsRequest.HTTPRequest.Method
	loginData["iam_request_url"] = base64.StdEncoding.EncodeToString([]byte(stsRequest.HTTPRequest.URL.String()))
	loginData["iam_request_headers"] = base64.StdEncoding.EncodeToString(headersJson)
	loginData["iam_request_body"] = base64.StdEncoding.EncodeToString(requestBody)

	if len(vaultRoleName) == 0 {
		//try and get the environment role name
		err := stsRequest.Send()
		if err != nil {
			return nil, err
		}
		loginData["role"] = response.Account
	} else {
		loginData["role"] = vaultRoleName
	}
	return loginData, nil
}

func GetExistingVaultToken() string {
	envTokenValue := os.Getenv("VAULT_TOKEN")
	if len(envTokenValue) != 0 {
		return envTokenValue
	}
	homeDir, err := homedir.Dir()
	if err != nil {
		return ""
	}
	tokenPath := filepath.Join(homeDir, ".vault-token")
	f, err := os.Open(tokenPath)
	if os.IsNotExist(err) || err != nil {
		return ""
	}
	defer f.Close()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, f); err != nil {
		return ""
	}
	return strings.TrimSpace(buf.String())
}

func IsKubeServiceAccountJwtOnFile(kubernetesJwtLocation string) bool {
	_, err := os.Stat(kubernetesJwtLocation)
	return err == nil
}

func GetAwsCredentials(vaultToken, namespace, secretPath, accountID, vaultStsRoleName, awsAssumeRoleName, vaultAddr string) (AwsSecretOutput, error) {
	var awsSecretOutput AwsSecretOutput

	vaultClient, err := GetVaultClient(vaultAddr)
	if err != nil {
		return awsSecretOutput, err
	}
	err = vaultClient.SetToken(vaultToken)
	if err != nil {
		return awsSecretOutput, err
	}
	err = vaultClient.SetNamespace(namespace)
	if err != nil {
		return awsSecretOutput, err
	}

	awsSecret := &AwsSecret{
		secretPath:        secretPath,
		accountID:         accountID,
		vaultStsRoleName:  vaultStsRoleName,
		awsAssumeRoleName: awsAssumeRoleName,
	}
	secretRequest := &SecretRequest{
		namespace,
		awsSecret,
	}

	err = secretRequest.readSecret(vaultClient)
	if err != nil {
		return awsSecretOutput, err
	}

	awsSecretOutput = AwsSecretOutput{
		CredentialProcessOutputVersion,
		awsSecret.accessKeyId,
		awsSecret.secretAccessKey,
		awsSecret.sessionToken,
		awsSecret.expiration.Format(time.RFC3339),
	}

	return awsSecretOutput, nil
}
