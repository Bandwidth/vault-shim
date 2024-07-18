# vault-shim
Inject secrets from HashiCorp Vault into the environment

- [Usage](#usage)
    - [Installation](#installation)
    - [Inputs and Outputs](#inputs-and-outputs)
        - [Generic Secrets](#generic-secrets)
- [Examples](#examples)
    - [Simple Example](#simple-example)
    - [Application Container Example](#application-container-example)
    - [Shared AWS Account Example](#shared-aws-account-example)
    - [AWS Credentials From Openshift](#aws-credentials-from-openshift)
- [FAQ](#faq)
    - [Where can I download vault-shim?](#where-can-i-download-vault-shim)
    - [How do my workloads get access to vault?](#how-do-my-workloads-get-access-to-vault)
    - [How does vault-shim auth with vault?](#how-does-vault-shim-auth-with-vault)

## Usage
Reads secrets from vault then runs a specified command with the commands environment populated with the retrieved secrets.
`<command>` must be a fully qualified or relative path to some executable. No shell is assumed.
```
vault-shim run-cmd -- <command>
```

### Installation
To install vault-shim, download the installer from GitHub and execute it.
```shell
curl -O https://raw.githubusercontent.com/Bandwidth/vault-shim/{$VERSION}/vault-shim-installer.sh
chmod +x vault-shim-installer.sh
./vault-shim-installer.sh "$VERSION" 

vault-shim --help
```

### Inputs and Outputs
What secrets are read from vault and passed to the run command are determined by what environmental variables are set that contain the `VAULT__` prefix.

#### Generic Secrets
Environmental variable input format for reading generic secrets.
```
export VAULT__<SECRET_NAME>=<namespace>::<mount>:<path>:<key>[@<version][::<export_name>]
```
Environmental variable output when a generic secret environmental variable input is set.
```
<SECRET_NAME>=<VALUE_IN_VAULT>
```

#### AWS Credentials
Reading AWS credentials from vault using vault-shim is similar to reading generic secrets but has a few caveats. Because AWS credentials issued from vault are short lived they can not just be exported to the environment of the running process.
Instead for every AWS credential required an aws profile will be created by vault-shim with the [credential_process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html) setting set in an AWS configuration file. vault-shim will set an appropriate value for `credential_process`.
This will ensure long running processes will have access to active AWS credentials.
The various AWS SDKs will work as is with this process as long as the correct AWS profile is specified. Multiple AWS credentials can be generated.

Environmental variable input format for reading AWS credentials.
```
export VAULT__<DESIRED_AWS_PROFILE_NAME>=AWS:/aws_deploy_role:<account-id>:<vault-sts-role>:<aws-assume-role>
```

The following profile would be created. The profile will be appended to the AWS configuration file or a new configuration file will be created if one does not exist.
```
[profile <DESIRED_AWS_PROFILE_NAME>]
credential_process = vault-shim aws-credentials --namespace="" --secret-path="<secret-path>" --account-id="<account-id>" --vault-sts-role-name="<vault-sts-role>" --aws-assume-role-name="<aws-assume-role>"
```

The only environmental variable exported is the aws config file location. This tells the AWS SDK where the aws config file is located. This will default to an auto generated location but can be specified with the `aws-config-file` flag.
```
AWS_CONFIG_FILE=/tmp/<random_16_char_string>_aws_config
```

## Examples
### Simple Example
This small example demonstrates that vault-shim reads the environment for any variables that are prefixed with `VAULT__` and uses their values to read the secret in vault then pass them to the run command specified.
```
export VAULT__SECRETONE=workloads/foo/bar::secret:secret_one:FIRST_KEY
export VAULT__SECRETTWO=workloads/foo/bar::secret:secret_two:SECOND_KEY
./vault-shim run-cmd -- /usr/bin/env | grep SECRET
SECRETONE=whateversecretvaluewassetforsecretoneFIRST_KEY # the run-cmd here was /usr/bin/env so all of the env is printed and we grep for just our secrets so they are the only output in the example.
SECRETTWO=whateversecretvaluewassetforsecrettwoSECOND_KEY
```
### Application Container Example
The following shows building a container that uses vault-shim to run and pass secrets to an application. Notice that the shim requires
sensitive Artifactory credentials. These should not get passed to the final image. The multi-stage build is used to avoid this.

vaultfile
```vaultfile
FROM python:3.12 as vault-shim

RUN curl -O https://raw.githubusercontent.com/Bandwidth/vault-shim/{$VERSION}/vault-shim-installer.sh
RUN chmod +x "vault-shim-installer.sh"
RUN ./vault-shim-installer.sh "$VERSION"

########## Second Stage ##########
FROM python:3.12
COPY example.py .
COPY --from=vault-shim /usr/local/bin/vault-shim /usr/local/bin/vault-shim
CMD ["vault-shim", "run-cmd", "--", "/usr/local/bin/python", "example.py"]
```
example.py
```python
import os
print(os.environ['BAR'])
```

Running our container
```bash
vault run -it -e VAULT__BAR=workloads/someenv/somedomain::secret:test_secret:FOO example
```
Setting the environmental variable `VAULT__BAR` when running the container sets the environmental variable `BAR` with the value of what ever is stored in vault at `workloads/someenv/somedomain::secret:test_secret:FOO` for our app.

Note: This is just an example using `vault run` to highlight that the `VAULT__BAR` environmental variable needs to be passed to the container but the concepts would still work with ECS and Kubernetes.

### Shared AWS Account Example
In Glorg AWS accounts, we tend to grant Vault access to all roles in the account. This is not the case in shared accounts outside the Glorg.
If `vault-shim` detects that it is operating in an AWS account, it defaults to the Glorg account behavior.  
In practice that means that the `--vault-role` flag defaults to the account id of the AWS account it is running in.
In shared accounts this role does not exist and must be set to a value configured in [vault-policies](https://github.com/Bandwidth/vault-policies/blob/main/vault-namespaces/auth_aws_iam.tf#L8) during vault namespace creation.  
For example, if we have pre-created a role `103854071333_elephant` that is allowed to be used by any AWS IAM role matching `arn:aws:iam::103854071333:role/elephant-*`, you would modify the vault command to add `--vault-role 103854071333_elephant` before the `--`.
```vaultfile
FROM python:3.12 as vault-shim

RUN curl -O https://raw.githubusercontent.com/Bandwidth/vault-shim/{$VERSION}/vault-shim-installer.sh
RUN chmod +x "vault-shim-installer.sh"
RUN ./vault-shim-installer.sh "$VERSION"

########## Second Stage ##########
FROM python:3.12
COPY example.py .
COPY --from=vault-shim /usr/local/bin/vault-shim /usr/local/bin/vault-shim
ENTRYPOINT ["vault-shim", "run-cmd", "--vault-role", "103854071333_elephant", "--", "/usr/local/bin/python", "./example.py"]
```

For clarity this is an example for the Glorg account `242521268600` with the `--vault-role` flag.
```vaultfile
FROM python:3.12 as vault-shim

RUN curl -O https://raw.githubusercontent.com/Bandwidth/vault-shim/{$VERSION}/vault-shim-installer.sh
RUN chmod +x "vault-shim-installer.sh"
RUN ./vault-shim-installer.sh "$VERSION"

########## Second Stage ##########
FROM python:3.12
COPY example.py .
COPY --from=vault-shim /usr/local/bin/vault-shim /usr/local/bin/vault-shim
ENTRYPOINT ["vault-shim", "run-cmd", "--vault-role", "242521268600", "--", "/usr/local/bin/python", "./example.py"]
```

It is advised to drive this value with an env var so multiple containers do not need to be created to support multiple AWS environments
```vaultfile
FROM python:3.12 as vault-shim

ARG VAULT_ROLE

RUN curl -O https://raw.githubusercontent.com/Bandwidth/vault-shim/{$VERSION}/vault-shim-installer.sh
RUN chmod +x "vault-shim-installer.sh"
RUN ./vault-shim-installer.sh "$VERSION"

########## Second Stage ##########
FROM python:3.12

ARG VAULT_ROLE

COPY example.py .
COPY --from=vault-shim /usr/local/bin/vault-shim /usr/local/bin/vault-shim
ENTRYPOINT ["sh", "-c", "vault-shim run-cmd --vault-role $VAULT_ROLE -- /usr/local/bin/python ./example.py"]
```
or (assuming the entrypoint is some shell)
```vaultfile
FROM python:3.12 as vault-shim

ARG VAULT_ROLE

RUN curl -O https://raw.githubusercontent.com/Bandwidth/vault-shim/{$VERSION}/vault-shim-installer.sh
RUN chmod +x "vault-shim-installer.sh"
RUN ./vault-shim-installer.sh "$VERSION"

########## Second Stage ##########
FROM python:3.12

ARG VAULT_ROLE

COPY example.py .
COPY --from=vault-shim /usr/local/bin/vault-shim /usr/local/bin/vault-shim
CMD exec vault-shim run-cmd --vault-role "$VAULT_ROLE" -- /usr/local/bin/python ./example.py
```

## FAQ
### Where can I download vault-shim?
It's in artifactory located [here](https://bandwidth.jfrog.io/ui/repos/tree/General/generic-local-prod/vault-shim). You will want to download the installer and run the script during the build process.
### Why do I need to download an installer?
The installer downloads the right version of vault-shim for the platform you are running on.
### How do my workloads get access to vault?
Check out our vault user guide [here](https://bandwidth-jira.atlassian.net/wiki/spaces/SWI/pages/4365156842/Vault+-+User+Guide)
### How does vault-shim auth with vault?
It will try to auth to vault in the following order:
1) Checks for vault token on disk at $HOME/.vault-token
2) Checks for kubernetes jwt on disk
3) Uses AWS IAM.
