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
curl -H 'Accept: application/vnd.github.v3.raw' -L -o vault-shim-installer.sh https://raw.githubusercontent.com/Bandwidth/vault-shim/<VERSION>/vault-shim-installer.sh
chmod +x vault-shim-installer.sh
./vault-shim-installer.sh "<VERSION>"

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
The following shows building a container that uses vault-shim to run and pass secrets to an application. These should not get passed to the final image. The multi-stage build is used to avoid this.

Dockerfile
```dockerfile
FROM python:3.12 as vault-shim

RUN curl -H 'Accept: application/vnd.github.v3.raw' -L -o vault-shim-installer.sh https://raw.githubusercontent.com/Bandwidth/vault-shim/<VERSION>/vault-shim-installer.sh
RUN chmod +x "vault-shim-installer.sh" 
RUN ./vault-shim-installer.sh "<VERSION>"

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
docker run -it -e VAULT__BAR=workloads/someenv/somedomain::secret:test_secret:FOO example
```
Setting the environmental variable `VAULT__BAR` when running the container sets the environmental variable `BAR` with the value of what ever is stored in vault at `workloads/someenv/somedomain::secret:test_secret:FOO` for our app.

Note: This is just an example using `docker run` to highlight that the `VAULT__BAR` environmental variable needs to be passed to the container but the concepts would still work with ECS and Kubernetes.

### AWS Credentials From Openshift
The following shows an example running a container that receives AWS credentials in an openshift cluster.

This assumes our example.jar uses a standard AWS SDK for interacting with AWS.

Dockerfile
```dockerfile
FROM python:3.12 as vault-shim

RUN curl -H 'Accept: application/vnd.github.v3.raw' -L -o vault-shim-installer.sh https://raw.githubusercontent.com/Bandwidth/vault-shim/<VERSION>/vault-shim-installer.sh
RUN chmod +x "vault-shim-installer.sh"
RUN ./vault-shim-installer.sh "<VERSION>"

########## Second Stage ##########
FROM example.jfrog.io/eclipse-temurin:19.0.2_7-jre

COPY --from=vault-shim /usr/local/bin/vault-shim /usr/local/bin/vault-shim

COPY example.jar .

ENTRYPOINT ["vault-shim", "run-cmd", "--", "/opt/java/openjdk/bin/java", "-jar", "example.jar"]
```

Atlas Application Deployment (The important part for this example is setting the AWS_PROFILE and VAULT__EXAMPLE env vars).
```yaml
apiVersion: proj.io/v1alpha1
kind: Application
metadata:
  name: example
spec:
  project: atlas
  source:
    chart: 'component'
    targetRevision: '0.5.*'
    helm:
      values: |
        image:
          uri: example.jfrog.io/example:1.0.0

          extraEnvVars:
            - name: AWS_PROFILE
              value: EXAMPLE
            - name: VAULT__EXAMPLE
              value: AWS:/aws_deploy_role:123456789101:123456789101_deploy:example-aws-role-to-assume
```
## FAQ
### Where can I download vault-shim?
You will want to download the installer from GitHub and run the script during the build process.
### Why do I need to download an installer?
The installer downloads the right version of vault-shim for the platform you are running on.
### How does vault-shim auth with vault?
It will try to auth to vault in the following order:
1) Checks for vault token on disk at $HOME/.vault-token
2) Checks for kubernetes jwt on disk
3) Uses AWS IAM.