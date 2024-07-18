#!/usr/bin/env bats

# Vault logs will be written to VAULT_OUTFILE.
# BATs test logs will be written to SETUP_TEARDOWN_OUTFILE.

export VAULT_ADDR='http://127.0.0.1:8200'
SETUP_TEARDOWN_OUTFILE=/tmp/bats-test.log
VAULT_OUTFILE=/tmp/vault.log
VAULT_TOKEN='root'
VAULT_STARTUP_TIMEOUT=15
VAULT_IMAGE=hashicorp/vault-enterprise

# Our vault license is required for namespaces.
[ ${VAULT_LICENSE:?} ]

# Our local vault for testing uses an access key and secret key for the swi lab user 'user-for-vault-sts-lab-tests'.
[ ${AWS_LAB_USER_ACCESS_KEY:?} ] 
[ ${AWS_LAB_USER_SECRET_KEY:?} ]

# assert_status evaluates if `status` is equal to $1. If they are not equal a
# log is written to the output file. This makes use of the BATs `status` and
# `output` globals.
#
# Parameters:
#   expect
# Globals:
#   status
#   output
assert_status() {
  local expect
  expect="$1"

  [ "${status}" -eq "${expect}" ] || \
    log_err "bad status: expect: ${expect}, got: ${status} \noutput:\n${output}"
}

log() {
  echo "INFO: $(date): [$BATS_TEST_NAME]: $@" >> $SETUP_TEARDOWN_OUTFILE
}

log_err() {
  echo -e "ERROR: $(date): [$BATS_TEST_NAME]: $@" >> $SETUP_TEARDOWN_OUTFILE
  exit 1
}

setup_file() {
    # clear log file
    echo "" > $SETUP_TEARDOWN_OUTFILE

    #cd ../
    #docker build -f test/Dockerfile . -t docker-shim
    #cd test

    VAULT_TOKEN='root'

    log "BEGIN SETUP"

    if [[ -n ${VAULT_IMAGE} ]]; then
      log "docker using VAULT_IMAGE: $VAULT_IMAGE"
      docker pull ${VAULT_IMAGE?}

      docker run \
        --name=vault \
        --hostname=vault \
        -p 8200:8200 \
        -e VAULT_LICENSE="${VAULT_LICENSE?}" \
        -e VAULT_DEV_ROOT_TOKEN_ID="root" \
        -e VAULT_ADDR="http://localhost:8200" \
        -e VAULT_DEV_LISTEN_ADDRESS="0.0.0.0:8200" \
        --privileged \
        --detach ${VAULT_IMAGE?}
    else
      log "using local vault binary"
      ./vault server -dev -dev-root-token-id=root \
        -log-level=trace > $VAULT_OUTFILE 2>&1 &
    fi

    log "waiting for vault..."
    i=0
    while ! vault status >/dev/null 2>&1; do
      sleep 1
      ((i=i+1))
      [ $i -gt $VAULT_STARTUP_TIMEOUT ] && log_err "timed out waiting for vault to start"
    done

    vault login ${VAULT_TOKEN?}

    run vault status
    assert_status 0
    log "vault started successfully"

    log "Starting JWT generation"
    openssl genrsa -out private.pem 512
    openssl rsa -pubout -in private.pem > public.pem

    PEM=$(cat private.pem)
    export PUBPEM=$(cat public.pem)

    NOW=$( date +%s )
    IAT="${NOW}"
    # expire 10 minutes in the future.
    EXP=$((${NOW} + 600))
    HEADER_RAW='{"alg":"RS256"}'
    HEADER=$( echo -n "${HEADER_RAW}" | openssl base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n' )
    PAYLOAD_RAW='{"iat": 1687564440,"exp":'"${EXP}"', "aud":["https://kubernetes.default.svc"], "iss":"https://kubernetes.default.svc", "sub": "system:serviceaccount:network-test:default", "kubernetes.io": {"namespace": "network-test", "serviceaccount" : { "uid": "bce54548-19b8-4644-ac25-05b8e8b4bc4e"}}}'
    PAYLOAD=$( echo -n "${PAYLOAD_RAW}" | openssl base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n' )
    HEADER_PAYLOAD="${HEADER}"."${PAYLOAD}"
    SIGNATURE=$( openssl dgst -sha256 -sign <(echo -n "${PEM}") <(echo -n "${HEADER_PAYLOAD}") | openssl base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n' )
    export JWT="${HEADER_PAYLOAD}"."${SIGNATURE}"
    echo $JWT > token
    log "JWT generated"

    log "END SETUP"
}

#teardown_file runs once after all tests complete
teardown_file() {
    log "BEGIN TEARDOWN"

    log "Cleaning up vault process"
    if [[ -n ${VAULT_IMAGE} ]]; then
      log "removing vault docker container"
      docker rm vault --force
    else
      log "killing vault process"
      pkill vault
    fi

    log "Cleaning up JWT and keys"
    rm private.pem
    rm public.pem
    rm token

    rm aws-config-*

    log "END SETUP"
    log "END TEARDOWN"
}

@test "Read license" {
    run vault read -format=json sys/license/status
    assert_status 0
}

@test "Create workloads namespace" {
    run vault namespace create workloads
    assert_status 0
}

@test "Create workloads/foo namespace" {
    run vault namespace create -ns=workloads foo
    assert_status 0
}

@test "Create workloads/foo/bar namespace" {
    run vault namespace create -ns=workloads/foo bar
    assert_status 0
}

@test "Create workloads/foo/baz namespace" {
    run vault namespace create -ns=workloads/foo baz
    assert_status 0
}

@test "Enable secret engine for foo/bar namespace" {
    run vault secrets enable -version=2 -path=secret -ns=workloads/foo/bar kv
    assert_status 0
}

@test "Enable secret engine for foo/baz namespace" {
    run vault secrets enable -version=2 -path=secret -ns=workloads/foo/baz kv
    assert_status 0
}

@test "Enable jwt mount with path of kubernetes" {
    run vault auth enable --path=kubernetes jwt
    assert_status 0
}

@test "Configure mount to use PUBKEY as validation key" {
    run vault write auth/kubernetes/config \
      jwt_validation_pubkeys="${PUBPEM}"

    assert_status 0
}

@test "Configure mount to use batch token type" {
    run vault auth tune -token-type=batch kubernetes/

    assert_status 0
}

@test "Configure kubernetes role" {
    run vault write auth/kubernetes/role/default \
      role_type="jwt" \
      bound_audiences="https://kubernetes.default.svc" \
      policies="default" \
      user_claim_json_pointer=true \
      user_claim="/kubernetes.io/serviceaccount/uid" \
      ttl="1h"

      assert_status 0
}

@test "Write test secret to bar ns" {
    run vault kv put -mount=workloads/foo/bar/secret test_secret BAR=BAZ FOO=JAZ
    assert_status 0
}

@test "Write second test secret to bar ns" {
    run vault kv put -mount=workloads/foo/bar/secret second_secret APPLE=BANANA
    assert_status 0
}

@test "Write test secret to baz ns" {
    run vault kv put -mount=workloads/foo/baz/secret baz_secret FOO=BAR
    assert_status 0
}

@test "Create read secret policy bar namespace" {
    run vault policy write --namespace=workloads/foo/bar test-policy -<<EOF
path "secret/*" {
  capabilities = [ "read" ]
}

EOF
    assert_status 0
}

@test "Create read secret policy for baz namespace" {
    run vault policy write --namespace=workloads/foo/baz test-policy -<<EOF
path "secret/*" {
  capabilities = [ "read" ]
}

EOF
    assert_status 0
}

@test "Create entity" {
    run vault write -format=json identity/entity name="test-entity"
    assert_status 0
}

@test "Create alias" {
  alias_id=$(vault auth list -format=json | jq -r '.["kubernetes/"].accessor')
  entity_id=$(vault read identity/entity/name/test-entity -format=json | jq -r .data.id)
  run vault write identity/entity-alias name="bce54548-19b8-4644-ac25-05b8e8b4bc4e" \
     canonical_id=${entity_id} \
     mount_accessor=${alias_id}

  assert_status 0
}

@test "Create aws secret policy" {
    run vault policy write aws-policy -<<EOF
path "aws_deploy_role/sts/970349098957_deploy" {
  capabilities = ["update"]
}

EOF
    assert_status 0
}

@test "Create aws group in root namespace" {
    entity_id=$(vault read identity/entity/name/test-entity -format=json | jq -r .data.id)
    run vault write identity/group name="aws" policies="aws-policy" member_entity_ids=${entity_id}
    assert_status 0
}

@test "Create reader group in foo namespace" {
    entity_id=$(vault read identity/entity/name/test-entity -format=json | jq -r .data.id)
    run vault write --namespace=workloads/foo/bar identity/group name="kubernetes-readers" policies="test-policy" member_entity_ids=${entity_id}
    assert_status 0
}

@test "Create reader group in baz namespace" {
    entity_id=$(vault read identity/entity/name/test-entity -format=json | jq -r .data.id)
    run vault write --namespace=workloads/foo/baz identity/group name="kubernetes-readers" policies="test-policy" member_entity_ids=${entity_id}
    assert_status 0
}

@test "Enable aws secrets" {
    run vault secrets enable --path=aws_deploy_role aws
    assert_status 0
}

@test "Configure aws secret creds that our local vault uses" {
    run vault write aws_deploy_role/config/root \
        access_key=${AWS_LAB_USER_ACCESS_KEY} \
        secret_key=${AWS_LAB_USER_SECRET_KEY} \
        region=us-east-2

    assert_status 0
}

@test "Create aws secret role" {
    run vault write aws_deploy_role/roles/970349098957_deploy \
        role_arns=arn:aws:iam::970349098957:role/lab-vault-sts-role-for-testing-purposes \
        credential_type=assumed_role

    assert_status 0
}

@test "Logout of root" {
    unset VAULT_TOKEN
    run rm ~/.vault-token
    assert_status 0
}

@test "Baseline test to ensure tests are setup correctly before testing docker-shim" {
    run vault write auth/kubernetes/login \
      jwt=$JWT \
      role="default"

    assert_status 0
}

@test "Run command with no vault envs" {
    run ./docker-shim run-cmd -- /usr/bin/env
    assert_status 0
    [[ "$output" == *"AWS"* ]] # Assert that the env command was run that was passed to run-cmd
}

@test "Read secret same namespace" {
    export VAULT__BAR=workloads/foo/bar::secret:test_secret:BAR
    export VAULT__FOO=workloads/foo/bar::secret:test_secret:FOO
    export VAULT__DIFFSECRET=workloads/foo/bar::secret:second_secret:APPLE
    run ./docker-shim --kubernetes-jwt-location=token run-cmd -- /usr/bin/env
    assert_status 0
    [[ "$output" == *"BAR=BAZ"* ]]
    [[ "$output" == *"FOO=JAZ"* ]]
    [[ "$output" == *"DIFFSECRET=BANANA"* ]]
}

@test "Read missing secret" {
    export VAULT__BAR=workloads/foo/bar::secret:test_secret:BAZ
    run ./docker-shim --kubernetes-jwt-location=token run-cmd -- /usr/bin/env
    assert_status 1
    [[ "$output" == *"Secret key BAZ not found"* ]]
}

@test "Read secret two namespaces" {
    unset BAR
    unset FOO
    export VAULT__BAR=workloads/foo/bar::secret:test_secret:BAR
    export VAULT__FOO=workloads/foo/baz::secret:baz_secret:FOO
    run ./docker-shim --kubernetes-jwt-location=token run-cmd -- /usr/bin/env
    assert_status 0
    [[ "$output" == *"BAR=BAZ"* ]]
    [[ "$output" == *"FOO=BAR"* ]]
}

@test "Output AWS credentials" {
    run ./docker-shim --kubernetes-jwt-location=token aws-credentials --namespace="" --secret-path="aws_deploy_role" --account-id="970349098957" --vault-sts-role-name="970349098957_deploy" --aws-assume-role-name="lab-vault-sts-assume-role-for-testing"
    assert_status 0
    echo $output | jq -e .Version
    assert_status 0
    echo $output | jq -e .AccessKeyId
    assert_status 0
    echo $output | jq -e .SecretAccessKey
    assert_status 0
    echo $output | jq -e .Expiration
    assert_status 0
}

@test "Write one AWS profile" {
    export VAULT__FOO=AWS:/aws_deploy_role:970349098957:970349098957_deploy:lab-vault-sts-assume-role-for-testing
    run ./docker-shim --kubernetes-jwt-location=token run-cmd --aws-config-file=aws-config-one-profile -- /usr/bin/env
    assert_status 0
    EXPECTED_FILE_OUTPUT='
[profile FOO]
credential_process = docker-shim aws-credentials --namespace="" --secret-path="aws_deploy_role" --account-id="970349098957" --vault-sts-role-name="970349098957_deploy" --aws-assume-role-name="lab-vault-sts-assume-role-for-testing" --vault-role=""'
    cat aws-config-one-profile
    [ "$(< aws-config-one-profile)" == "$EXPECTED_FILE_OUTPUT" ]
    [[ "$output" == *"AWS_CONFIG_FILE=aws-config-one-profile"* ]]
}
@test "Write two AWS profiles" {
    export VAULT__FOO=AWS:/aws_deploy_role:970349098957:970349098957_deploy:lab-vault-sts-assume-role-for-testing
    export VAULT__BAR=AWS:/aws_deploy_role:970349098957:970349098957_deploy:lab-vault-sts-assume-role-for-testing
    run ./docker-shim --kubernetes-jwt-location=token run-cmd --aws-config-file=aws-config-two-profiles -- /usr/bin/env
    assert_status 0
    EXPECTED_FILE_OUTPUT='
[profile BAR]
credential_process = docker-shim aws-credentials --namespace="" --secret-path="aws_deploy_role" --account-id="970349098957" --vault-sts-role-name="970349098957_deploy" --aws-assume-role-name="lab-vault-sts-assume-role-for-testing" --vault-role=""

[profile FOO]
credential_process = docker-shim aws-credentials --namespace="" --secret-path="aws_deploy_role" --account-id="970349098957" --vault-sts-role-name="970349098957_deploy" --aws-assume-role-name="lab-vault-sts-assume-role-for-testing" --vault-role=""'
    cat aws-config-two-profiles
    [ "$(< aws-config-two-profiles)" == "$EXPECTED_FILE_OUTPUT" ]
    [[ "$output" == *"AWS_CONFIG_FILE=aws-config-two-profiles"* ]]
}
@test "Write one AWS profile with auth role name" {
    export VAULT__FOO=AWS:/aws_deploy_role:970349098957:970349098957_deploy:lab-vault-sts-assume-role-for-testing:some-separate-role
    run ./docker-shim --kubernetes-jwt-location=token run-cmd --aws-config-file=aws-config-one-profile-role-override -- /usr/bin/env
    assert_status 0
    EXPECTED_FILE_OUTPUT='
[profile FOO]
credential_process = docker-shim aws-credentials --namespace="" --secret-path="aws_deploy_role" --account-id="970349098957" --vault-sts-role-name="970349098957_deploy" --aws-assume-role-name="lab-vault-sts-assume-role-for-testing" --vault-role="some-separate-role"'
    cat aws-config-one-profile-role-override
    [ "$(< aws-config-one-profile-role-override)" == "$EXPECTED_FILE_OUTPUT" ]
    [[ "$output" == *"AWS_CONFIG_FILE=aws-config-one-profile-role-override"* ]]
}
@test "Write one AWS profile with no assume role colon" {
    export VAULT__FOO=AWS:/aws_deploy_role:970349098957:970349098957_deploy:
    run ./docker-shim --kubernetes-jwt-location=token run-cmd --aws-config-file=aws-config-one-profile-no-assume-role-colon -- /usr/bin/env
    assert_status 0
    EXPECTED_FILE_OUTPUT='
[profile FOO]
credential_process = docker-shim aws-credentials --namespace="" --secret-path="aws_deploy_role" --account-id="970349098957" --vault-sts-role-name="970349098957_deploy" --aws-assume-role-name="" --vault-role=""'
    cat aws-config-one-profile-no-assume-role-colon
    [ "$(< aws-config-one-profile-no-assume-role-colon)" == "$EXPECTED_FILE_OUTPUT" ]
    [[ "$output" == *"AWS_CONFIG_FILE=aws-config-one-profile-no-assume-role-colon"* ]]
}
@test "Write one AWS profile with no assume role" {
    export VAULT__FOO=AWS:/aws_deploy_role:970349098957:970349098957_deploy
    run ./docker-shim --kubernetes-jwt-location=token run-cmd --aws-config-file=aws-config-one-profile-no-assume-role -- /usr/bin/env
    assert_status 0
    EXPECTED_FILE_OUTPUT='
[profile FOO]
credential_process = docker-shim aws-credentials --namespace="" --secret-path="aws_deploy_role" --account-id="970349098957" --vault-sts-role-name="970349098957_deploy" --aws-assume-role-name="" --vault-role=""'
    cat aws-config-one-profile-no-assume-role
    [ "$(< aws-config-one-profile-no-assume-role)" == "$EXPECTED_FILE_OUTPUT" ]
    [[ "$output" == *"AWS_CONFIG_FILE=aws-config-one-profile-no-assume-role"* ]]
}
@test "Write one AWS profile with no assume role and auth role name" {
    export VAULT__FOO=AWS:/aws_deploy_role:970349098957:970349098957_deploy::some-separate-role
    run ./docker-shim --kubernetes-jwt-location=token run-cmd --aws-config-file=aws-config-one-profile-no-assume-role-override -- /usr/bin/env
    assert_status 0
    EXPECTED_FILE_OUTPUT='
[profile FOO]
credential_process = docker-shim aws-credentials --namespace="" --secret-path="aws_deploy_role" --account-id="970349098957" --vault-sts-role-name="970349098957_deploy" --aws-assume-role-name="" --vault-role="some-separate-role"'
    cat aws-config-one-profile-no-assume-role-override
    [ "$(< aws-config-one-profile-no-assume-role-override)" == "$EXPECTED_FILE_OUTPUT" ]
    [[ "$output" == *"AWS_CONFIG_FILE=aws-config-one-profile-no-assume-role-override"* ]]
}
