# Vault install

## Install vault

Ubunut / WSL

```bash
sudo apt install vault
```

Generic linux

```bash
wget https://releases.hashicorp.com/vault/1.17.5/vault_1.17.5_linux_amd64.zip \
unzip vault_1.17.5_linux_amd64.zip \
./vault status
```

Windows

- Download the file from `https://releases.hashicorp.com/vault/1.17.5/vault_1.17.5_windows_amd64.zip`
- Unzip the file
- Run it using the terminal

## Configure vault

Linux

```bash
nano /etc/vault.d/vault.hcl
```

Windows

- Create a file named vault.hcl

Add the snippet bellow

```bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# Full configuration options can be found at https://developer.hashicorp.com/vault/docs/configuration

ui = true

#mlock = true
#disable_mlock = true

# use different storage depending oh your use case https://developer.hashicorp.com/vault/docs/configuration/storage/raft
storage "file" {
  path = "~/vault/data"
}

#storage "consul" {
#  address = "127.0.0.1:8500"
#  path    = "vault"
#}

HTTP listener
listener "tcp" {
 address = "127.0.0.1:8200"
 tls_disable = 1
}

log_level = "info"

# use this with certbot keys for https
# HTTPS listener
# listener "tcp" {
#   tls_disable   = 1
#   address       = "0.0.0.0:8200"
#   tls_cert_file = "/opt/vault/tls/tls.crt"
#   tls_key_file  = "/opt/vault/tls/tls.key"
# }

# Enterprise license_path
# This will be required for enterprise as of v1.8
#license_path = "/etc/vault.d/vault.hclic"

# Example AWS KMS auto unseal
#seal "awskms" {
#  region = "us-east-1"
#  kms_key_id = "REPLACE-ME"
#}

# Example HSM auto unseal
#seal "pkcs11" {
#  lib            = "/usr/vault/lib/libCryptoki2_64.so"
#  slot           = "0"
#  pin            = "AAAA-BBBB-CCCC-DDDD"
#  key_label      = "vault-hsm-key"
#  hmac_key_label = "vault-hsm-hmac-key"
#}
```

## Optional create a service for valt on linux

```bash
sudo nano /etc/systemd/system/vault.service
```

Paste the bellow in the file name vault.service

```bash
[Unit]
Description=Vault
Documentation=https://www.vault.io/

[Service]
ExecStart=/usr/bin/vault server -config=/etc/vault/config.hcl
ExecReload=/bin/kill -HUP $MAINPID
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Update enable and start the vault service more info [here](https://www.digitalocean.com/community/tutorials/how-to-use-systemctl-to-manage-systemd-services-and-units)

```bash
sudo systemctl daemon-reload
sudo systemctl enable vault
sudo systemctl start vault
sudo systemctl list-units --type=service
sudo systemctl status vault
```

## Start vault server

Linux

```bash
sudo vault server -config /etc/vault.d/vault.hcl
```

Windows

```bash
./vault.exe server -config ./vault.hcl
```

## Initialize vault

```bash
vault operator init

# output
Unseal Key 1: o0rXIQNGZzV3Ka6mT1+mCV2iGVdSdYl/lT9/Yodsb7wo
Unseal Key 2: 0QQ9BVMv3EnVNeJ7a4+dJyA08/rReodiVksMYGC1fZjr
Unseal Key 3: M3iDwDiSPFsWvW42VjIJfubZ9XAGbW2JzQuuYUJWI3fW
Unseal Key 4: IxAgmNr9gUOX5T6PmI9vIjd3h34HozDKZYf9O/mOKoOp
Unseal Key 5: +Mx2Euzt6Go+KXjv1Qc1DhSoob203z+hOuVuycJWsEkn

Initial Root Token: hvs.htoFrwoCC6gBVBnD10zwTsQC

```

**Warning**
Save the keys we will need them later!

## Unlock vault

### Unlock vault using the ui

- Navigate to `http://127.0.0.1:8200`
- In the ui enter 3 different keys from the key list we got before

### Login through the ui

- Navigate to `http://127.0.0.1:8200`
- Use the token login as we have nmos set up another method and paste the token we saved before

```bash
Initial Root Token: hvs.htoFrwoCC6gBVBnD10zwTsQC
```

### Unlock Vault using the cli

```bash
# 3 times as it requires 3 keys
vault operator unseal # x3
vault login
```

You should see the Sealed property to be false

```bash
Unseal Key (will be hidden):
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false  <-------- The seal has been lifted
Total Shares    5
Threshold       3
Version         1.17.5
Build Date      2024-08-30T15:54:57Z
Storage Type    file
Cluster Name    vault-cluster-aafffa25
Cluster ID      4e257c8a-a10b-72de-79c0-b750322bc271
HA Enabled      false
```

## Enable Secret Engines

-In the menu click **Secret Engines** and click enable new engine on the top right corner
-Add a generic KV here we will have to choose the **Maximum number of versions** and more options
-For now we will use the basic and click **Enable Engine**

Or using the cli

```bash
vault secrets enable -path=databases kv
vault secrets disable kv
```

## Adding secrets to the engine

- Click on the **KV** engine and then click on the **Create secret**
- Here we can choose the ype of secret **JSON** or **String** which is the default
- We add a **path** to it and one or multiple **key/value** pairs

  - Path: initial
  - Secret data:
    - key: cant
    - value: touch

Or using the cli

```bash
vault kv put databases/prod postgres=my_super_secret_postgres_master_key
vault kv get databases/prod
```

### Exercise 1

- Enable a new secrets engine of type key/value named `databases`
- Create a secret named postgres:value and place it under staging (databases/staging)
- Get the secret
- Update the secret to postgres:real_value
- Delete the secret
- Disable the engine

# Authentication

## Tokens

Create a new login token

```bash
vault token create # -role=role_name -policy=policy_name
```

## Add Username password access to your vault

**Warning**
Users can only be added from the cli or the REST API

- From the menu click on **Access**
- Then cloose **Authentication methods**
- Click on the **Username & Password**
- Leave the path as is and clock **Enable method**

Cli commands

```bash
vault auth enable userpass
vault auth list
vault write auth/userpass/users/new_user password=new_pass
vault login -method=userpass username=new_user password=new_password
```

## Optional add MFA

- From the menu click on **Access**
- Then cloose **Multi-factor Authentication**
- Click on the **Configure MFA**
- Click **TOTP**
- Click **Next**
- Fill up the configuration and click continue

|                  |                       |
| ---------------- | --------------------- |
| Issuer           | company name          |
| Key size         | 33                    |
| Qr size          | 100                   |
| Algorithm        | SHA256                |
| Digits           | 8                     |
| Skew             | 0                     |
| Enforcement      | Create new            |
| Enforcement name | name your enfoecement |
| Targets          | userpass              |

- Click **Add**
- Click **Continue**

## Optional Github tokens

```bash
vault auth enable github
vault write auth/github/config organization=org_name
vault auth list
vault write auth/github/map/teams/development vaule=dev-policy # Setup default policy for users loggin in
vault write auth/github/map/users/myuser value=prod-policy # update user policy
```

- Navigate to github
- Find the user ex github.com/alpap
- Click on **Settings > Develope Settings > Personal access token**
- Select scopes
- Generate token
- You can login with that token now

## Other authentication methods

- AWS
- Azure
- Google
- Github
- Ali cloud
- Ldap
- Okta
- Jwt
- TLS
- Userpass
- IODC
- AppRole
- Radius
- K8s

You can also create a github application linked to your organization to use github OAth

# Authorization

## Create a Policy

- From the menu click on **Policies**
- Click on **ACL Policies**
- Click on **Create ACL Policy**
- Name the policy **Initial**
- Add the content bellow to the text field
- Click **Save**

Or using the cli

```bash
tee policy.hcl <<EOF
  # Read permission on the k/v secrets
  path "/secret/*" {
      capabilities = ["read", "list"]
  }
EOF
vault policy write testpolicy policy.hcl
vault token create -policy=testpolicy
```

### Open source Vault policies

```bash
# Grant 'create', 'read' , 'update', and ‘list’ permission
# to paths prefixed by 'secret/*'
path "initial/*" {
  capabilities = [ "create", "read", "update", "list" ]
}

# Even though we allowed secret/*, this line explicitly denies
# secret/super-secret. This takes precedence.
path "initial/cant" {
  capabilities = ["deny"]
}
```

### Sentinel policies

Sentinel Policies are advanced options for the policies. For example allow access to a sybset of users from another region during working hours

Bindings:

- Time
- Region
- IP

Example

```bash
import "time"

# Expect requests to only happen during work days (Monday through Friday)
# 0 for Sunday and 6 for Saturday
workdays = rule {
    time.now.weekday > 0 and time.now.weekday < 6
}

# Expect requests to only happen during work hours (7:00 am - 6:00 pm)
workhours = rule {
    time.now.hour > 7 and time.now.hour < 18
}

main = rule {
    workdays and workhours
}
```

More examples [here](https://developer.hashicorp.com/vault/tutorials/policies/sentinel)

## Entities

Used if the users can be identified from multiple providers

- Create a policy for the acces the user should have
- Create an entity representing teh user
- Associate aliases representing each of his accounts as the entity member
- You can set additional policies and metadata on the entity level so that both accounts can inherit them

## Groups

Croups are used to combine multiple entities

### Example

Any user who belongs to training team in GitHub organization, example-inc are permitted to perform all operations against the secret/education path.

You can find more information [here](https://developer.hashicorp.com/vault/tutorials/auth-methods/identity)

### Exercise 2

- Create a secret in your key/value store named secret
- Create a policy using the ui to read the specific secret and policy to write the secret
- Generate two tokens ansd atach each policy to a token accordingly
- Then test the access level of policies using the tokens to read and overwrite the secret

## Additional Engines

### SSH

Enable an SSH engine
Here you can generate new keys

- Navigate to **Secret Engines**
- Click **Enable Engine**
- Select **SSH**
- Click **Enable Engine**
- Select the engine and click **Create role**
- Add a name for the role
- Crerate a file file **otp_role**
- Set the Key type to **top**
- Set a default username **ubuntu**
- Click on the new role in the ssh engine and you can add username and ip address
- Click generate to generate a key
- Make sure that the user has the newly create role

Or using the cli

```bash
# Local machine
vault secrets enable ssh
vault write ssh/roles/opt_role key_type=otp \
default_user=ubuntu \
cird_list=0.0.0.0/0  # create role for the engine

tee policy.hcl <<EOF
  # Read permission on the k/v secrets
  path "ssh/creds/opt_role" {
      capabilities = ["read", "read", "update"]
  }
EOF

vault policy write otp_policy ./policy.hcl
# you can set access to specific a ip address using the newly created user
vault write ssh/creds/otp_role ip=172.31.109.21
```

Now when we create a new user we attach the policy to give them access to the ssh engine
To use the ssh key for loging into a server we can use ssh-helper to get the keys from vault

Install ssh helper

```bash
# on the remote machine
sudo tee /etc/vault-ssh-helper.d/config.hcl <<EOF
vault_addr = "http:127.0.0.1:8200"
ssh_mount_point = "ssh"
allowed_roles = "*"
EOF

vim /etc/pam.d/sshd
# Comment out @include common-auth
# And add
auth requisite pam_exec.so quiet expose_authtok log=/var/log/vault-ssh.log /user/local/bin/vault-ssh-helper -config=/etc/vault-ssh-helper.d/config.hcl
auth optional pam_unix.so not_set_pass use_first_pass nodelay

vim /etc/ssh/sshd_config

# Change the properties
ChalendgeResponseAuthentication yes
UsePam yes
PasswordAuthentication no

# Restart the service
sudo systemctl restart sshd

# Test the configuration
vault-ssh-helper -verify-only -config /etc/vault-ssh-helper.d/config.hcl

vault write ssh/creds/otp_role ip=172.31.109.21

# The output will generate a key which we use as a one time password for the ssh command

ssh ubuntu@172.31.109.21

```

## Logging

By default the logs of vault when run as a service are stored in /var/log/vault_audit.log

## Using vault for Website authentication

```bash
# On the vault server
vault secrets enable -path=web-auth kv
# Add user credentials
vault kv put web_auth/creds user@mail.com=mypass
# Add a policy to read the secrets
sudo tee policy.hcl <<EOF
path "web-auth/creds" {
  capabilities = ["read"]
}
EOF
vault policy write web-auth-policy policy.hcl
# Create token using the policy
vault token create -policy=web-auth-policy -format=json | jq -r ".auth.client_token"
# hvs.htoFrwoCC6gBVBnD10zwTsQC
```

```bash
# On the client
VAULT_TOKEN=hvs.htoFrwoCC6gBVBnD10zwTsQC
HASHED_CREDS=$(echo "user@mail.commypass" | base64)
VAULT_SERVER_HOST=https://vault.mycompany.com
curl -H "X-Vault_token: $VAULT_TOKEN" --request POST -d '{"user@mail.com":"${HAShED_CREDS}"} \
$VAULT_SERVER_HOST/v1/web-auth/creds
```

## Authenticate incoming requests using vault

```bash
# On the vault server
vault secrets enable -path=api-keys kv
# generate a token
TOKEN=$(echo -n "random_string" | sha256sum | cut -d' ' -f1)
# Add user credentials
vault kv put api-keys/my_api api_01=$TOKEN
# Add a policy to read the secrets
sudo tee policy.hcl <<EOF
path "api-keys/my_api" {
  capabilities = ["read"]
}
EOF
vault policy write my_api-policy policy.hcl
# Create token using the policy
vault token create -policy=web-auth-policy -format=json | jq -r ".auth.client_token"
# hvs.htoFrwoCC6gBVBnD10zwTsQC
```

```bash
# On the client
VAULT_TOKEN=hvs.htoFrwoCC6gBVBnD10zwTsQC
VAULT_SERVER_HOST=https://vault.mycompany.com

curl -H "X-Vault_token: $VAULT_TOKEN" --request GET \
$VAULT_SERVER_HOST/v1/api_keys/my_api

# this will be the output
{
  "request_id": "b92b3be7-c793-366b-914b-b4cc5df82c4e",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "data": {
      "api_01": "528b36022f3bc7b1de66f30b", # <-- We extracted the token
    },
    "metadata": {
      "created_time": "2024-09-17T10:53:22.090934781Z",
      "custom_metadata": null,
      "deletion_time": "",
      "destroyed": false,
      "version": 1
    }
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null,
  "mount_type": "kv"
}
```

https://github.com/nodevault/node-vault

## Database Authentication via Vault

Vault can automatically create efemeral paswords for our database to use for a specific time period

```bash
# On the vault server
vault secrets enable database
# generate a token
SQL_ADDR="127.0.0.1"
DB_USER="user"
DB_PASS=$(echo -n "random_string" | sha256sum | cut -d' ' -f1)

# Add user credentials
vault write database/config/mssql \
    plugin_name=mssql-database-plugin \
    connection_url=sqlserver://{{username}}:{{password}}@$SQL_ADDR \
    allowed_roles="readonly" \
    username=$DB_USER \
    password=$DB_PASS

# Add a policy to read the secrets
tee readonly.sql <<EOF
USE [myapp];
CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}';
CREATE USER [{{name}}] FOR LOGIN [{{name}}];
EXEC sp_addrolemember db_datareader, [{{name}}];
EOF

vault write database/roles/readonly \
  db_name=mssql \
creation_statements=@readonly.sql \
  default_ttl=1h \
  max_ttl=24h

# get the credentials
read database/creds/readonly

```

### Leases

The credentials generated are leased that means that they have an expiration time
We can modify that expiration time or renew the lease

```bash
LEASE_ID=$(vault list -format=json sys/leases/lookup/database/creds/readonly | jq -r ".[0]")
# Renew the lease
vault lease renew database/creds/readonly/$LEASE_ID

# Output
Key                Value
---                -----
lease_id           database/creds/readonly/IQKUMCTg3M5QTRZ0abmLKjTX
lease_duration     1h
lease_renewable    true

# Revoke a specific lease
vault lease revoke database/creds/readonly/$LEASE_ID

# Output
All revocation operations queued successfully!

# List the existing leases
vault list sys/leases/lookup/database/creds/readonly

#Output
Keys
----
PQ32SURhydsSqu286tvsOpli.OywaL

# Revoke all leases
vault lease revoke -prefix database/creds/readonly
# Output
All revocation operations queued successfully!

# List the existing leases
vault list sys/leases/lookup/database/creds/readonly
# Output
No value found at sys/leases/lookup/database/creds/readonly/

```

You can also define a password policy so the generated passwords will be created based on it

```bash
# Create policy
$ tee password-policy.hcl <<EOF
length=20

rule "charset" {
  charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  min-chars = 1
}

rule "charset" {
  charset = "abcdefghijklmnopqrstuvwxyz"
  min-chars = 1
}

rule "charset" {
  charset = "0123456789"
  min-chars = 1
}

rule "charset" {
  charset = "!@#$%^&*"
  min-chars = 1
}
EOF

vault write sys/policies/password/mssql policy=@password-policy.hcl

# Test by generating a secret
vault read sys/policies/password/mssql/generate

# Output
Key         Value
---         -----
password    #v!RQDHxHunJ1TUmCyys

# Assign policy to the database engine
vault write database/config/mssql \
     password_policy="mssql"

# Optional: define a username template
vault write database/config/mssql \
    username_template="myorg-{{.RoleName}}-{{unix_time}}-{{random 8}}"

```

# Vault cli

## Enviroment variables

Can be used in order not to pass paramters to Vault

```bash
export VAULT_TOKEN=<token>
export VAULT_NAMESPACE=<namespace>
export VAULT_ADDR=<vault_ip>
export VAULT_LOG_LEVEL=info | debug | warning | error
```

## Create a secret path

```bash
vault operator unseal                    # unseals vault
vault login                              # use token
vault secrets enable -path=databases kv  # enables a new secrets path of type key/value
vault secrets list                       # lists all secrets
```

## Insert a key/value secret to vault

```bash
vault kv put databases/prod postgress=my_super_secret_postgres_master_key
vault kv get databases/prod
```

## Disabling the secrets engine

```bash
vault secrets disable -path=databases
```

# Vault Rest Api

The API of can be found [here](https://developer.hashicorp.com/vault/api-docs)

Example

```bash
# get specific secret
curl \
    --header "X-Vault-Token: ..." \
    https://127.0.0.1:8200/v1/kv/:path

# list secrets
curl \
    --header "X-Vault-Token: ..." \
    --request LIST \
    https://127.0.0.1:8200/v1/kv/:path
```

# Dynamic secrets in GCP

More information [here](https://developer.hashicorp.com/vault/tutorials/auth-methods/gcp-auth-method)

Usage example
()

## GCP Initial Setup

- Create a project
- Create service level account **IAM & Admins > Service Accounts**
- Name it **Vault**
- Click **Create and Continue**
- On the role type filter type and select the following roles
  - **Service Account Key Admin**
  - **Serivce Account Token Creator**
  - **Serivce Account Admin**
  - **Security Reviewer**
  - **Security Admin**
- CLick **Done**
- On the right menu next to the name of your service account click the three dots
- Select **Manage Keys**
- Click on **Add Key > Create new key**
- Click on **JSON**
- Save the file as **VaultServiceAccountKey.json**
- Go to **APIs and Services > Enable APIs** E
- Enable **Identity and Access Management API**
- Enable **Cloud Resource Management Management API**

or use the gcloud cli
Install gcloud cli

Linux

```bash
curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz
tar -xf google-cloud-cli-linux-x86_64.tar.gz
./google-cloud-sdk/install.sh
gcloud init
```

Windows

```poweshell
(New-Object Net.WebClient).DownloadFile("https://dl.google.com/dl/cloudsdk/channels/rapid/GoogleCloudSDKInstaller.exe", "$env:Temp\GoogleCloudSDKInstaller.exe")

& $env:Temp\GoogleCloudSDKInstaller.exe
gcloud init
```

```bash
export PROJECT_ID="id _of _the project"
gcloud projects list  # get google project id
gcloud services list --enabled | grep 'resource\|iam' # see which apis are enabled
gcloud services enable iam.googleapis.com # enabled apis
gcloud services enable compute.googleapis.com # optional
gcloud services enable cloudresourcemanager.googleapis.com
gcloud iam service-accounts create VaultServiceAccount --display-name="VaultServiceAccount" # create gcloud gcloud iam roles create VaultServiceRole \
    --project=$PROJECT_ID \
    --title=VaultServiceRole \
    --stage=GA \
    --permissions=iam.serviceAccounts.get,iam.serviceAccountKeys.get,iam.serviceAccounts.signJwt # create IAM role
ROLE_NAME=$(gcloud iam roles list --project=$PROJECT_ID --format=json --filter="vault" | jq -r '.[].name') # get role name
SERVICE_ACCOUNT=$(gcloud iam service-accounts list --project=$PROJECT_ID --filter=vault --format=json | jq -r '.[].email') # get service account
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="$ROLE_NAME" # add the Vault service account to the GCP project and bind the role to the service account.
gcloud iam service-accounts keys create VaultServiceAccountKey.json \
    --iam-account=$SERVICE_ACCOUNT \
    --project=$PROJECT_ID # create a service account key credential file
# download the key JSON file

```

## Vault Authentication with GCP

Add credentials

```bash
vault secrets enable gcp
vault write auth/gcp/config credentials=@VaultServiceAccountKey.json
tee dev.hcl <<EOF
  # Read permission on the k/v secrets
  path "/secret/*" {
      capabilities = ["read", "list"]
  }
EOF
vault policy write dev dev.hcl # create development policy

vault write auth/gcp/role/vault-iam-auth-role \
   type="iam" \
   policies="dev" \
   bound_service_accounts="$SERVICE_ACCOUNT"
```

Create a Roleset

```bash

# Optional deploy an instance of vault
vault write auth/gcp/role/vault-gce-auth-role \
   type="gce" \
   policies="dev" \
   bound_projects="$PROJECT_ID" \
   bound_zones="eu-west1-b" \

vault login -method=gcp \
    role="vault-iam-auth-role" \
    service_account="$SERVICE_ACCOUNT" \
    jwt_exp="15m" \
    credentials=@VaultServiceAccountKey.json
```
