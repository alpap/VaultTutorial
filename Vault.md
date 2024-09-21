# Vault install

## Install vault

```bash
sudo apt install vault
```

## Configure vault

```bash
nano /etc/vault.d/vault.hcl
```

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

## Optional create a service for valt

```bash
sudo nano /etc/systemd/system/vault.service
```

pasteh the bellow in the file

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

update enable and start the vault service more info [here](https://www.digitalocean.com/community/tutorials/how-to-use-systemctl-to-manage-systemd-services-and-units)

```bash
sudo systemctl daemon-reload
sudo systemctl enable vault
sudo systemctl start vault
sudo systemctl list-units --type=service
sudo systemctl status vault
```

## Start vault

```bash
sudo vault server -config /etc/vault.d/vault.hcl
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

```**bash**
# 3 times as it requires 3 keys
vault operator unseal
```

**Info**
Then paste in the key ansd repeat the process two more times

```bash
#output
Unseal Key (will be hidden):
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false  <-------- this means that the seal has been lifted
Total Shares    5
Threshold       3
Version         1.17.5
Build Date      2024-08-30T15:54:57Z
Storage Type    file
Cluster Name    vault-cluster-aafffa25
Cluster ID      4e257c8a-a10b-72de-79c0-b750322bc271
HA Enabled      false
```

https://releases.hashicorp.com/consul/1.19.2/consul_1.19.2_linux_arm64.zip

## Optional unlock vault using th ui

Navigate to `https://127.0.0.1:8200`

In the ui enter 3 different keys from the key list we got before

## Login throught he ui

Navigate to `https://127.0.0.1:8200`

Use the token login as we have nmos set up another method and paste the token we saved before

```bash
Initial Root Token: hvs.htoFrwoCC6gBVBnD10zwTsQC
```

## Enable Secret Engines

In the menu click **Secret Engines** and click enable new engine on the top right corner

Add a generic KV here we will have to choose the **Maximum number of versions** and more options

For now we will use the basic and click **Enable Engine**

## Adding keys to the engine

Click on the **KV** engine and then click on the **Create secret**

Here we can choose the ype of secret **JSON** or **String** which is the default

We add a **path** to it and one or multiple **key/value** pairs

- Path: initial
- Secret data:
  - key: cant
  - value: touch

## Optional add Username password access to your vault

- From the menu click on **Access**
- Then cloose **Authentication methods**
- Click on the **Username & Password**
- Leave the path as is and clock **Enable method**

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

## Optional OIDC Provider

Set up a **Vault** IODC to use with other services and users

## Create a Group

## Create an Entity

## Create a policy

- From the menu click on **Policies**
- Click on **ACL Policies**
- Click on **Create ACL Policy**
- Name the policy **Initial**
- Add the content bellow to the text field

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

- Click **Save**


## Vault cli

```bash
vault operator unseal # unseals vault 
vault login # use token 
valult secrets list # lists all secrets


```


|update||
|---|----|
|||