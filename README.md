# Vault Fauna Secrets Plugin

A Vault secrets engine that can generate Fauna keys and return their secret.

Very much a work in progress.

To try run `make` in one terminal to build the plugin, start a Vault dev server
and load the plugin.

In a separate terminal enable the secrets engine:
```
vault secrets enable -path=fauna vault-fauna
```

Set the root config:
```
vault write fauna/config/root endpoint=https://db.fauna.com secret=[admin key secret]
```

Rotate the root key:
```
vault write -force fauna/config/rotate-root
```

Create a role:
```
vault write fauna/roles/[role name] database=[database] role=[fauna key role]
```

Get a new key:
```
vault read fauna/[role name]

Key                Value
---                -----
lease_id           fauna/[role name]/[lease id]
lease_duration     768h
lease_renewable    true
secret             [secret]
```
