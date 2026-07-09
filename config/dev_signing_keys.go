package config

// devSigningKeysJSON is a CHECKED-IN Ed25519 keypair for local development
// only, so `make dev` works with zero setup. Load uses it exclusively when
// ENV=local and AUTH_SIGNING_KEYS is unset (master plan §5); every other
// environment must supply real keys and never these.
const devSigningKeysJSON = `[{"kid":"dev-1","private_key_b64":"XundoKwZm+4auDDZcsn5HzuS0AhO2GbGIHysj8UGsctg1nw4m0C84PfDLizM4buVZ3cda8nN28SCrWhUrwK2QQ=="}]`
