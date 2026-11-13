package vaultsecret

func AlertDeliveryRefs() map[string]Ref {
	return map[string]Ref{
		"CLOUDFLARE_ACCOUNT_ID_FILE":  {Vault: SharedVault, Name: "gru-1-cloudflare-account-id"},
		"CLOUDFLARE_EMAIL_TOKEN_FILE": {Vault: SharedVault, Name: "gru-1-cloudflare-email-token"},
		"TS_ALERTS_NTFY_TOPIC_FILE":   {Vault: SharedVault, Name: "gru-1-ts-alerts-ntfy-topic"},
	}
}
