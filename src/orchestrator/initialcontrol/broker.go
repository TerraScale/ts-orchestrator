package initialcontrol

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"

	"github.com/nats-io/nats-server/v2/server"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

// Resolve the signed TLS declaration against the admitted file pins, then
// remove all TLS paths before invoking the NATS parser. Only captured material
// reaches the server, so a later file replacement cannot trigger another read.
func brokerConfigurationWithoutTLS(cfg initialgrant.Config) ([]byte, error) {
	if err := validateBrokerJSON(cfg.Broker.Configuration); err != nil {
		return nil, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(cfg.Broker.Configuration), &root); err != nil {
		return nil, err
	}
	var declaration struct {
		Certificate string `json:"cert_file"`
		Key         string `json:"key_file"`
		CA          string `json:"ca_file"`
		Verify      bool   `json:"verify"`
		Minimum     string `json:"min_version"`
	}
	decoder := json.NewDecoder(bytes.NewReader(root["tls"]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&declaration) != nil || decoder.Decode(&struct{}{}) != io.EOF || declaration.Certificate != cfg.Broker.TLS.CertificateFile || declaration.Key != cfg.Broker.TLS.KeyFile || declaration.CA != cfg.Broker.TLS.CAFile || !declaration.Verify || declaration.Minimum != "1.3" {
		return nil, errors.New("initial control: signed broker TLS declaration differs from admitted material")
	}
	delete(root, "tls")
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(root); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte("\n")), nil
}

func validateBrokerJSON(configuration string) error {
	var root map[string]json.RawMessage
	if json.Unmarshal([]byte(configuration), &root) != nil {
		return errors.New("initial control: broker configuration must be literal JSON")
	}
	allowed := map[string]bool{"server_name": true, "listen": true, "host": true, "port": true, "jetstream": true, "tls": true, "accounts": true, "max_payload": true, "no_sys_acc": true}
	for key := range root {
		if !allowed[key] {
			return errors.New("initial control: broker configuration has an unadmitted top-level option")
		}
	}
	var accounts map[string]map[string]json.RawMessage
	if json.Unmarshal(root["accounts"], &accounts) != nil || len(accounts) != 2 {
		return errors.New("initial control: broker requires exactly two isolated accounts")
	}
	for _, account := range accounts {
		for key := range account {
			if key != "jetstream" && key != "users" {
				return errors.New("initial control: account imports, exports and mappings are not admitted")
			}
		}
	}
	return nil
}

func validateBrokerOptions(cfg initialgrant.Config, expectedTLS *tls.Config) func(*server.Options) error {
	return func(o *server.Options) error {
		invalid := errors.New("initial control: parsed broker options differ from admitted scope")
		needed, err := RequiredStorageBytes(cfg.Cell, cfg.SeedInstance)
		if err != nil {
			return err
		}
		endpoint, err := url.Parse(cfg.Broker.Endpoint)
		if err != nil || endpoint.Scheme != "tls" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" {
			return invalid
		}
		host, port, err := net.SplitHostPort(endpoint.Host)
		if err != nil {
			return invalid
		}
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 {
			return invalid
		}
		if o.ServerName != cfg.Broker.ServerName || o.StoreDir != cfg.Broker.StoreDir || o.Port != p || (o.Host != host && o.Host != "0.0.0.0" && o.Host != "::") || o.DontListen || o.ClientAdvertise != "" || !o.JetStream || o.JetStreamMaxStore < needed || o.JetStreamMaxStore > cfg.Broker.StorageBudgetBytes || o.JetStreamDomain != "" || o.HTTPPort != 0 || o.HTTPSPort != 0 || o.ProfPort != 0 || len(o.Routes) != 0 || o.Cluster.Port != 0 || o.Gateway.Port != 0 || len(o.Gateway.Gateways) != 0 || o.LeafNode.Port != 0 || len(o.LeafNode.Remotes) != 0 || o.Websocket.Port != 0 || o.MQTT.Port != 0 {
			return invalid
		}
		if len(o.Users) != 0 || o.Username != "" || o.Password != "" || o.Authorization != "" || o.AuthCallout != nil || len(o.TrustedKeys) != 0 || len(o.TrustedOperators) != 0 || o.AccountResolver != nil || o.SystemAccount != "" || o.NoAuthUser != "" || o.TLSMap || o.AllowNonTLS {
			return invalid
		}
		actual := o.TLSConfig
		if actual == nil || actual.GetCertificate != nil || actual.GetConfigForClient != nil || actual.GetClientCertificate != nil || actual.VerifyConnection != nil || actual.VerifyPeerCertificate != nil || actual.ClientAuth != tls.RequireAndVerifyClientCert || actual.MinVersion < tls.VersionTLS13 || actual.InsecureSkipVerify || actual.ClientCAs == nil || !actual.ClientCAs.Equal(expectedTLS.ClientCAs) || len(actual.Certificates) != 1 || len(actual.Certificates[0].Certificate) != len(expectedTLS.Certificates[0].Certificate) {
			return invalid
		}
		for i, der := range actual.Certificates[0].Certificate {
			if !bytes.Equal(der, expectedTLS.Certificates[0].Certificate[i]) {
				return invalid
			}
		}
		if cfg.Global == nil || cfg.Regional.Provisioner == nil || cfg.Global.Provisioner == nil || cfg.Regional.Account == cfg.Global.Account {
			return invalid
		}
		accounts := map[string]bool{cfg.Regional.Account: false, cfg.Global.Account: false}
		for _, a := range o.Accounts {
			if a == nil {
				return invalid
			}
			if _, ok := accounts[a.Name]; !ok {
				return invalid
			}
			if accounts[a.Name] {
				return invalid
			}
			accounts[a.Name] = true
		}
		if len(o.Accounts) != 2 {
			return invalid
		}
		type userPlan struct {
			account            string
			publish, subscribe []string
		}
		users := map[string]userPlan{}
		add := func(key, account, instance string, global, infra bool) error {
			if key == "" {
				return invalid
			}
			if _, ok := users[key]; ok {
				return invalid
			}
			pub, sub, err := Permissions(cfg.Cell, instance, global, infra)
			if err != nil {
				return err
			}
			users[key] = userPlan{account, pub, sub}
			return nil
		}
		if err = add(cfg.Regional.Provisioner.PublicNKey, cfg.Regional.Account, cfg.SeedInstance, false, true); err != nil {
			return err
		}
		if err = add(cfg.Global.Provisioner.PublicNKey, cfg.Global.Account, cfg.SeedInstance, true, true); err != nil {
			return err
		}
		if cfg.PreliminaryCapture != nil {
			for index, connection := range []initialgrant.Connection{cfg.PreliminaryCapture.Regional, cfg.PreliminaryCapture.Global} {
				if _, exists := users[connection.PublicNKey]; exists {
					return invalid
				}
				pub, sub, err := CapturePermissions(cfg.Cell, cfg.SeedInstance, index == 1)
				if err != nil {
					return err
				}
				account := cfg.Regional.Account
				if index == 1 {
					account = cfg.Global.Account
				}
				users[connection.PublicNKey] = userPlan{account, pub, sub}
			}
		}
		for _, peer := range cfg.Peers {
			if _, exists := users[peer.AuthorityReaderPublicNKey]; exists {
				return invalid
			}
			pub, sub, err := nodeauthority.ReaderPermissions("ORCH_LEADERS")
			if err != nil {
				return err
			}
			users[peer.AuthorityReaderPublicNKey] = userPlan{cfg.Regional.Account, pub, sub}
			if err = add(peer.RegionalPublicNKey, cfg.Regional.Account, peer.Instance, false, false); err != nil {
				return err
			}
			if peer.GlobalPublicNKey != "" {
				if peer.Instance != cfg.SeedInstance {
					return invalid
				}
				if err = add(peer.GlobalPublicNKey, cfg.Global.Account, peer.Instance, true, false); err != nil {
					return err
				}
			}
		}
		if len(users) != len(o.Nkeys) {
			return invalid
		}
		seen := map[string]bool{}
		for _, user := range o.Nkeys {
			if user == nil || user.Account == nil || user.Permissions == nil || user.Permissions.Publish == nil || user.Permissions.Subscribe == nil || user.Permissions.Response != nil {
				return invalid
			}
			expected, ok := users[user.Nkey]
			if !ok || seen[user.Nkey] || user.Account.Name != expected.account || len(user.Permissions.Publish.Deny) != 0 || len(user.Permissions.Subscribe.Deny) != 0 || !equalStrings(user.Permissions.Publish.Allow, expected.publish) || !equalStrings(user.Permissions.Subscribe.Allow, expected.subscribe) {
				return invalid
			}
			seen[user.Nkey] = true
		}
		return nil
	}
}
