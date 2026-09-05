package vmcontrolseed

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"sort"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func newUser(files map[string][]byte, path string, tls initialgrant.TLSFiles) (initialgrant.Connection, error) {
	pair, err := nkeys.CreateUser()
	if err != nil {
		return initialgrant.Connection{}, err
	}
	defer pair.Wipe()
	raw, err := pair.Seed()
	if err != nil {
		return initialgrant.Connection{}, err
	}
	files[path] = append([]byte(nil), raw...)
	public, err := pair.PublicKey()
	if err != nil {
		return initialgrant.Connection{}, err
	}
	return initialgrant.Connection{NKeySeedFile: path, PublicNKey: public, TLS: tls}, nil
}
func tlsFiles(files map[string][]byte, cert, key string) initialgrant.TLSFiles {
	return initialgrant.TLSFiles{CAFile: CAPath, CASHA256: digest(files[CAPath]), CertificateFile: cert, CertificateSHA256: digest(files[cert]), KeyFile: key}
}
func brokerUser(cell, instance string, global, provisioner bool, public string) (map[string]any, error) {
	publish, subscribe, err := initialcontrol.Permissions(cell, instance, global, provisioner)
	if err != nil {
		return nil, err
	}
	return map[string]any{"nkey": public, "permissions": map[string]any{"publish": map[string]any{"allow": publish}, "subscribe": map[string]any{"allow": subscribe}}}, nil
}

// GenerateGRU declares one seed and the remaining signed initial participants.
// All membership pins are supplied by the real guest identity issuer.
func GenerateGRU(runID string, guests []Guest) (map[string]Material, error) {
	if !identifierPattern.MatchString(runID) || len(guests) == 0 || len(guests) > 3 {
		return nil, errors.New("vmcontrolseed: initial GRU requires one to three declared candidates")
	}
	ordered := append([]Guest(nil), guests...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	seen := map[string]bool{}
	pins := map[string]string{}
	for _, guest := range ordered {
		ip, err := netip.ParseAddr(guest.Address)
		raw, keyErr := base64.StdEncoding.DecodeString(guest.MembershipPublicKey)
		if err != nil || !ip.Is4() || !ip.IsPrivate() || !identifierPattern.MatchString(guest.ID) || seen[guest.ID] || seen[guest.Address] || seen[guest.MembershipPublicKey] || keyErr != nil {
			return nil, errors.New("vmcontrolseed: invalid declared guest identity, address or membership")
		}
		if _, err := x509.ParsePKIXPublicKey(raw); err != nil {
			return nil, errors.New("vmcontrolseed: invalid membership public key")
		}
		seen[guest.ID], seen[guest.Address], seen[guest.MembershipPublicKey] = true, true, true
		pins[guest.ID] = guest.MembershipPublicKey
	}
	pinsJSON, err := json.Marshal(pins)
	if err != nil {
		return nil, err
	}
	ca, issue, closeIssuer, err := newCertificateIssuer(runID)
	if err != nil {
		return nil, err
	}
	defer closeIssuer()
	profile, err := initialcontrol.ProfileDigest("gru", ordered[0].ID)
	if err != nil {
		return nil, err
	}
	budget, err := initialcontrol.RequiredStorageBytes("gru", ordered[0].ID)
	if err != nil {
		return nil, err
	}
	result := map[string]Material{}
	complete := false
	defer func() {
		if !complete {
			for _, m := range result {
				m.Clear()
			}
		}
	}()
	configs := map[string]initialgrant.Config{}
	var peers []initialgrant.Peer
	for index, guest := range ordered {
		files := map[string][]byte{CAPath: append([]byte(nil), ca...)}
		result[guest.ID] = Material{HostID: guest.ID, Address: guest.Address, Selected: index == 0, Files: files}
		cert, key, err := issue(guest, false)
		if err != nil {
			return nil, err
		}
		files[CertificatePath], files[PrivateKeyPath] = cert, key
		runtime, err := newUser(files, NKeyPath, tlsFiles(files, CertificatePath, PrivateKeyPath))
		if err != nil {
			return nil, err
		}
		config := initialgrant.Config{Version: 1, Mode: "initial-gru-r1", Role: "participant", NodeID: guest.ID, Cell: "gru", Instance: guest.ID, SeedInstance: ordered[0].ID, ProfileSHA256: profile, Regional: initialgrant.Store{Account: RegionalAccount, Runtime: runtime}, Membership: initialgrant.Membership{SigningKeyFile: MembershipKeyPath, PublicKey: guest.MembershipPublicKey, PinsFile: MembershipPinsPath, PinsSHA256: digest(pinsJSON)}, Broker: initialgrant.Broker{ServerName: ordered[0].ID, StoreDir: StorePath, Endpoint: "tls://" + net.JoinHostPort(ordered[0].Address, "4222"), StorageBudgetBytes: budget}}

		readerGuest := guest
		readerGuest.ID += "-authority-reader"
		readerCert, readerKey, err := issue(readerGuest, false)
		if err != nil {
			return nil, err
		}
		files[AuthorityCAPath], files[AuthorityCertificatePath], files[AuthorityPrivateKeyPath] = append([]byte(nil), ca...), readerCert, readerKey
		readerUser, err := newUser(files, AuthorityNKeyPath, initialgrant.TLSFiles{})
		if err != nil {
			return nil, err
		}
		config.AuthorityReader = nodeauthority.ReaderConfig{Endpoint: config.Broker.Endpoint, ServerName: config.Broker.ServerName, Account: RegionalAccount, NKeySeedFile: AuthorityNKeyPath, PublicNKey: readerUser.PublicNKey, CAFile: AuthorityCAPath, CASHA256: digest(ca), CertificateFile: AuthorityCertificatePath, CertificateSHA256: digest(readerCert), KeyFile: AuthorityPrivateKeyPath}
		peer := initialgrant.Peer{AuthorityReaderPublicNKey: readerUser.PublicNKey, Instance: guest.ID, RegionalPublicNKey: runtime.PublicNKey, MembershipPublicKey: guest.MembershipPublicKey}
		if index == 0 {
			config.Role = "seed"
			provisionerGuest := guest
			provisionerGuest.ID += "-provisioner"
			cert, key, err := issue(provisionerGuest, false)
			if err != nil {
				return nil, err
			}
			files[ProvisionerCertificatePath], files[ProvisionerPrivateKeyPath] = cert, key
			provisionerTLS := tlsFiles(files, ProvisionerCertificatePath, ProvisionerPrivateKeyPath)
			regionalProvisioner, err := newUser(files, RegionalProvisionerNKeyPath, provisionerTLS)
			if err != nil {
				return nil, err
			}
			config.Regional.Provisioner = &regionalProvisioner
			globalProvisioner, err := newUser(files, GlobalProvisionerNKeyPath, provisionerTLS)
			if err != nil {
				return nil, err
			}
			globalRuntime, err := newUser(files, GlobalNKeyPath, runtime.TLS)
			if err != nil {
				return nil, err
			}
			config.Global = &initialgrant.Store{Account: GlobalAccount, Provisioner: &globalProvisioner, Runtime: globalRuntime}
			peer.GlobalPublicNKey = globalRuntime.PublicNKey
			snapshotGuest := guest
			snapshotGuest.ID += "-snapshot-reader"
			snapshotCert, snapshotKey, err := issue(snapshotGuest, false)
			if err != nil {
				return nil, err
			}
			files[SnapshotCertificatePath], files[SnapshotPrivateKeyPath] = snapshotCert, snapshotKey
			snapshotTLS := tlsFiles(files, SnapshotCertificatePath, SnapshotPrivateKeyPath)
			regionalSnapshot, err := newUser(files, RegionalSnapshotNKeyPath, snapshotTLS)
			if err != nil {
				return nil, err
			}
			globalSnapshot, err := newUser(files, GlobalSnapshotNKeyPath, snapshotTLS)
			if err != nil {
				return nil, err
			}
			config.Regional.SnapshotReader, config.Global.SnapshotReader = &regionalSnapshot, &globalSnapshot

			cert, key, err = issue(guest, true)
			if err != nil {
				return nil, err
			}
			files[ServerCertificatePath], files[ServerPrivateKeyPath] = cert, key
			config.Broker.TLS = tlsFiles(files, ServerCertificatePath, ServerPrivateKeyPath)
		}
		configs[guest.ID] = config
		peers = append(peers, peer)
	}
	for _, guest := range ordered {
		config := configs[guest.ID]
		config.Peers = append([]initialgrant.Peer(nil), peers...)
		if config.Role == "seed" {
			config.Broker.Configuration, err = renderBroker(config)
			if err != nil {
				return nil, err
			}
		}
		data, err := json.Marshal(config)
		if err != nil {
			return nil, err
		}
		m := result[guest.ID]
		m.Settings = string(data)
		result[guest.ID] = m
	}
	for _, m := range result {
		if err := m.Validate(); err != nil {
			return nil, err
		}
	}
	complete = true
	return result, nil
}

func renderBroker(config initialgrant.Config) (string, error) {
	endpoint, err := url.Parse(config.Broker.Endpoint)
	if err != nil {
		return "", err
	}
	brokerAddress := endpoint.Hostname()

	regionalUsers := []map[string]any{}
	globalUsers := []map[string]any{}
	for _, peer := range config.Peers {
		user, err := brokerUser("gru", peer.Instance, false, false, peer.RegionalPublicNKey)
		if err != nil {
			return "", err
		}
		regionalUsers = append(regionalUsers, user)
		pub, sub, err := nodeauthority.ReaderPermissions("ORCH_LEADERS")
		if err != nil {
			return "", err
		}
		regionalUsers = append(regionalUsers, map[string]any{"nkey": peer.AuthorityReaderPublicNKey, "permissions": map[string]any{"publish": map[string]any{"allow": pub}, "subscribe": map[string]any{"allow": sub}}})
	}
	for _, entry := range []struct {
		global, provisioner bool
		key                 string
	}{{false, true, config.Regional.Provisioner.PublicNKey}, {true, true, config.Global.Provisioner.PublicNKey}, {true, false, config.Global.Runtime.PublicNKey}} {
		user, err := brokerUser("gru", config.Instance, entry.global, entry.provisioner, entry.key)
		if err != nil {
			return "", err
		}
		if entry.global {
			globalUsers = append(globalUsers, user)
		} else {
			regionalUsers = append(regionalUsers, user)
		}
	}
	for _, entry := range []struct {
		global bool
		reader *initialgrant.Connection
	}{{false, config.Regional.SnapshotReader}, {true, config.Global.SnapshotReader}} {
		if entry.reader == nil {
			continue
		}
		publish, subscribe, err := initialcontrol.SnapshotPermissions("gru", config.Instance, entry.global)
		if err != nil {
			return "", err
		}
		user := map[string]any{"nkey": entry.reader.PublicNKey, "permissions": map[string]any{"publish": map[string]any{"allow": publish}, "subscribe": map[string]any{"allow": subscribe}}}
		if entry.global {
			globalUsers = append(globalUsers, user)
		} else {
			regionalUsers = append(regionalUsers, user)
		}
	}
	broker := map[string]any{"server_name": config.Instance, "listen": net.JoinHostPort(brokerAddress, "4222"), "max_payload": 4 << 20, "jetstream": map[string]any{"store_dir": StorePath, "max_memory_store": 32 << 20, "max_file_store": config.Broker.StorageBudgetBytes}, "tls": map[string]any{"cert_file": ServerCertificatePath, "key_file": ServerPrivateKeyPath, "ca_file": CAPath, "verify": true, "min_version": "1.3"}, "accounts": map[string]any{RegionalAccount: map[string]any{"jetstream": "enabled", "users": regionalUsers}, GlobalAccount: map[string]any{"jetstream": "enabled", "users": globalUsers}}}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(broker); err != nil {
		return "", err
	}
	return string(bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))), nil
}
