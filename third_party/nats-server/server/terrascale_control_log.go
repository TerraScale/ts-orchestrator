package server

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/nats-io/nkeys"
)

const terraScaleControlLog = "TS_CONTROL_LOG"

// EnsureTerraScaleControlLog is an in-process root operation, never a NATS API.
// Its caller must independently prove the original protected birth/incarnation.
func (s *Server) EnsureTerraScaleControlLog(ctx context.Context, account *Account, replicas int, beforeEffect func(context.Context) error) error {
	if s == nil || ctx == nil || account == nil || beforeEffect == nil || (replicas != 1 && replicas != 3 && replicas != 5) {
		return errors.New("fixed control-log initialization lacks its original root source")
	}
	if _, finite := ctx.Deadline(); !finite {
		return errors.New("fixed control-log initialization requires its original finite lifetime")
	}
	controlAccount, regional := s.terraScaleControlLogAccount()
	if !regional || controlAccount == "" || account.Name != controlAccount {
		return errors.New("fixed control-log initialization requires the installed regional account pin")
	}
	account.mu.RLock()
	owned := account.srv == s
	account.mu.RUnlock()
	registered, found := s.accounts.Load(account.Name)
	if !owned || !found || registered != account || account == s.SystemAccount() {
		return errors.New("fixed control-log initialization requires this server's actual regional account")
	}
	guard := func() error {
		if current, regional := s.terraScaleControlLogAccount(); !regional || current != controlAccount {
			return errors.New("original regional account pin is unavailable")
		}
		if ctx.Err() != nil || !s.Running() {
			return errors.New("original root control-log initialization ended")
		}
		if err := beforeEffect(ctx); err != nil {
			return err
		}
		return ctx.Err()
	}
	if err := guard(); err != nil {
		return err
	}
	expected := StreamConfig{
		Name: terraScaleControlLog, Description: "Fenced regional authority, operation, and host mutation log",
		Subjects: []string{"ts.control.*.>"}, Retention: LimitsPolicy,
		MaxConsumers: -1, MaxMsgs: -1, MaxBytes: -1, MaxMsgsPer: -1,
		Storage: FileStorage, Replicas: replicas, DenyDelete: true, DenyPurge: true,
		Metadata: map[string]string{"terrascale-contract": "authority-log-v1"},
	}
	setStaticStreamMetadata(&expected)
	expected, apiErr := s.checkStreamCfg(&expected, account, false)
	if apiErr != nil {
		return apiErr
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := guard(); err != nil {
			return err
		}
		clustered := s.JetStreamIsClustered()
		if replicas > 1 && !clustered {
			return errors.New("replicated control-log initialization requires the native metadata group")
		}
		assigned, pending := false, false
		var assignmentConfig *StreamConfig
		if clustered {
			js, cc := s.getJetStreamCluster()
			if js == nil || cc == nil {
				return errors.New("original control-log metadata group is unavailable")
			}
			js.mu.RLock()
			if committed := js.streamAssignment(account.Name, terraScaleControlLog); committed != nil {
				assigned, assignmentConfig = true, committed.Config.clone()
			} else if inflight := js.streamAssignmentOrInflight(account.Name, terraScaleControlLog); inflight != nil {
				pending, assignmentConfig = true, inflight.Config.clone()
			}
			js.mu.RUnlock()
			if assignmentConfig != nil && !reflect.DeepEqual(*assignmentConfig, expected) {
				return errors.New("existing control-log assignment differs from its fixed contract")
			}
		}
		if stream, err := account.lookupStream(terraScaleControlLog); err == nil {
			if !reflect.DeepEqual(stream.config(), expected) {
				return errors.New("existing control log differs from its fixed contract")
			}
			if !clustered || assigned {
				return guard()
			}
		} else if !IsNatsErr(err, JSStreamNotFoundErr) {
			return err
		} else if !clustered {
			if err := guard(); err != nil {
				return err
			}
			if err := account.jsNonClusteredStreamLimitsCheck(&expected); err != nil {
				return err
			}
			if err := guard(); err != nil {
				return err
			}
			if _, err := account.addStreamPedantic(&expected, false); err != nil {
				return err
			}
			continue
		} else if !assigned && !pending && s.JetStreamIsLeader() {
			if err := guard(); err != nil {
				return err
			}
			// Preserve the actual metadata proposal/assignment path for R3.
			s.jsClusteredStreamRequest(&ClientInfo{Account: account.Name, Cluster: s.ClusterName()}, account,
				"$JS.API.STREAM.CREATE."+terraScaleControlLog, _EMPTY_, nil, &StreamConfigRequest{StreamConfig: expected})
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.quitCh:
			return errors.New("original root broker stopped during control-log initialization")
		case <-ticker.C:
		}
	}
}

// API callers, including native reply dispatchers, cannot mutate this fixed log.
func (s *Server) denyTerraScaleControlLogAPI(ci *ClientInfo, account *Account, stream, subject, reply string, msg []byte) bool {
	if stream != terraScaleControlLog {
		return false
	}
	response := ApiResponse{Type: JSApiSystemResponseType,
		Error: &ApiError{Code: 403, Description: "TS_CONTROL_LOG lifecycle belongs to the original root broker"}}
	s.sendAPIErrResponse(ci, account, subject, reply, string(msg), s.jsonResponse(&response))
	return true
}

// Generic NATS resolvers keep native behavior; a regional resolver must pin a valid account.
func (s *Server) terraScaleControlLogAccount() (string, bool) {
	resolver, regional := s.AccountResolver().(interface{ TerraScaleControlLogAccount() string })
	if !regional {
		return "", false
	}
	account := resolver.TerraScaleControlLogAccount()
	if !nkeys.IsValidPublicAccountKey(account) {
		return "", true
	}
	return account, true
}
