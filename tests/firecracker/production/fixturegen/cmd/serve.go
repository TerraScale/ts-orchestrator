package main

import (
	"context"
	"crypto/tls"
	json "encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/tests/firecracker/production"
	"git.terrascale.tech/TerraScale/ts-orchestrator/tests/firecracker/production/fixturegen"
)

type simulatorAudit struct {
	Slots          map[string]slotAudit `json:"slots"`
	UnknownSources uint64               `json:"unknownSources"`
}

type slotAudit struct {
	Requests []production.RequestRecord `json:"requests"`
	Overflow uint64                     `json:"overflow"`
}

// serveSimulators binds only the isolated lab bridge and link-local IMDS
// address. A source-IP map prevents one VM from reading another slot's routes.
func serveSimulators(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	packetPath := flags.String("packet", "", "signed production packet")
	publicPath := flags.String("root-cert", "", "trusted packet root PEM")
	sourceRoot := flags.String("source-root", "", "source tree matching packet pins")
	imageOCID := flags.String("image-ocid", "", "reviewed image OCID")
	auditPath := flags.String("audit", "", "new JSON audit output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *packetPath == "" || *publicPath == "" ||
		*sourceRoot == "" || *imageOCID == "" || *auditPath == "" {
		return errors.New("serve requires -packet, -root-cert, -source-root, -image-ocid and -audit")
	}
	auditFile, err := os.OpenFile(*auditPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer auditFile.Close()
	roots, err := readRoots(*publicPath)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	packet, err := fixturegen.ValidatePacket(*packetPath, roots, now)
	if err != nil {
		return err
	}
	if err := fixturegen.VerifyCompletedSourcePins(*sourceRoot, packet.Manifest().SourcePins); err != nil {
		return err
	}
	if _, err := fixturegen.VerifyPacketEmbeddedImage(packet, roots, *imageOCID, now); err != nil {
		return err
	}
	if err := packet.ValidateProductionGuests(now); err != nil {
		return err
	}
	certificate, key, err := packet.SimulatorTLS(now)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		return err
	}
	simulators := make(map[string]*production.Simulator, 3)
	addresses := make(map[string]string, 3)
	for _, controller := range packet.Manifest().Controllers {
		config, err := packet.SimulatorConfig(controller.Slot)
		if err != nil {
			return err
		}
		simulator, err := production.NewSimulator(config)
		if err != nil {
			return err
		}
		address, err := packet.PrivateAddress(controller.Slot)
		if err != nil {
			return err
		}
		if addresses[address] != "" {
			return errors.New("simulator source IPs are duplicated")
		}
		addresses[address] = controller.Slot
		simulators[controller.Slot] = simulator
	}
	var unknown atomic.Uint64
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ip, _, err := net.SplitHostPort(request.RemoteAddr)
		if err != nil || addresses[ip] == "" {
			unknown.Add(1)
			http.Error(writer, "unknown controller source", http.StatusForbidden)
			return
		}
		simulators[addresses[ip]].ServeHTTP(writer, request)
	})
	imds, err := net.Listen("tcp", "169.254.169.254:80")
	if err != nil {
		return fmt.Errorf("bind isolated IMDS: %w", err)
	}
	defer imds.Close()
	oci, err := net.Listen("tcp", "10.44.0.1:443")
	if err != nil {
		return fmt.Errorf("bind isolated OCI HTTPS: %w", err)
	}
	defer oci.Close()
	imdsServer := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes: 64 << 10}
	ociServer := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes: 64 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12,
			Certificates: []tls.Certificate{pair}}}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errorsCh := make(chan error, 2)
	go func() { errorsCh <- imdsServer.Serve(imds) }()
	go func() { errorsCh <- ociServer.Serve(tls.NewListener(oci, ociServer.TLSConfig)) }()
	fmt.Println("production OCI simulators ready on isolated bridge")
	select {
	case <-ctx.Done():
	case err = <-errorsCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := errors.Join(imdsServer.Shutdown(shutdownCtx), ociServer.Shutdown(shutdownCtx)); err != nil {
		return err
	}
	audit := simulatorAudit{Slots: make(map[string]slotAudit, len(simulators)),
		UnknownSources: unknown.Load()}
	for slot, simulator := range simulators {
		audit.Slots[slot] = slotAudit{Requests: simulator.Requests(), Overflow: simulator.OverflowCount()}
	}
	wire, err := json.Marshal(audit)
	if err != nil {
		return err
	}
	if _, err := auditFile.Write(append(wire, '\n')); err != nil {
		return err
	}
	if err := auditFile.Sync(); err != nil {
		return err
	}
	if strings.TrimSpace(string(wire)) == "" {
		return errors.New("simulator audit was empty")
	}
	return nil
}
