package nodelist

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func Run(args []string, out io.Writer) error {
	if len(args) > 0 && args[0] == "keys" {

		if len(args) > 2 {
			return errors.New("usage: ts-orch node keys [STATE]")
		}
		state := "/var/lib/ts-orch"
		if len(args) == 2 {
			state = args[1]
		}

		keys, err := Keys(state)
		if err != nil {
			return err
		}
		data, err := protocol.EncodeJSON(keys)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "%s\n", data)
		return err
	}
	if len(args) != 5 || args[0] != "list" || args[1] != "build" {
		return errors.New("usage: ts-orch node list build SEQUENCE INVENTORY OUTPUT")
	}
	sequence, err := strconv.ParseUint(args[2], 10, 64)
	if err != nil || sequence == 0 {
		return errors.New("sequence must be a positive integer")
	}
	data, err := os.ReadFile(args[3])
	if err != nil {
		return err
	}
	var nodes []Node
	if err := protocol.DecodeStrict(data, &nodes, MaxBytes); err != nil {
		return err
	}
	for i := range nodes {
		address, err := MeshIP(nodes[i].Name, nodes[i].Region)
		if err != nil {
			return err
		}
		if nodes[i].MeshIP != "" && nodes[i].MeshIP != address {
			return errors.New("mesh_ip differs from the derived address")
		}
		nodes[i].MeshIP = address
	}
	list := List{Sequence: sequence, Nodes: nodes}
	if err := list.Validate(); err != nil {
		return err
	}
	data, err = protocol.EncodeJSON(list)
	if err != nil {
		return err
	}
	return os.WriteFile(args[4], append(data, '\n'), 0o644)
}
