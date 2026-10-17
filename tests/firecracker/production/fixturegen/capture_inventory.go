package fixturegen

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

// CapturedInventory contains only Object Storage routes generated from exact
// keys observed by the public Ledger's capturing ObjectStorageClient. The
// caller may add separately verified Compute inventory before packet emission.
type CapturedInventory struct {
	Routes []Route
	Bodies map[string][]byte
}

func BuildCapturedInventory(anchor bootstrap.VerifiedBootstrapAnchor, controllers []Controller,
	store *CapturingObjectStorage,
) (CapturedInventory, error) {
	if !anchor.IsVerified() || store == nil || store.PutCount() == 0 || len(controllers) != 3 {
		return CapturedInventory{}, errors.New("capture inventory requires verified anchor, ledger writes, and three controllers")
	}
	anchored := anchor.Anchor()
	if anchored.Environment != "production" || string(anchored.Cell) != "GRU" ||
		!slices.Equal(anchored.ControllerSlots, []string{"controller-a", "controller-b", "controller-c"}) {
		return CapturedInventory{}, errors.New("capture inventory anchor is outside production GRU three-slot scope")
	}
	domain := anchor.StorageDomain()
	if err := domain.Validate(); err != nil {
		return CapturedInventory{}, err
	}
	for index, controller := range controllers {
		if controller.Slot != anchored.ControllerSlots[index] ||
			controller.GuestRoot != "controllers/"+controller.Slot+"/guest-root" ||
			!strings.HasPrefix(controller.InstanceOCID, "ocid1.instance.oc1.sa-saopaulo-1.") {
			return CapturedInventory{}, fmt.Errorf("capture controller %q differs from anchored slot topology", controller.Slot)
		}
		for previous := range index {
			if controllers[previous].InstanceOCID == controller.InstanceOCID {
				return CapturedInventory{}, errors.New("capture controllers share one OCI instance identity")
			}
		}
	}
	validKey := func(namespace, bucket, name string) bool {
		return namespace == domain.Namespace &&
			(bucket == domain.LedgerBucket || bucket == domain.HeadBucket) && name != "" &&
			(domain.Prefix == "" || strings.HasPrefix(name, domain.Prefix+"/"))
	}
	objects := store.Snapshot()
	missing := store.MissingSnapshot()
	if len(objects)+len(missing) == 0 || 3*(len(objects)+len(missing)) > 512 {
		return CapturedInventory{}, errors.New("captured object inventory exceeds simulator route bound")
	}
	inventory := CapturedInventory{Bodies: make(map[string][]byte, len(objects))}
	for _, controller := range controllers {
		for _, object := range objects {
			if !validKey(object.Namespace, object.Bucket, object.ObjectName) {
				return CapturedInventory{}, errors.New("captured object escaped anchored private storage domain")
			}
			route, err := CapturedObjectRoute(controller, object)
			if err != nil {
				return CapturedInventory{}, err
			}
			if previous, ok := inventory.Bodies[route.BodyPath]; ok && !bytes.Equal(previous, object.Body) {
				return CapturedInventory{}, errors.New("captured response digest path has different bytes")
			}
			inventory.Bodies[route.BodyPath] = bytes.Clone(object.Body)
			inventory.Routes = append(inventory.Routes, route)
		}
		for _, absent := range missing {
			if !validKey(absent.Namespace, absent.Bucket, absent.ObjectName) {
				return CapturedInventory{}, errors.New("captured missing key escaped anchored private storage domain")
			}
			route, err := CapturedMissingRoute(controller, absent)
			if err != nil {
				return CapturedInventory{}, err
			}
			inventory.Routes = append(inventory.Routes, route)
		}
	}
	slices.SortFunc(inventory.Routes, func(a, b Route) int {
		return strings.Compare(a.ControllerSlot+"\n"+a.InstanceOCID+"\n"+a.Host+"\n"+a.RequestURI,
			b.ControllerSlot+"\n"+b.InstanceOCID+"\n"+b.Host+"\n"+b.RequestURI)
	})
	return inventory, nil
}
