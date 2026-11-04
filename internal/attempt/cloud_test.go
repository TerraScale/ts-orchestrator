package attempt

import ()

// sampleLaunch has exactly the members `oci-region preview seed-launch`
// writes (internal/ociregion/seed.go seedLaunch).
const sampleLaunch = `{"availabilityDomain":"AD-1","faultDomain":"FAULT-DOMAIN-1","compartmentId":"ocid1.compartment.oc1..c","displayName":"gru-1-ctl-1","shape":"VM.Standard.A1.Flex","shapeConfig":{"ocpus":1,"memoryInGBs":6},"sourceDetails":{"sourceType":"image","imageId":"ocid1.image.fixture","bootVolumeSizeInGBs":50,"bootVolumeVpusPerGB":10},"subnetId":"ocid1.subnet.oc1..s","privateIp":"10.0.0.11","nsgIds":["ocid1.networksecuritygroup.oc1..n"],"assignPublicIp":false,"metadata":{"terrascale-bootstrap":"{\"schemaVersion\":1,\"slot\":\"controller-a\"}","user_data":"Y2xvdWQtaW5pdA=="},"freeformTags":{"BootstrapCreateKey":"seed-a"}}`
