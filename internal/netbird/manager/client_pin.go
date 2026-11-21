package manager

import "github.com/TerraScale/ts-orchestrator/internal/netbird/client"

var clientPin = func() client.Pin {
	p := client.Pin{Version: "0.81.3"}
	p.Archives.Arm64 = client.Archive{URL: "https://github.com/netbirdio/netbird/releases/download/v0.81.3/netbird_0.81.3_linux_arm64.tar.gz",
		Bytes: 14607827, SHA256: "980eef938177108bdfa7d802566b6309123592a58631349a78f11cd97c76c22d",
		BinarySHA256: "da0c759ba50c0e1fd652d6f584587db3d3523dcc6bd18c11fab479969a3057ce"}
	p.Archives.AMD64 = client.Archive{URL: "https://github.com/netbirdio/netbird/releases/download/v0.81.3/netbird_0.81.3_linux_amd64.tar.gz",
		Bytes: 15954874, SHA256: "cbdea310068e35449f034544d5137fefee8f6d948fffd020883ffc8b3bab63b1",
		BinarySHA256: "2bef5a5a44249443c0c492883e1b243ff5bc9d835266a8c5644a2a664bb3b846"}
	return p
}()
