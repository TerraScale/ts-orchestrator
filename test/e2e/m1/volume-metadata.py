import http.server
import json
import sys

volume = "ocid1.volume.oc1.test.data"


class Metadata(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/opc/v2/volumeAttachments/":
            self.send_error(404)
            return
        if self.path != "/opc/v2/instance/":
            self.send_error(404)
            return
        case = self.headers.get("X-Lane-Case", "")
        if case == "metadata-stalled":
            self.connection.recv(1)
            return
        document = dict.fromkeys(
            (
                "agentConfig", "availabilityDomain", "canonicalRegionName",
                "compartmentId", "definedTags", "displayName", "faultDomain",
                "hostname", "id", "image", "metadata", "ociAdName", "region",
                "regionInfo", "shape", "shapeConfig", "state", "tenantId",
                "timeCreated",
            )
        )
        document["id"] = "ocid1.instance.oc1.test.host"
        document["metadata"] = {
            "terrascale-data-volume": volume,
            "terrascale-data-may-format": "true",
        }
        metadata = document["metadata"]
        if case == "instance-id-null":
            document["id"] = None
        elif case == "instance-id-empty":
            document["id"] = ""
        elif case == "instance-id-number":
            document["id"] = 7
        elif case == "instance-id-missing":
            del document["id"]
        elif case == "metadata-missing":
            del document["metadata"]
        elif case == "metadata-null":
            document["metadata"] = None
        elif case == "metadata-array":
            document["metadata"] = []
        elif case.startswith("binding-volume-"):
            value = case.removeprefix("binding-volume-")
            if value == "missing":
                del metadata["terrascale-data-volume"]
            else:
                metadata["terrascale-data-volume"] = {
                    "empty": "", "different": "ocid1.volume.oc1.test.other",
                    "null": None, "number": 7, "malformed": "data",
                }[value]
        elif case.startswith("binding-permission-"):
            value = case.removeprefix("binding-permission-")
            if value == "missing":
                del metadata["terrascale-data-may-format"]
            else:
                metadata["terrascale-data-may-format"] = {
                    "empty": "", "different": "false", "null": None,
                    "boolean": True, "malformed": "yes",
                }[value]
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{" if case == "instance-invalid-json" else json.dumps(document).encode())


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Metadata)
with open(sys.argv[1], "w") as ready:
    ready.write(str(server.server_port) + "\n")
server.serve_forever()
