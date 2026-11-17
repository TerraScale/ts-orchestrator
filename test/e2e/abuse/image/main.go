package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func run() error {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(&tar.Header{Name: "probe", Mode: 0755, Size: int64(len(data))}); err != nil {
		return err
	}
	if _, err := writer.Write(data); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	layer, err := tarball.LayerFromReader(&buffer)
	if err != nil {
		return err
	}
	image, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		return err
	}
	config, err := image.ConfigFile()
	if err != nil {
		return err
	}
	config.Architecture, config.OS = os.Args[2], "linux"
	config.Config = v1.Config{Entrypoint: []string{"/probe"}}
	image, err = mutate.ConfigFile(image, config)
	if err != nil {
		return err
	}
	digest, err := image.Digest()
	if err != nil {
		return err
	}
	tag, err := name.ParseReference("localhost/terrascale-abuse-probe:" + digest.Hex[:16])
	if err != nil {
		return err
	}
	directory, err := os.MkdirTemp("", "abuse-oci-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	index, err := layout.Write(directory, empty.Index)
	if err != nil {
		return err
	}
	if err := index.AppendImage(image, layout.WithAnnotations(map[string]string{"org.opencontainers.image.ref.name": tag.Name(), "io.containerd.image.name": tag.Name()})); err != nil {
		return err
	}
	archive, err := os.Create(os.Args[3])
	if err != nil {
		return err
	}
	defer archive.Close()
	output := tar.NewWriter(archive)
	err = filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name, err = filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(header.Name)
		header.Uid, header.Gid = 0, 0
		header.Uname, header.Gname = "", ""
		if err := output.WriteHeader(header); err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copied := io.Copy(output, file)
		closed := file.Close()
		if copied != nil {
			return copied
		}
		return closed
	})
	if err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := archive.Close(); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"tag": tag.Name(), "ref": "localhost/terrascale-abuse-probe@" + digest.String()})
}

func main() {
	if len(os.Args) != 4 || (os.Args[2] != "amd64" && os.Args[2] != "arm64") || run() != nil {
		os.Exit(1)
	}
}
