//go:build linux && amd64

package main

import (
	"fmt"
	"io"
	"path"
	"strings"
)

// newc assigns guest UID/GID 0 without chown, mknod or a host filesystem mount.
type newc struct {
	out   io.Writer
	ino   uint32
	paths map[string]bool
}

func (c *newc) entry(name string, mode uint32, data []byte, major, minor uint32) error {
	name = strings.TrimPrefix(name, "/")
	if name == "" || name == "." || name == ".." || path.IsAbs(name) || name != path.Clean(name) || strings.HasPrefix(name, "../") || strings.ContainsRune(name, 0) || c.paths[name] {
		return fmt.Errorf("invalid or repeated guest archive path %q", name)
	}
	c.paths[name] = true
	c.ino++
	header := fmt.Sprintf("070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x", c.ino, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(name)+1, 0)
	if _, err := io.WriteString(c.out, header+name+"\x00"); err != nil {
		return err
	}
	if err := c.pad(len(header) + len(name) + 1); err != nil {
		return err
	}
	if _, err := c.out.Write(data); err != nil {
		return err
	}
	return c.pad(len(data))
}

func (c *newc) pad(size int) error {
	_, err := c.out.Write(make([]byte, (4-size%4)%4))
	return err
}
