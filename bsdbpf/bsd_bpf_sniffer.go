// +build darwin dragonfly freebsd netbsd openbsd

package bsdbpf

import (
	"github.com/google/gopacket/bsdbpf"
)

func GetSniffer() func(iface string, options *bsdbpf.Options) (*bsdbpf.BPFSniffer, error) {
	return bsdbpf.NewBPFSniffer
}
