// +build linux

/*
 *    HoneyBadger core library for detecting TCP injection attacks
 *
 *    Copyright (C) 2014, 2015  David Stainton
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package pcap_sniffer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"time"
)

type PcapHandle struct {
	handle *pcap.Handle
}

func NewPcapFileSniffer(filename string) (*PcapHandle, error) {
	pcapFileHandle, err := pcap.OpenOffline(filename)
	pcapHandle := PcapHandle{
		handle: pcapFileHandle,
	}
	return &pcapHandle, err
}

func NewPcapWireSniffer(netDevice string, snaplen int32, wireDuration time.Duration, filter string) (*PcapHandle, error) {
	pcapWireHandle, err := pcap.OpenLive(netDevice, snaplen, true, wireDuration)
	pcapHandle := PcapHandle{
		handle: pcapWireHandle,
	}
	err = pcapHandle.handle.SetBPFFilter(filter)
	return &pcapHandle, err
}

func (p *PcapHandle) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	return p.handle.ReadPacketData()
}

func (p *PcapHandle) Close() {
}
