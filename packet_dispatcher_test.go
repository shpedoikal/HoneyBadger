package HoneyBadger

import (
	"github.com/david415/HoneyBadger/logging"
	"github.com/david415/HoneyBadger/types"
	"log"
	"os"
	"testing"
	"time"
)

type MockSniffer struct {
	supervisor  types.Supervisor
	startedChan chan bool
}

func NewMockSniffer(options *PcapSnifferOptions) types.PacketSource {
	var packetSource types.PacketSource = MockSniffer{
		startedChan: make(chan bool, 0),
	}
	return packetSource
}

func (s MockSniffer) Start() {
	log.Print("MockSniffer Start()")
	s.startedChan <- true
}
func (s MockSniffer) Stop() {
	log.Print("MockSniffer Stop()")
}
func (s MockSniffer) SetSupervisor(supervisor types.Supervisor) {
	s.supervisor = supervisor
}
func (s MockSniffer) GetStartedChan() chan bool {
	return s.startedChan
}

type MockConnection struct {
	clientFlow       types.TcpIpFlow
	serverFlow       types.TcpIpFlow
	lastSeen         time.Time
	ClientStreamRing *types.Ring
}

func (m *MockConnection) Start() {
}

func (m *MockConnection) Stop() {
}

func (m *MockConnection) Close() {
}

func (m *MockConnection) GetConnectionHash() types.ConnectionHash {
	return m.clientFlow.ConnectionHash()
}

func (m *MockConnection) GetLastSeen() time.Time {
	return m.lastSeen
}

func (m *MockConnection) ReceivePacket(p *types.PacketManifest) {
}

func (m *MockConnection) SetPacketLogger(l types.PacketLogger) {
}

func (m *MockConnection) SetServerFlow(*types.TcpIpFlow) {
}

func (m *MockConnection) SetClientFlow(*types.TcpIpFlow) {
}

func (m *MockConnection) AppendToClientStreamRing(reassembly *types.Reassembly) {
}

func (m *MockConnection) detectInjection(p types.PacketManifest, flow *types.TcpIpFlow) {
}

func (m *MockConnection) GetClientStreamRing() *types.Ring {
	return m.ClientStreamRing
}

func (m *MockConnection) SetState(state uint8) {
}

func NewMockConnection(options *ConnectionOptions) ConnectionInterface {
	m := MockConnection{}
	return ConnectionInterface(&m)
}

func TestInquisitorForceQuit(t *testing.T) {

	tcpIdleTimeout, _ := time.ParseDuration("10m")
	inquisitorOptions := InquisitorOptions{
		BufferedPerConnection:    10,
		BufferedTotal:            100,
		LogDir:                   ".",
		LogPackets:               true,
		TcpIdleTimeout:           tcpIdleTimeout,
		MaxRingPackets:           40,
		Logger:                   logging.NewAttackMetadataJsonLogger("."),
		DetectHijack:             true,
		DetectInjection:          true,
		DetectCoalesceInjection:  true,
		MaxConcurrentConnections: 100,
	}

	wireDuration, _ := time.ParseDuration("3s")
	snifferOptions := PcapSnifferOptions{
		Interface:    "myInterface",
		Filename:     "",
		WireDuration: wireDuration,
		Snaplen:      65536,
		Filter:       "tcp",
	}

	supervisor := NewBadgerSupervisor(&snifferOptions, &inquisitorOptions, NewMockSniffer, NewMockConnection)

	log.Print("supervisor before run")
	go supervisor.Run()
	log.Print("supervisor after run")

	sniffer := supervisor.GetSniffer()
	startedChan := sniffer.GetStartedChan()
	<-startedChan

	var sig os.Signal
	supervisor.forceQuitChan <- sig
}

func TestInquisitorSourceStopped(t *testing.T) {

	tcpIdleTimeout, _ := time.ParseDuration("10m")
	inquisitorOptions := InquisitorOptions{
		BufferedPerConnection:    10,
		BufferedTotal:            100,
		LogDir:                   ".",
		LogPackets:               true,
		TcpIdleTimeout:           tcpIdleTimeout,
		MaxRingPackets:           40,
		Logger:                   logging.NewAttackMetadataJsonLogger("."),
		DetectHijack:             true,
		DetectInjection:          true,
		DetectCoalesceInjection:  true,
		MaxConcurrentConnections: 100,
	}

	wireDuration, _ := time.ParseDuration("3s")
	snifferOptions := PcapSnifferOptions{
		Interface:    "myInterface",
		Filename:     "",
		WireDuration: wireDuration,
		Snaplen:      65536,
		Filter:       "tcp",
	}

	supervisor := NewBadgerSupervisor(&snifferOptions, &inquisitorOptions, NewMockSniffer, NewMockConnection)

	log.Print("supervisor before run")
	go supervisor.Run()
	log.Print("supervisor after run")

	sniffer := supervisor.GetSniffer()
	startedChan := sniffer.GetStartedChan()
	<-startedChan

	sniffer.Stop()
}

func TestInquisitorSourceReceiveSimple(t *testing.T) {

	tcpIdleTimeout, _ := time.ParseDuration("10m")
	inquisitorOptions := InquisitorOptions{
		BufferedPerConnection:    10,
		BufferedTotal:            100,
		LogDir:                   ".",
		LogPackets:               true,
		TcpIdleTimeout:           tcpIdleTimeout,
		MaxRingPackets:           40,
		Logger:                   logging.NewAttackMetadataJsonLogger("."),
		DetectHijack:             true,
		DetectInjection:          true,
		DetectCoalesceInjection:  true,
		MaxConcurrentConnections: 100,
	}

	wireDuration, _ := time.ParseDuration("3s")
	snifferOptions := PcapSnifferOptions{
		Interface:    "myInterface",
		Filename:     "",
		WireDuration: wireDuration,
		Snaplen:      65536,
		Filter:       "tcp",
	}

	supervisor := NewBadgerSupervisor(&snifferOptions, &inquisitorOptions, NewMockSniffer, NewMockConnection)

	log.Print("supervisor before run")
	go supervisor.Run()
	log.Print("supervisor after run")

	sniffer := supervisor.GetSniffer()
	startedChan := sniffer.GetStartedChan()
	<-startedChan

	sniffer.Stop()
}