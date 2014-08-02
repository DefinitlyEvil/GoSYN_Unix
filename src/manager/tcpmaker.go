package manager

import (
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	URG = 0x20
	ACK = 0X10
	PSH = 0X08
	RST = 0x04
	SYN = 0X02
	FIN = 0X01
)

type IP_HEADER struct {
	headLengthAndVersion byte
	tos                  byte
	totalLength          uint16
	id                   uint16
	flags                uint16
	ttl                  byte
	proto                byte
	checksum             uint16
	sourceIP             uint32
	destIP               uint32
}

type PSD_HEADER struct {
	sourceAddr uint32
	destAddr   uint32
	mbz        byte // some error ,the type of mbz should be signed ,but the byte type is unsigned
	protoType  byte
	headLength uint16
}

type TCP_HEADER struct {
	soucePort    uint16
	destPort     uint16
	seq          uint32
	ack          uint32
	lengthAndres byte
	flag         byte
	windowsSize  uint16
	sum          uint16
	urp          uint16
	//options      [12]byte
}
type TCPmaker struct {
	SourceAddr string
	SourcePort uint16
	DestAddr   string
	DestPort   uint16
}

const (
	IP_HEADER_LEN  = 20
	TCP_HEADER_LEN = 20
	PSD_HEADER_LEN = 12
)

func inet_address(IPString string) (value uint32) {

	per := strings.Split(IPString, ".")
	a, _ := strconv.Atoi(per[0])
	b, _ := strconv.Atoi(per[1])
	c, _ := strconv.Atoi(per[2])
	d, _ := strconv.Atoi(per[3])

	var result uint32

	result1 := uint32(d)
	result1 = result1 << 24 //Padding First place

	result2 := uint32(c)
	result2 = result2 << 16 //Padding Second place

	result3 := uint32(b)
	result3 = result3 << 8 //Padding Third place

	result4 := uint32(a) //Padding Last place

	result = result1 + result2 + result3 + result4 // Combine

	value = result
	return
}

func htons(value uint16) uint16 {

	High := value & 0xFF00
	Low := value & 0xFF

	NewLow := High >> 8
	NewHigh := Low << 8
	NewValue := NewHigh + NewLow
	return NewValue
}
func htonl(value uint32) uint32 {
	a := value & 0xFF000000
	b := value & 0xFF0000
	c := value & 0xFF00
	d := value & 0xFF

	NewA := d << 24
	NewB := c << 8
	NewC := b >> 8
	NewD := a >> 24

	var NewValue uint32 = NewA + NewB + NewC + NewD
	return NewValue
}
func Checksum(buffer []byte, size uint32) uint16 {

	var checksum uint32
	var i uint32 = 0
	for ; size > 0; i += 2 {
		checksum += uint32(buffer[i]) + uint32(buffer[i+1])<<8
		size -= 2
	}

	checksum = checksum>>16 + (checksum & 0xffff)
	checksum += checksum >> 16
	return (uint16(^checksum))
}

func (this *TCPmaker) GetPacketLen() uint32 {

	var Len uint32
	Len = uint32(TCP_HEADER_LEN + IP_HEADER_LEN)
	return Len

}
func (this *TCPmaker) MakePacket(flag byte) (packet []byte) {

	/* Padding The ip Head Data */
	ipHeader := new(IP_HEADER)
	ipHeader.headLengthAndVersion = byte(4<<4 | IP_HEADER_LEN/4)
	ipHeader.tos = 0
	ipHeader.totalLength = htons(uint16(IP_HEADER_LEN + TCP_HEADER_LEN))

	ipHeader.id = htons(1)
	ipHeader.flags = 0
	ipHeader.ttl = 64
	ipHeader.proto = syscall.IPPROTO_TCP
	ipHeader.checksum = 0

	ipHeader.sourceIP = inet_address(this.SourceAddr)
	ipHeader.destIP = inet_address(this.DestAddr)

	/*  Padding The tcp header data */
	tcpHeader := new(TCP_HEADER)

	tcpHeader.destPort = htons(uint16(this.DestPort))
	tcpHeader.soucePort = htons(this.SourcePort)

	tcpHeader.seq = htonl(0x01)
	tcpHeader.ack = 0
	tcpHeader.lengthAndres = (uint8(TCP_HEADER_LEN)/4<<4 | 0)
	tcpHeader.flag = flag //SYN
	tcpHeader.windowsSize = htons(10)
	tcpHeader.sum = 0
	tcpHeader.urp = 0

	/* Padding The psd Header data */
	psdHeader := new(PSD_HEADER)
	psdHeader.sourceAddr = ipHeader.sourceIP
	psdHeader.destAddr = ipHeader.destIP
	psdHeader.mbz = 0
	psdHeader.protoType = syscall.IPPROTO_TCP
	psdHeader.headLength = htons(uint16(TCP_HEADER_LEN))

	/* Calc The tcp Header checkcum */
	PSDHeaderDataPtr := unsafe.Pointer(&psdHeader.sourceAddr)
	TcpHeaderDataPtr := unsafe.Pointer(&tcpHeader.soucePort)
	buf := make([]byte, 60)
	copy(buf, (*[12]byte)(PSDHeaderDataPtr)[:])
	copy(buf[12:], (*[20]byte)(TcpHeaderDataPtr)[:])
	tcpHeader.sum = uint16(Checksum(buf, TCP_HEADER_LEN+PSD_HEADER_LEN))

	/* Calc The IPHeader checksum */
	IPHeaderDataPtr := unsafe.Pointer(&ipHeader.headLengthAndVersion)
	copy(buf, (*[20]byte)(IPHeaderDataPtr)[:])
	copy(buf[20:], (*[20]byte)(TcpHeaderDataPtr)[:])
	TotalLength := uint32(TCP_HEADER_LEN + IP_HEADER_LEN)
	for i := 0; i < 4; i++ {
		buf[TotalLength+uint32(i)] = '0'
	}
	ipHeader.checksum = Checksum(buf, TotalLength)

	Buf := make([]byte, IP_HEADER_LEN+TCP_HEADER_LEN)
	copy(Buf, (*[20]byte)(IPHeaderDataPtr)[:])
	copy(Buf[20:], (*[20]byte)(TcpHeaderDataPtr)[:])

	return Buf
}

func (t *TCPmaker) GetlittleEndianDestPort() uint16 {
	return htons(t.DestPort)
}
func (t *TCPmaker) GetInetDestIPAddr() uint32 {
	return inet_address(t.DestAddr)
}
