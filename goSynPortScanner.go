/**********************************************
  Brief : a Golang PortScanner
  Athour : feimyy <feimyy@hotmail.com>
  CopyRight :GPL v2
************************************************/

package main

import (
	"fmt"
	"net"
	"os"
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

func usage() {
	fmt.Printf("\nUSAGE : goSynPortScanner [SourceIP] [SourcePort] [DestIP] [DestPort] \n")
	fmt.Printf("\nExample : goSynPortScanner 192.168.1.1 1234 8.8.8.8 53 \n\n")
	fmt.Printf("\t The Source Address of the packet  is :\t\t192.168.1.1 \n")
	fmt.Printf("\t The Source Port of the packet is :\t\t1234 \n")
	fmt.Printf("\t The Destinations Address of the packet is :\t8.8.8.8 \n")
	fmt.Printf("\t The Destinations Port of the packet is :\t53 \n")
	fmt.Printf("\n Note : You must check that The Destinations Address is legal \n \tAnd The Source Address should be The Address of Network card\n")
}
func main() {

	if len(os.Args) < 5 {
		usage()
		return
	}
	var IP_HEADER_LEN uint32 = 20
	var TCP_HEADER_LEN uint32 = 20
	var PSD_HEADER_LEN uint32 = 12

	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {

		fmt.Fprintf(os.Stderr, "fail to Socket :%s\n", err.Error())
		os.Exit(1)
	}

	err = syscall.SetsockoptString(socket, syscall.IPPROTO_IP, syscall.IP_HDRINCL, "1")
	if err != nil {
		fmt.Fprintf(os.Stderr, "SetsockoptString error :%s\ns", err.Error())
		os.Exit(1)
	}

	timeVal := new(syscall.Timeval)
	timeVal.Sec = 5
	err = syscall.SetsockoptTimeval(socket, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, timeVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SetsockoptTimeval error :%s", err.Error())
		os.Exit(1)
	}

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

	sourceIP := strings.Join(os.Args[1:2], "")
	IP := net.ParseIP(sourceIP)
	b := IP.To4()
	if b == nil {
		fmt.Fprintf(os.Stderr, "Source Address is incorrect\n")
		os.Exit(1)
	}
	ipHeader.sourceIP = inet_address(sourceIP)

	destIP := strings.Join(os.Args[3:4], "")
	IP = net.ParseIP(destIP)
	b = IP.To4()
	if b == nil {
		fmt.Fprintf(os.Stderr, "Dest Address is incorrect\n")
		os.Exit(1)
	}
	ipHeader.destIP = inet_address(destIP)

	/*  Padding The tcp header data */
	tcpHeader := new(TCP_HEADER)

	destPort, err := strconv.Atoi(strings.Join(os.Args[4:5], ""))
	if err != nil {
		fmt.Fprintf(os.Stderr, "DestPort must be a number \n%s \n", err.Error())
		os.Exit(1)
	}
	tcpHeader.destPort = htons(uint16(destPort))

	sourcePort, err := strconv.Atoi(strings.Join(os.Args[2:3], ""))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Source Port must be a number :\n%s\n", err.Error())
		os.Exit(1)
	}
	tcpHeader.soucePort = htons(uint16(sourcePort)) //Source Port

	tcpHeader.seq = htonl(0x01)
	tcpHeader.ack = 0
	tcpHeader.lengthAndres = (uint8(TCP_HEADER_LEN)/4<<4 | 0)
	tcpHeader.flag = 2 //SYN
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
	TotalLength := TCP_HEADER_LEN + IP_HEADER_LEN
	for i := 0; i < 4; i++ {
		buf[TotalLength+uint32(i)] = '0'
	}
	ipHeader.checksum = Checksum(buf, TotalLength)

	copy(buf, (*[20]byte)(IPHeaderDataPtr)[:])

	/* Padding The Source IP and Source Port */
	RemoteAddr := new(syscall.SockaddrInet4)
	destAddr := unsafe.Pointer(&ipHeader.destIP)
	byteAddr := (*[4]byte)(destAddr)
	RemoteAddr.Addr[0] = byteAddr[0]
	RemoteAddr.Addr[1] = byteAddr[1]
	RemoteAddr.Addr[2] = byteAddr[2]
	RemoteAddr.Addr[3] = byteAddr[3]
	RemoteAddr.Port = int(tcpHeader.destPort)

	/* Create New packet ,And the length of packet is 52 bytes */
	SendBuf := make([]byte, IP_HEADER_LEN+TCP_HEADER_LEN)
	copy(SendBuf, (*[20]byte)(IPHeaderDataPtr)[:])
	copy(SendBuf[20:], (*[20]byte)(TcpHeaderDataPtr)[:])

	SendtoErr := syscall.Sendto(socket, SendBuf, 0, RemoteAddr)
	if SendtoErr != nil {
		fmt.Fprintf(os.Stderr, "Sendto is failed : %s \n", SendtoErr)
		return
	} else {
		fmt.Printf("Sendto is ok \n")
	}

	/* Recv information from remote */
	RecvBuf := make([]byte, 52) //The Buffer will not  more than 52 
	_, _, RecvErr := syscall.Recvfrom(socket, RecvBuf, 0)
	if RecvErr != nil {
		fmt.Printf("%s", RecvErr.Error())
	}

	if RecvBuf[33]&ACK == ACK && RecvBuf[33]&SYN == SYN { //RecvBuf[33] is flag of tcp header
		fmt.Printf("The Port %d is Open \n", destPort)
	} else {
		fmt.Printf("The Port %d is not open \n", destPort)
	}

}
