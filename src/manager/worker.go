package manager

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	//"time"
	"net"
	"unsafe"
)

var mutex sync.Mutex

type Worker struct {
	SourceAddr    string
	SourcePort    uint16
	DestStartAddr string
	DestEndAddr   string
	DestStartPort uint16
	DestEndPort   uint16
	StartPort     uint16
	EndPort       uint16
	notify        chan int

	nowDestAddr     string
	nowDestPort     uint16
	IsRandomSrcPort bool
	RoutineId       int
}

func (w *Worker) createRawSocket() (fd int) {

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
	timeVal.Sec = 6
	err = syscall.SetsockoptTimeval(socket, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, timeVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SetsockoptTimeval error :%s", err.Error())
		os.Exit(1)
	}

	return socket
}

func (w *Worker) sendPacket(buf []byte, RemoteAddr *syscall.SockaddrInet4, socket int) {
	SendtoErr := syscall.Sendto(socket, buf, 0, RemoteAddr)
	if SendtoErr != nil {
		fmt.Fprintf(os.Stderr, "Sendto is failed : %s \n", SendtoErr)
		return
	} else {
		//fmt.Printf("Sendto is ok \n")
	}

}

func (w *Worker) recvPacket(socket int) ([]byte, int) {

	//time.Sleep(time.Duration(time.Millisecond * 100))
	RecvBuf := make([]byte, 52)
	var RecvLen int
	//var from net.TCPAddr
	var RecvErr error
	RecvLen, _, RecvErr = syscall.Recvfrom(socket, RecvBuf, 0)
	if RecvErr != nil {
		fmt.Printf("%s", RecvErr.Error())
	}
	return RecvBuf, RecvLen
}

func (w *Worker) check(Buf []byte) bool {
	if Buf[33]&ACK == ACK && Buf[33]&SYN == SYN && Buf[33]&RST != RST { //RecvBuf[33] is flag of tcp header
		return true
	} else {
		return false
	}
	return true
}

func parseSrcAddrFromRecvBuf(buf []byte) string {
	Addr_A := fmt.Sprintf("%02x", buf[12])
	Addr_B := fmt.Sprintf("%02x", buf[13])
	Addr_C := fmt.Sprintf("%02x", buf[14])
	Addr_D := fmt.Sprintf("%02x", buf[15])

	Addr_Int_A, _ := strconv.ParseInt(Addr_A, 16, 0)
	Addr_Int_B, _ := strconv.ParseInt(Addr_B, 16, 0)
	Addr_Int_C, _ := strconv.ParseInt(Addr_C, 16, 0)
	Addr_Int_D, _ := strconv.ParseInt(Addr_D, 16, 0)

	SrcAddr := fmt.Sprintf("%d.%d.%d.%d", Addr_Int_A, Addr_Int_B, Addr_Int_C, Addr_Int_D)
	return SrcAddr
}
func parseDstAddrFromRecvBuf(buf []byte) string {
	Addr_A := fmt.Sprintf("%02x", buf[16])
	Addr_B := fmt.Sprintf("%02x", buf[17])
	Addr_C := fmt.Sprintf("%02x", buf[18])
	Addr_D := fmt.Sprintf("%02x", buf[19])

	Addr_Int_A, _ := strconv.ParseInt(Addr_A, 16, 0)
	Addr_Int_B, _ := strconv.ParseInt(Addr_B, 16, 0)
	Addr_Int_C, _ := strconv.ParseInt(Addr_C, 16, 0)
	Addr_Int_D, _ := strconv.ParseInt(Addr_D, 16, 0)

	SrcAddr := fmt.Sprintf("%d.%d.%d.%d", Addr_Int_A, Addr_Int_B, Addr_Int_C, Addr_Int_D)
	return SrcAddr
}
func parseSrcPortFromRecvBuf(buf []byte) string {
	SrcPort := fmt.Sprintf("%2x", buf[20:22])
	Iport, _ := strconv.ParseInt(SrcPort, 16, 0)
	return strconv.Itoa(int(Iport))
}
func (w *Worker) Init() {

	w.nowDestAddr = w.DestStartAddr
	w.nowDestPort = w.DestStartPort

}

func (w *Worker) setNowPort(port uint16) {
	w.nowDestPort = port
}

func (w *Worker) setNowIPAddr(IP string) {
	w.nowDestAddr = IP
}

func (w *Worker) nextTask() (NextIPAddr string, NextPort uint16) {

	nowIP := w.nowDestAddr
	nowPort := w.nowDestPort

	if nowPort == w.EndPort { //The Next Port will be overflow
		if nowIP != w.DestEndAddr {
			nextIP := w.ipAddressSelfAdd(nowIP)
			NextIPAddr = nextIP
			NextPort = w.StartPort
			w.setNowIPAddr(NextIPAddr)
			w.setNowPort(NextPort)
			return
		} else {
			return "", 0
		}

	} else {
		if nowPort < w.EndPort && nowIP != w.DestEndAddr {
			NextPort = nowPort + 1
			NextIPAddr = nowIP
			w.setNowPort(NextPort)
			w.setNowIPAddr(NextIPAddr)
			return
		} else {
			if nowPort < w.EndPort && nowPort < w.DestEndPort && nowIP == w.DestEndAddr {
				NextIPAddr = nowIP
				NextPort = nowPort + 1
				w.setNowIPAddr(NextIPAddr)
				w.setNowPort(NextPort)
			}

			if nowPort == w.DestEndPort && nowIP == w.DestEndAddr {
				return "", 0
			}
		}
	}
	return

}

func (w *Worker) ipAddressSelfAdd(IPString string) string {

	if IPString == "" {
		fmt.Fprintf(os.Stderr, "IPString is Null ")
		os.Exit(0)
	}
	per := strings.Split(IPString, ".")

	a, _ := strconv.Atoi(per[0])
	b, _ := strconv.Atoi(per[1])
	c, _ := strconv.Atoi(per[2])
	d, _ := strconv.Atoi(per[3])

	if d >= 254 {
		if c >= 255 {

			if b >= 255 {
				if a == 255 {
					a = 255
					b = 255
					c = 255
					d = 255 //ip address is overflow
				} else {
					a++
					b = 0
					c = 0
				}
			} else {
				b++ //进位
				c = 0
			}

		} else {
			c++ //c小于254，自加
		}
		d = 1 //过滤网路地址
	} else {
		d += 1 //最后一位小于254，自加
	}

	var NewIP []string = make([]string, 4)
	NewIP[0] = strconv.Itoa(a)
	NewIP[1] = strconv.Itoa(b)
	NewIP[2] = strconv.Itoa(c)
	NewIP[3] = strconv.Itoa(d)

	DestIPAddress := strings.Join(NewIP, ".")
	return DestIPAddress
}

//find unused port
func getFreePort() (port int) {
	conn, err := net.Listen("tcp", ":0")
	if err != nil {
		fmt.Printf("find unused port failed:%s\n", err)
		os.Exit(1)
	}

	port = conn.Addr().(*net.TCPAddr).Port
	err = conn.Close()
	if err != nil {
		fmt.Printf("find unused port failed:%s\n", err)
		os.Exit(1)
	}
	return port
}

func (w *Worker) run() {

	for i := 0; ; i++ {
		/* Make tcp Packet */
		tcpMaker := new(TCPmaker)
		tcpMaker.DestAddr = w.nowDestAddr
		tcpMaker.DestPort = w.nowDestPort
		tcpMaker.SourceAddr = w.SourceAddr
		if w.IsRandomSrcPort {
			tcpMaker.SourcePort = uint16(getFreePort())
		} else {
			tcpMaker.SourcePort = w.SourcePort
		}
		PacketLen := tcpMaker.GetPacketLen()
		Packet := make([]byte, PacketLen)
		buf := tcpMaker.MakePacket(SYN)
		copy(Packet, buf)

		RemoteAddr := new(syscall.SockaddrInet4)
		InetIPAddr := tcpMaker.GetInetDestIPAddr()
		destAddr := unsafe.Pointer(&InetIPAddr)
		byteAddr := (*[4]byte)(destAddr)
		RemoteAddr.Addr[0] = byteAddr[0]
		RemoteAddr.Addr[1] = byteAddr[1]
		RemoteAddr.Addr[2] = byteAddr[2]
		RemoteAddr.Addr[3] = byteAddr[3]
		RemoteAddr.Port = int(tcpMaker.GetlittleEndianDestPort())

		socket := w.createRawSocket()
		//fmt.Printf("%d sendpacket,port :%d \n", i, w.nowDestPort)
		w.sendPacket(Packet, RemoteAddr, socket)
		RecvBuf, RecvLen := w.recvPacket(socket)
		if RecvLen == 44 && w.check(RecvBuf) {

			Openned_Port := parseSrcPortFromRecvBuf(RecvBuf)
			Openned_Addr := parseSrcAddrFromRecvBuf(RecvBuf)
			DstAddr := parseDstAddrFromRecvBuf(RecvBuf)
			if DstAddr == w.SourceAddr {
				fmt.Printf("IP :%s \t\t Port :%s \t\t is open \n", Openned_Addr, Openned_Port)
				//sendRSTPacket(tcpMaker, RemoteAddr, socket)

			}
			syscall.Close(socket)

		} else {
			//fmt.Printf("IP :%s Port :%d \t is not open \n", w.nowDestAddr, w.nowDestPort)
			syscall.Close(socket)
		}

		NextIP, NextPort := w.nextTask()

		//fmt.Printf("NextIP %s NextPort %d\n", NextIP, NextPort)

		if NextIP == "" && 0 == NextPort {
			//w.notify <- 1
			break
		} else {
			w.setNowIPAddr(NextIP)
			w.setNowPort(NextPort)
		}
	}
}

func (w *Worker) Run(channel chan int) {
	w.notify = channel
	w.run()
	channel <- w.RoutineId
}
func sendRSTPacket(Maker *TCPmaker, RemoteAddr *syscall.SockaddrInet4, socket int) {
	buf := Maker.MakePacket(RST)
	SendtoErr := syscall.Sendto(socket, buf, 0, RemoteAddr)
	if SendtoErr != nil {
		fmt.Fprintf(os.Stderr, "Sendto is failed : %s \n", SendtoErr)
		return
	} else {
		fmt.Printf("Send Fin packet is ok \n")
	}
}
