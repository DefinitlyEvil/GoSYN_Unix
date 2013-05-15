package manager

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

	nowDestAddr string
	nowDestPort uint16
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
	timeVal.Sec = 5
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

func (w *Worker) recvPacket(socket int) []byte {

	RecvBuf := make([]byte, 52)
	_, _, RecvErr := syscall.Recvfrom(socket, RecvBuf, 0)
	if RecvErr != nil {
		fmt.Printf("%s", RecvErr.Error())
	}
	return RecvBuf
}

func (w *Worker) check(Buf []byte) bool {

	if Buf[33]&ACK == ACK && Buf[33]&SYN == SYN { //RecvBuf[33] is flag of tcp header
		return true
	} else {
		return false
	}
	return true
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
func (w *Worker) run() {

	for {
		/* Make tcp Packet */
		tcpMaker := new(TCPmaker)
		tcpMaker.DestAddr = w.nowDestAddr
		tcpMaker.DestPort = w.nowDestPort
		tcpMaker.SourceAddr = w.SourceAddr
		tcpMaker.SourcePort = w.SourcePort

		PacketLen := tcpMaker.GetPacketLen()
		Packet := make([]byte, PacketLen)
		buf := tcpMaker.MakePacket()
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
		//fmt.Printf("Socket :%d\n", socket)
		w.sendPacket(Packet, RemoteAddr, socket)

		RecvBuf := w.recvPacket(socket)
		if w.check(RecvBuf) {
			mutex.Lock()
			fmt.Printf("IP :%s \t\t Port :%d \t\t is open \n", w.nowDestAddr, w.nowDestPort)
			mutex.Unlock()
		} else {
			//fmt.Printf("IP :%s Port :%d \t is not open \n", w.nowDestAddr, w.nowDestPort)
		}
		NextIP, NextPort := w.nextTask()

		//fmt.Printf("NextIP %s NextPort %d\n", NextIP, NextPort)

		if NextIP == "" && 0 == NextPort {
			//w.notify <- 1
			break
		} else {
			w.setNowIPAddr(NextIP)
			w.setNowPort(NextPort)
			syscall.Close(socket)
		}
	}
}

func (w *Worker) Run(channel chan int) {
	w.notify = channel
	w.run()
	channel <- 1
}
