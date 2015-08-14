/**********************************************
  Brief : a Golang PortScanner
  Athour : feimyy <feimyy@hotmail.com>
  CopyRight :GPL v2
************************************************/

package main

import (
	"fmt"
	"manager"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MAX_ROUTINUE_NUM = 20
)

var mutex sync.Mutex

func usage() {
	fmt.Printf(`
USAGE : goSynPortScanner [SourceIP] [SourcePort] [DestStartIP]-[DestEndIP] [DestStartPort]-[DestEndPort] [RoutineNum] [IsRandomSrcPort]
	
	Example : goSynPortScanner 192.168.1.1 1234 8.8.8.8-8.8.8.9 53-1024  10 true 

		The Source Address of the packet		:	192.168.1.1
		The Source Port of the packet			:	1234
		The Destination Start Address of the packet 		:	8.8.8.8
		The Destination End Address of the packet 		:	8.8.8.8
		The Destination Start Port of the packet		:	53
		The Destination End Port  of the packet			:	1024
		The  Routine Number of Will Created 			：  10
		Whether	the source port be random generated			: 	false

		Note : 
			You must check that The Destinations Address is legal 
			And The Source Address should be The Address of Network card
`)
}

func checkIP(ip string) {
	IP := net.ParseIP(ip)
	b := IP.To4()
	if b == nil {
		fmt.Fprintf(os.Stderr, "IP Address is incorrect\n")
		os.Exit(1)
	}
}
func checkRoutinueNum(num string) uint32 {

	Num, err := strconv.Atoi(num)
	if err != nil {
		fmt.Fprintf(os.Stderr, "The Routinue must be a number \n%s \n", err.Error())
		os.Exit(1)
	}
	if Num > MAX_ROUTINUE_NUM {
		return uint32(MAX_ROUTINUE_NUM)
	} else {
		return uint32(Num)
	}
	return uint32(Num)
}
func getSourceAddr() string {
	sourceIP := strings.Join(os.Args[1:2], "")
	checkIP(sourceIP)
	return sourceIP

}
func getSourcePort() uint16 {
	sourcePort, err := strconv.Atoi(strings.Join(os.Args[2:3], ""))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Source Port must be a number :\n%s\n", err.Error())
		os.Exit(1)
	}
	return uint16(sourcePort)
}

func getDestStartAddr() string {
	DestAddresses := os.Args[3:4]
	Dest := strings.Split(strings.Join(DestAddresses, ""), "-")
	DestStartAddr := Dest[0]
	checkIP(DestStartAddr)
	return DestStartAddr
}
func getDestEndAddr() string {
	destAddresses := os.Args[3:4]
	Dest := strings.Split(strings.Join(destAddresses, ""), "-")
	DestEndAddr := Dest[1]
	checkIP(DestEndAddr)
	return DestEndAddr
}
func getDestStartPort() uint16 {
	Ports := os.Args[4:5]
	p := strings.Split(strings.Join(Ports, ""), "-")
	DestStartPort, err := strconv.Atoi(p[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "DestStartPort  must be a number :\n%s\n", err.Error())
		os.Exit(1)
	}
	return uint16(DestStartPort)
}
func getDestEndPort() uint16 {
	Ports := os.Args[4:5]
	p := strings.Split(strings.Join(Ports, ""), "-")
	DestEndPort, err := strconv.Atoi(p[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "DestEndPort  must be a number :\n%s\n", err.Error())
		os.Exit(1)
	}
	return uint16(DestEndPort)
}
func getRoutinueNum() uint32 {
	Num := os.Args[5:6]
	n := checkRoutinueNum(strings.Join(Num, ""))
	return uint32(n)
}
func getSrcPortOption() bool {
	value, err := strconv.ParseBool(strings.Join(os.Args[6:7], ""))
	if err != nil {
		return true
	} else {
		fmt.Printf("value :%v", value)
		return value
	}
}

func ipAddressSelfAdd(IPString string) string {

	if IPString == "" {
		fmt.Fprintf(os.Stderr, "IPString is Null ")
		os.Exit(0)
	}

	mutex.Lock()
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
	defer mutex.Unlock()
	return DestIPAddress
}

func nextTask(NowDestBeginIP string, NowDestBeginPort uint16, DestStartPort uint16, DestEndPort uint16, routinueNum uint8) (string, uint16) {

	nowIP := NowDestBeginIP
	nowPort := NowDestBeginPort
	var i uint8
	for i = 0; i < routinueNum; i++ {
		if nowPort == DestEndPort { //The Next Port will be overflow

			nowIP = ipAddressSelfAdd(nowIP)
			nowPort = DestStartPort
		} else {
			if nowPort < DestEndPort {
				nowPort++
			} else {

			}
		}
	}

	return nowIP, nowPort

}

func getTaskNum(DestStartAddr string, DestEndAddr string, DestStartPort uint16, DestEndPort uint16) uint32 {

	nowIP := DestStartAddr
	nowPort := DestStartPort

	var count uint32 = 0
	for {

		nextIP, nextPort := nextTask(nowIP, nowPort, DestStartPort, DestEndPort, 1)
		if DestEndPort == nowPort && DestEndAddr == nowIP {
			count = 1
			break
		} else {
			nowIP = nextIP
			nowPort = nextPort
			count++
			if nowIP == DestEndAddr && nowPort == DestEndPort {
				break
			}
		}
	}

	return count
}
func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	if len(os.Args) < 7 {
		usage()
		return
	}

	SourceAddr := getSourceAddr()
	SourcePort := getSourcePort()
	DestStartAddr := getDestStartAddr()
	DestEndAddr := getDestEndAddr()
	DestStartPort := getDestStartPort()
	DestEndPort := getDestEndPort()

	RoutinueNum := getRoutinueNum()
	IsRandomSrcPort := getSrcPortOption()
	var i uint32
	taskNum := getTaskNum(DestStartAddr, DestEndAddr, DestStartPort, DestEndPort)
	space := taskNum / RoutinueNum
	InstanceNum := RoutinueNum

	fmt.Printf("space : %d taskNum %d\n", space, taskNum)
	workers := make([]manager.Worker, InstanceNum)
	channels := make([]chan int, InstanceNum)

	NowDestStartAddr := DestStartAddr
	NowDestStartPort := DestStartPort

	startTime := time.Now()
	for i = 0; i < InstanceNum; i++ {
		worker := new(manager.Worker)
		workers[i] = *worker
		workers[i].SourceAddr = SourceAddr
		workers[i].SourcePort = SourcePort
		workers[i].DestStartAddr = NowDestStartAddr
		workers[i].DestStartPort = NowDestStartPort
		workers[i].StartPort = DestStartPort
		workers[i].EndPort = DestEndPort
		workers[i].IsRandomSrcPort = IsRandomSrcPort
		workers[i].RoutineId = int(i)
		var NowDestEndAddr string
		var NowDestEndPort uint16

		if i != InstanceNum-1 {
			NowDestEndAddr, NowDestEndPort = nextTask(NowDestStartAddr, NowDestStartPort, DestStartPort, DestEndPort, uint8(space))
		} else {
			NowDestEndAddr = DestEndAddr
			NowDestEndPort = DestEndPort
		}

		//fmt.Printf("i : %d NowDestStartAddr: %s  NowDestStartPort:  %d NowDestEndAddr : %s ,NowDestEndPort: %d  \n", i, NowDestStartAddr, NowDestStartPort, NowDestEndAddr, NowDestEndPort)
		workers[i].DestEndAddr = NowDestEndAddr
		workers[i].DestEndPort = NowDestEndPort
		workers[i].Init()
		channels[i] = make(chan int)
		go workers[i].Run(channels[i])
		if (InstanceNum - 1) != i {
			NowDestStartAddr, NowDestStartPort = nextTask(NowDestEndAddr, NowDestEndPort, DestStartPort, DestEndPort, 1)
		}

		if NowDestEndAddr == DestEndAddr && NowDestEndPort == DestEndPort {
			break
		}
	}

	for _, v := range channels {
		<-v
		//fmt.Printf("The %d Routine Finish  its task\n", <-v)
	}
	endTime := time.Now()
	elapseTimeSec := float64(endTime.Sub(startTime).Nanoseconds()) / float64(time.Millisecond)
	fmt.Printf("All Task is finished,elapse time :%0.3f ms\n", elapseTimeSec)
}
