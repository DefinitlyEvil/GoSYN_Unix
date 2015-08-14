goSynPortScanner
================
####目前只支持在linux运行，可能是最快的tcp syn端口扫描器了


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
