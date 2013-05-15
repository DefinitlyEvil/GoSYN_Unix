goSynPortScanner
================

USAGE : goSynPortScanner [SourceIP] [SourcePort] [DestStartIP-DestEndIP] [DestStartPort-DestEndPort]  [goroutineNum]

Example : goSynPortScanner 192.168.1.1 1234 8.8.8.8-8.8.8.9 50-100 10 

         The Source Address of the packet  is            :         192.168.1.1 
         The Source Port of the packet is                :         1234 
         The Destinations Start Address of the packet is :         8.8.8.8 
         The Destinations End Address of the packet is   :         8.8.8.9 
         The Destinations Start Port of the packet is    :         53 
         The Destinations End Port of the packet is      :         100
         The numbers of goroutine is                      :         10

 Note : You must check that The Destinations Address is legal 
        And The Source Address should be The Address of Network card
