package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	handle *pcap.Handle
	err    error

	channel     int8 = 0
	station_mac string
	iface       string
)

var ap_list []AP

type AP struct {
	Bbsid   string
	Essid   string
	Channel int8

	Station_list []Station
}

type Station struct {
	Mac string
}

func main() {
	// argv //////////////////////////////////////////////////////////////////////////////
	// if len(os.Args) < 3 {
	// 	fmt.Println("syntax : ./deauth-attack <interface> <ap mac> [<station mac>]")
	// 	fmt.Println("sample : ./deauth-attack 00:11:22:33:44:55 66:77:88:99:AA:BB")
	// 	os.Exit(1)
	// }

	// iface := os.Args[1]
	iface := "mon0"
	// ap_mac := os.Args[2]
	// station_mac = "ff:ff:ff:ff:ff:ff"
	// if len(os.Args) == 4 {
	// 	station_mac = os.Args[3]
	// }
	//////////////////////////////////////////////////////////////////////////////////////

	// pcap handler //////////////////////////////////////////////////////////////////////
	handle, err = pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	//////////////////////////////////////////////////////////////////////////////////////

	go channel_hopping()
	go send_ap_list()
	// Parsing ///////////////////////////////////////////////////////////////////////////
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		_dot11 := packet.Layer(layers.LayerTypeDot11)
		if _dot11 == nil {
			continue
		}
		dot11, _ := _dot11.(*layers.Dot11)

		bbsid_mac := dot11.Address2
		station_mac := dot11.Address1
		channel := int8(0)
		essid := ""

		if dot11.Type == 32 {
			// Paarse Beacon Frame ///////////////////////////////////////////////////////
			_dot11info := packet.Layer(layers.LayerTypeDot11InformationElement)
			if _dot11info == nil {
				continue
			}
			dot11info, _ := _dot11info.(*layers.Dot11InformationElement)
			if dot11info.ID != layers.Dot11InformationElementIDSSID {
				continue
			}

			essid = string(dot11info.Info)
			channel = int8(packet.Layers()[5].LayerContents()[2])

			// exist => true /////////////////////////////////////////////////////////////
			if !check_ap_exist(bbsid_mac.String(), ap_list) {
				one := AP{}
				one.Bbsid = bbsid_mac.String()
				one.Essid = essid
				one.Channel = channel
				one.Station_list = []Station{}

				ap_list = append(ap_list, one)
			}
			///////////////////////////////////////////////////////////////////////////////
		} else if dot11.Type == 34 {
			// Parse QoS Data /////////////////////////////////////////////////////////////

			// fmt.Println("bbsid_mac : ", bbsid_mac, " station_mac : ", station_mac)

			for i, ap := range ap_list {
				var mac net.HardwareAddr

				if ap.Bbsid == bbsid_mac.String() {
					mac = station_mac
				} else if ap.Bbsid == station_mac.String() {
					mac = bbsid_mac
				}

				if !check_station_exist(mac.String(), ap.Bbsid, ap.Station_list) {
					one := Station{}
					one.Mac = mac.String()
					ap_list[i].Station_list = append(ap_list[i].Station_list, one)
				}
			}
			///////////////////////////////////////////////////////////////////////////////
		} else {
			continue
		}
		// show_current()
	}
}

func send_ap_list() {
	for {
		for _, ap := range ap_list {
			pbytes, _ := json.Marshal(ap)
			buff := bytes.NewBuffer(pbytes)

			_, err := http.Post("http://localhost:3000/post", "application/json", buff)
			if err != nil {
				// panic(err)
				continue
			}

			time.Sleep(time.Second)
		}

	}
}

func check_ap_exist(bbsid string, ap_list []AP) bool {
	for _, ap := range ap_list {
		if ap.Bbsid == bbsid {
			return true
		}
	}

	return false
}

func check_station_exist(mac string, ap string, stations []Station) bool {
	if len(mac) == 0 {
		return true
	}

	for _, station := range stations {
		if station.Mac == mac || station.Mac == ap {
			return true
		}
	}

	return false
}

// "ff:ff:ff:ff:ff:ff" => 255 255 255 255 255 255 ////////////////////////////////////////
func trans_string_to_int(str string) []byte {
	arr := []byte{}
	for i := 0; i <= 15; i += 3 {
		num, _ := strconv.ParseInt(str[i:i+2], 16, 16)
		arr = append(arr, byte(num))
	}
	return arr
}

//////////////////////////////////////////////////////////////////////////////////////////

func channel_hopping() {
	a := []string{"1", "7", "13", "2", "8", "3", "9", "4", "10", "5", "11", "6", "12"}

	for {
		for _, j := range a {
			exec.Command("iwconfig", "mon0", "channel", j).Start()
			time.Sleep(time.Second * 1)
			if channel != 0 {
				break
			}
		}
		if channel != 0 {
			break
		}
	}
}

func show_current() {
	for _, ap := range ap_list {
		fmt.Println(ap.Bbsid, ap.Essid, ap.Channel)

		for _, station := range ap.Station_list {
			fmt.Println(station.Mac, " - ", len(station.Mac))
		}
	}

	fmt.Printf("------------------------------------------\n")
}
