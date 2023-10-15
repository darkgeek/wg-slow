package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"

	"gopkg.in/ini.v1"
)

type WireguardConfig struct {
	Interface  string
	Address    string
	PrivateKey string
	Peers      []Peer
}

type Peer struct {
	Name                string
	PublicKey           string
	AllowedIPs          string
	Endpoint            string
	PersistentKeepalive uint32
	PingTarget          string
}

func main() {
	wgInterface := os.Args[1]
	dryRun := os.Args[2]

	isDryRun, err := strconv.ParseBool(dryRun)
	if err != nil {
		fmt.Println("Only accept boolean value for dryRun.")
		os.Exit(3)
	}

	inidata, err := ini.LoadSources(
		ini.LoadOptions{AllowNonUniqueSections: true},
		buildIniFilePath(wgInterface),
	)
	if err != nil {
		fmt.Printf("Fail to load wireguard config file: %v", err)
		os.Exit(1)
	}

	wgConfig := parseWgConfig(inidata)
	wgConfig.Interface = wgInterface

	execute(buildCreateInterfaceCmd(wgConfig), isDryRun)
	execute(buildWritePrivateKeyCmd(wgConfig), isDryRun)
	execute(buildSetPrivateKeyCmd(wgConfig), isDryRun)

	addPeerCmds := buildAddPeersCmds(wgConfig)
	for _, cmd := range addPeerCmds {
		execute(cmd, isDryRun)
	}

	execute(buildTurnOnInterfaceCmd(wgConfig), isDryRun)
	execute(buildShowWgStatusCmd(wgConfig), isDryRun)

	// Set up a task group, in which all peers that need PersistentKeepalive will be assigned a infinite ping task respectively
	var tasks sync.WaitGroup
	for _, peer := range wgConfig.Peers {
		if needKeepAlive(peer) {
			tasks.Add(1)

			go func() {
				defer tasks.Done()
				fmt.Printf("register peer to keepalive task set: %s\n", peer.Name)
				registerKeepAliveService(&peer, isDryRun)
			}()
		}
	}

	tasks.Wait()
}

func execute(cmd string, isDryRun bool) {
	fmt.Println(cmd)

	if isDryRun {
		return
	} else {
		result := exec.Command("/usr/bin/env", "sh", "-c", cmd)
		stdout, err := result.Output()

		if err != nil {
			fmt.Println(err.Error())
			os.Exit(5)
		}

		fmt.Println(string(stdout))
	}
}

func buildCreateInterfaceCmd(wgConfig WireguardConfig) string {
	return fmt.Sprintf("ifconfig %s create %s", wgConfig.Interface, wgConfig.Address)
}

func buildWritePrivateKeyCmd(wgConfig WireguardConfig) string {
	return fmt.Sprintf("echo \"%s\" > /etc/wg/%s", wgConfig.PrivateKey, wgConfig.Interface)
}

func buildSetPrivateKeyCmd(wgConfig WireguardConfig) string {
	return fmt.Sprintf("wgconfig %s set private-key /etc/wg/%s", wgConfig.Interface, wgConfig.Interface)
}

func buildAddPeersCmds(wgConfig WireguardConfig) []string {
	var cmds []string

	for _, peer := range wgConfig.Peers {
		cmds = append(cmds, fmt.Sprintf("wgconfig %s add peer %s %s --allowed-ips=%s --endpoint=%s", wgConfig.Interface, peer.Name, peer.PublicKey, peer.AllowedIPs, peer.Endpoint))
	}

	return cmds
}

func buildTurnOnInterfaceCmd(wgConfig WireguardConfig) string {
	return fmt.Sprintf("ifconfig %s up", wgConfig.Interface)
}

func buildShowWgStatusCmd(wgConfig WireguardConfig) string {
	return fmt.Sprintf("wgconfig %s", wgConfig.Interface)
}

func parseWgConfig(inidata *ini.File) WireguardConfig {
	wgConfig := WireguardConfig{}
	var peers []Peer

	sections := inidata.Sections()
	for _, section := range sections {
		sectionName := section.Name()
		if sectionName == "Interface" {
			wgConfig.Address = section.Key("Address").String()
			wgConfig.PrivateKey = section.Key("PrivateKey").String()
		} else if section.Name() == "Peer" {
			peer := Peer{
				PublicKey:  section.Key("PublicKey").String(),
				AllowedIPs: section.Key("AllowedIPs").String(),
				Endpoint:   section.Key("Endpoint").String(),
				Name:       section.Key("Name").String(),
				PingTarget: section.Key("PingTarget").String(),
			}
			pka, err := section.Key("PersistentKeepalive").Uint()
			if err != nil {
				fmt.Printf("failed to read PersistentKeepalive as uint: %s\n", err)
				peer.PersistentKeepalive = 0
			} else {
				peer.PersistentKeepalive = uint32(pka)
			}

			peers = append(peers, peer)
		}
	}

	wgConfig.Peers = peers

	return wgConfig
}

func needKeepAlive(peer Peer) bool {
	return peer.PersistentKeepalive != 0 && len(peer.PingTarget) > 0
}

func buildIniFilePath(wgInterface string) string {
	return fmt.Sprintf("/etc/wireguard/%s.conf", wgInterface)
}
