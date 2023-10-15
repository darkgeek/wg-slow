package main

import (
	"fmt"
	"time"
)

func registerKeepAliveService(peer *Peer, isDryRun bool) {
	for {
		time.Sleep(time.Duration(peer.PersistentKeepalive) * time.Second)
		execute(buildPingCmd(peer), isDryRun)
	}
}

func buildPingCmd(peer *Peer) string {
	return fmt.Sprintf("ping -c 1 %s", peer.PingTarget)
}
