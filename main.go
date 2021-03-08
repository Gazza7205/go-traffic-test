package main

import (
	"os"
	"time"

	manager "github.com/gazza7205/go-traffic-test/pkg/manager"
	server "github.com/gazza7205/go-traffic-test/pkg/server"
)

func main() {
	startServer := os.Getenv("startServer")
	//kubernetes := os.Getenv("k8s")
	mode := os.Getenv("mode")

	if mode == "headless" {
		//setup go routine.. run the installer every 60 seconds - make this settable...
		//should also be able to pick up where a previous installation failed.. need to note successfull steps
		go func() {
			for true {
				gateways := manager.ListInstalledSolutionKits()
				for gateway := range gateways {
					for kit := range gateways[gateway].Kits {
						go manager.InstallSolutionKit(gateways[gateway], gateways[gateway].Kits[kit])
					}
				}
				time.Sleep(60 * time.Second)
			}
		}()
	}

	// if kubernetes == "true" {
	// 	go Discover("gateway")
	// }

	if startServer == "true" {
		port := os.Getenv("PORT")
		if port != "" {
			port = ":" + port
		} else {
			port = ":8080"
		}
		server.Start(port)
	}
}
