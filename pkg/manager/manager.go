package manager

import (
	"encoding/json"
	"encoding/xml"
	"io/ioutil"

	"github.com/gazza7205/go-traffic-test/pkg/database"
	"github.com/gazza7205/go-traffic-test/pkg/l7"
	"github.com/gazza7205/go-traffic-test/pkg/restman"
	"github.com/gazza7205/go-traffic-test/pkg/util"
	log "github.com/sirupsen/logrus"
)

//InstallSolutionKit on a target Gateway
func InstallSolutionKit(gateway l7.Gateway, solutionKit l7.Kit) {
	if gateway.IsReachable {
		for s := range gateway.Kits {
			if gateway.Kits[s].Name == solutionKit.Name && gateway.Kits[s].Installed == false {
				if solutionKit.Name == "OAuthSolutionKit" {
					err := database.CreateMySQLDatabase(gateway.Kits[s].Database.Username, gateway.Kits[s].Database.Password, gateway.Kits[s].Database.Hostname, gateway.Kits[s].Database.Port, gateway.Kits[s].Database.Name, solutionKit.Version, gateway.Kits[s].Database.Demo, gateway.Kits[s].Database.Type, gateway.Name)
					util.ErrorCheck(err)
				}
				restman.RestInstallSolutionKit(solutionKit, gateway)
			} else {
				log.Println("Ignoring " + gateway.Kits[s].Name + " on " + gateway.Name)
			}
		}
	} else {
		log.Println(gateway.Name + " is unreachable")
	}
}

//ListInstalledSolutionKits on a target Gateway
func ListInstalledSolutionKits() []l7.Gateway {
	gateways := l7.ListGateways()
	for index, gateway := range gateways {
		err := restman.TestGatewayConnection(gateway.Hostname, gateway.Port, gateway.Username, gateway.Password)

		if err != nil {
			log.Println("Error is: " + err.Error())
			gateways[index].IsReachable = false
			util.ErrorCheck(err)
		} else {
			gateways[index].IsReachable = true

			solutionKits := restman.RestGetSolutionKits(gateway.Hostname, gateway.Port, gateway.Username, gateway.Password)
			list := &restman.List{}
			_ = xml.Unmarshal([]byte(solutionKits), &list)
			if len(list.Item) > 0 {
				for item := range list.Item {
					gateways[index] = l7.UpdateGatewayMeta(gateways[index], list.Item[item].Name, list.Item[item].Resource.SolutionKit.SolutionKitVersion)
				}
			} else {
				gateways[index] = l7.UpdateGatewayMeta(gateways[index], "", "")
			}
		}
	}

	file, _ := json.MarshalIndent(gateways, "", " ")
	_ = ioutil.WriteFile("./gateway-meta.json", file, 0644)

	return gateways
}
