package l7

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

//AvailableSolutionKit json structure
type AvailableSolutionKit struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
}

//Gateway struct
type Gateway struct {
	Name        string   `json:"name"`
	Hostname    string   `json:"hostname"`
	Username    string   `json:"username,omitempty"`
	Password    string   `json:"password,omitempty"`
	Port        string   `json:"port"`
	Designation string   `json:"designation"`
	DependsOn   []string `json:"depends_on"`
	Portal      *Portal  `json:"portal"`
	Kits        []Kit    `json:"kits"`
	IsReachable bool     `json:"isReachable"`
}

//Kit struct
type Kit struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Installed bool      `json:"installed"`
	Status    string    `json:"status,omitempty"`
	Database  *Database `json:"database,omitempty"`
}

//Database struct
type Database struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Hostname string `json:"hostname"`
	Name     string `json:"name"`
	Port     string `json:"port"`
	Type     string `json:"type"`
	Demo     bool   `json:"demo"`
}

//Portal struct
type Portal struct {
	Enroll   bool   `json:"enroll"`
	TenantID string `json:"tenantId"`
	Proxy    struct {
		Name              string `json:"name"`
		APIDeploymentType string `json:"apiDeploymentType"`
		KeyDeploymentType string `json:"keyDeploymentType"`
	} `json:"proxy"`
	Pssg struct {
		Host         string `json:"host"`
		Port         string `json:"port"`
		APIKey       string `json:"apiKey"`
		SharedSecret string `json:"sharedSecret"`
	} `json:"pssg"`
}

//ListGateways from meta file
func ListGateways() []Gateway {
	data, err := ioutil.ReadFile("./gateway-meta.json")
	if err != nil {
		log.Print(err)
	}

	var gateways []Gateway

	err = json.Unmarshal([]byte(data), &gateways)
	if err != nil {
		log.Println("error:", err)
	}

	return gateways
}

//GetGateway from config by name
func GetGateway(name string) Gateway {
	data, err := ioutil.ReadFile("./gateway-meta.json")
	if err != nil {
		log.Print(err)
	}

	var gateways []Gateway
	//var gateway Gateway

	err = json.Unmarshal([]byte(data), &gateways)
	if err != nil {
		log.Println("error:", err)
	}

	for _, gateway := range gateways {
		if gateway.Name == name {
			return gateway
		}
	}

	return Gateway{}
}

//ListSolutionKits available
func ListSolutionKits() string {
	data, err := ioutil.ReadFile("./solutionkits/meta.json")
	if err != nil {
		log.Print(err)
	}
	return string(data)
}

//UpdateGatewayMeta related to installed solution kits
func UpdateGatewayMeta(gateway Gateway, solutionkit string, version string) Gateway {
	match := 0
	for kit := range gateway.Kits {
		if gateway.Kits[kit].Name == solutionkit {
			gateway.Kits[kit].Installed = true
			match++
		} else if solutionkit == "" {
			gateway.Kits[kit].Installed = false
			match++
		}
	}

	if match == 0 {
		gateway.Kits = append(gateway.Kits, Kit{Name: solutionkit, Version: version, Installed: true})
	}
	return gateway
}

//UpdateGatewayStatus solution kit
func UpdateGatewayStatus(name string, solutionKit string, status string) {
	gateways := ListGateways()

	for gateway := range gateways {
		if gateways[gateway].Name == name {
			for kit := range gateways[gateway].Kits {
				if gateways[gateway].Kits[kit].Name == solutionKit {
					gateways[gateway].Kits[kit].Status = status
				}
			}
		}
	}
	file, _ := json.MarshalIndent(gateways, "", " ")
	_ = ioutil.WriteFile("./gateway-meta.json", file, 0644)
}
