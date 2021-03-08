package restman

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gazza7205/go-traffic-test/pkg/l7"
	"github.com/gazza7205/go-traffic-test/pkg/util"
	log "github.com/sirupsen/logrus"
)

//List XML struct
type List struct {
	XMLName   xml.Name `xml:"List"`
	L7        string   `xml:"l7,attr"`
	Name      string   `xml:"Name"`
	Type      string   `xml:"Type"`
	TimeStamp string   `xml:"TimeStamp"`
	Link      []struct {
		Rel string `xml:"rel,attr"`
		URI string `xml:"uri,attr"`
	} `xml:"Link"`
	Item []Item `xml:"Item"`
}

//Item l7
type Item struct {
	Name      string `xml:"Name"`
	ID        string `xml:"Id"`
	Type      string `xml:"Type"`
	TimeStamp string `xml:"TimeStamp"`
	Link      struct {
		Rel string `xml:"rel,attr"`
		URI string `xml:"uri,attr"`
	} `xml:"Link"`
	Resource struct {
		SolutionKit struct {
			ID                 string `xml:"id,attr"`
			Version            string `xml:"version,attr"`
			Name               string `xml:"Name"`
			SolutionKitGUID    string `xml:"SolutionKitGuid"`
			SolutionKitVersion string `xml:"SolutionKitVersion"`
			Properties         struct {
				Property []struct {
					Key         string `xml:"key,attr"`
					StringValue string `xml:"StringValue"`
				} `xml:"Property"`
			} `xml:"Properties"`
			Mappings                   string `xml:"Mappings"`
			LastUpdateTime             string `xml:"LastUpdateTime"`
			UninstallBundle            string `xml:"UninstallBundle"`
			EntityOwnershipDescriptors struct {
				EntityOwnershipDescriptor []struct {
					ID           string `xml:"id,attr"`
					EntityID     string `xml:"EntityId"`
					EntityType   string `xml:"EntityType"`
					ReadOnly     string `xml:"ReadOnly"`
					VersionStamp string `xml:"VersionStamp"`
				} `xml:"EntityOwnershipDescriptor"`
			} `xml:"EntityOwnershipDescriptors"`
		} `xml:"SolutionKit"`
	} `xml:"Resource"`
}

//JDBCConnection represents a JDBC connection object
type JDBCConnection struct {
	XMLName    xml.Name
	Version    string `xml:"version,attr"`
	Name       string `xml:"Name"`
	Enabled    string `xml:"Enabled"`
	Properties struct {
		Property []struct {
			Key          string `xml:"key,attr"`
			IntegerValue string `xml:"IntegerValue"`
		} `xml:"Property"`
	} `xml:"Properties"`
	Extension struct {
		DriverClass          string `xml:"DriverClass"`
		JdbcURL              string `xml:"JdbcUrl"`
		ConnectionProperties struct {
			Property []struct {
				Key         string `xml:"key,attr"`
				StringValue string `xml:"StringValue"`
			} `xml:"Property"`
		} `xml:"ConnectionProperties"`
	} `xml:"Extension"`
}

//CassandraConnection represents a Cassandra connection Object
type CassandraConnection struct {
	XMLName      xml.Name
	Name         string `xml:"Name"`
	Keyspace     string `xml:"Keyspace"`
	ContactPoint string `xml:"ContactPoint"`
	Port         string `xml:"Port"`
	Username     string `xml:"Username"`
	Compression  string `xml:"Compression"`
	Ssl          string `xml:"Ssl"`
	Enabled      string `xml:"Enabled"`
	Properties   string `xml:"Properties"`
}

//TrustedCertificate Restman Ref
type TrustedCertificate struct {
	XMLName         xml.Name
	Name            string `xml:"Name"`
	CertificateData struct {
		IssuerName  string `xml:"IssuerName"`
		SubjectName string `xml:"SubjectName"`
		Encoded     string `xml:"Encoded"`
	} `xml:"CertificateData"`
	Properties struct {
		Property []struct {
			Key          string `xml:"key,attr"`
			BooleanValue string `xml:"BooleanValue"`
		} `xml:"Property"`
	} `xml:"Properties"`
}

//IdentityProvider layer7
type IdentityProvider struct {
	XMLName              xml.Name
	Version              string `xml:"version,attr"`
	Name                 string `xml:"Name"`
	IdentityProviderType string `xml:"IdentityProviderType"`
	Properties           struct {
		Property []struct {
			Key          string `xml:"key,attr"`
			BooleanValue string `xml:"BooleanValue"`
		} `xml:"Property"`
	} `xml:"Properties"`
}

//User layer7 Gateway User
type User struct {
	XMLName    xml.Name
	Version    string `xml:"version,attr"`
	ProviderID string `xml:"providerId,attr"`
	Login      string `xml:"Login"`
	FirstName  string `xml:"FirstName"`
	LastName   string `xml:"LastName"`
	Email      string `xml:"Email"`
	SubjectDn  string `xml:"SubjectDn"`
	Properties struct {
		Property []struct {
			Key          string `xml:"key,attr"`
			LongValue    string `xml:"LongValue,omitempty"`
			BooleanValue string `xml:"BooleanValue,omitempty"`
			StringValue  string `xml:"StringValue,omitempty"`
		} `xml:"Property"`
	} `xml:"Properties"`
}

//CertificateData user certificate
type CertificateData struct {
	XMLName xml.Name
	Version string `xml:"version,attr"`
	Encoded string `xml:"Encoded"`
}

//Bundle for the L7 Gateway
type Bundle struct {
	XMLName    xml.Name
	References struct {
		Item []struct {
			Name     string `xml:"Name"`
			ID       string `xml:"Id"`
			Type     string `xml:"Type"`
			Resource *struct {
				Folder *struct {
					ID       string `xml:"id,attr,omitempty"`
					FolderID string `xml:"folderId,attr,omitempty"`
					Name     string `xml:"Name,omitempty"`
				} `xml:"Folder"`
				Policy *struct {
					Text         string `xml:",chardata"`
					GUID         string `xml:"guid,attr"`
					ID           string `xml:"id,attr"`
					PolicyDetail struct {
						Text       string `xml:",chardata"`
						FolderID   string `xml:"folderId,attr"`
						GUID       string `xml:"guid,attr"`
						ID         string `xml:"id,attr"`
						Name       string `xml:"Name"`
						PolicyType string `xml:"PolicyType"`
					} `xml:"PolicyDetail"`
					Resources *struct {
						ResourceSet *struct {
							Tag      string `xml:"tag,attr"`
							Resource struct {
								Text string `xml:",chardata"`
								Type string `xml:"type,attr"`
							} `xml:"Resource"`
						} `xml:"ResourceSet"`
					} `xml:"Resources"`
				} `xml:"Policy"`
			} `xml:"Resource"`
		} `xml:"Item"`
	} `xml:"References"`
	Mappings struct {
		Mapping []struct {
			Action     string `xml:"action,attr"`
			SrcID      string `xml:"srcId,attr"`
			Type       string `xml:"type,attr"`
			Properties struct {
				Property []struct {
					Key         string `xml:"key,attr"`
					StringValue string `xml:"StringValue"`
				} `xml:"Property"`
			} `xml:"Properties"`
		} `xml:"Mapping"`
	} `xml:"Mappings"`
}

//RestGetSolutionKits - queries Restman for Solution Kits that this installer provides
func RestGetSolutionKits(hostname string, port string, username string, password string) []byte {
	requestURL := "https://" + hostname + ":" + port + "/restman/1.0/solutionKits?name=OAuthSolutionKit&name=Layer7%20Precision%20API%20Monitoring"
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("GET", requestURL, nil)

	req.SetBasicAuth(username, password)
	resp, err := client.Do(req)

	if err != nil {
		util.ErrorCheck(err)
	}

	bodyText, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		util.ErrorCheck(err)
	}
	return bodyText
}

//RestInstallSolutionKit - Install a solukit into a target API Gateway
func RestInstallSolutionKit(solutionKit l7.Kit, gateway l7.Gateway) { // version string, host string, port string, username string, password string, name string, designation string, solutionkit string, databaseType string) {

	baseURL := "https://" + gateway.Hostname + ":" + gateway.Port
	URL := ""
	//var jdbc = JDBCConnection{}
	if solutionKit.Name == "OAuthSolutionKit" {
		// if databaseType == "mysql" {
		URL = baseURL + "/restman/1.0/jdbcConnections/4432207d16a1b505e8a6ed59993eaa27"
		filePath := "./solutionkits/otk/actions/install/jdbc.xml"

		// } else if databaseType == "cassandra" {
		// 	URL = baseURL + "/restman/1.0/cassandraConnections/c2e0825b2f52dc7819cd6e68893df157"
		// 	filePath = "./solutionkits/otk/actions/install/cassandra.xml"
		// } else {
		// 	ErrorCheck(errors.New("Please specify a database type"))
		// }

		data, err := ioutil.ReadFile(filePath)
		jdbc := JDBCConnection{}
		_ = xml.Unmarshal([]byte(data), &jdbc)
		jdbc.Extension.DriverClass = "com.l7tech.jdbc.mysql.MySQLDriver"
		jdbc.Extension.JdbcURL = "jdbc:mysql://" + solutionKit.Database.Hostname + ":" + solutionKit.Database.Port + "/" + solutionKit.Database.Name
		jdbc.Extension.ConnectionProperties.Property[0].Key = "EnableCancelTimeout"
		jdbc.Extension.ConnectionProperties.Property[0].StringValue = "true"
		jdbc.Extension.ConnectionProperties.Property[1].Key = "user"
		jdbc.Extension.ConnectionProperties.Property[1].StringValue = solutionKit.Database.Username
		jdbc.Extension.ConnectionProperties.Property[2].Key = "password"
		jdbc.Extension.ConnectionProperties.Property[2].StringValue = solutionKit.Database.Password
		jdbcXML, err := xml.Marshal(jdbc)
		if err != nil {
			util.ErrorCheck(err)
		}

		_, err = restCall("PUT", URL, "application/xml", jdbcXML, gateway.Username, gateway.Password, "")

		if err != nil {
			util.ErrorCheck(err)
		}

		baseURL = "https://" + gateway.Hostname + ":" + gateway.Port
		URL = baseURL + "/restman/1.0/solutionKitManagers"

		switch gateway.Designation {
		case "edge":
			//Assertions + Configuration
			installOTKComponent([]string{"b74b063c-5151-4f7d-b4db-71f032cc2d46", "b74b063c-5151-4f7d-b4db-71f032cc2d47"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "1")
			//Shared OAuth Resources
			installOTKComponent([]string{"1f5dcaea-94a9-4bf7-8c9c-5a49be1a6001"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "2")
			//Shared Portal Resources
			installOTKComponent([]string{"0b0f9534-94f4-4cca-a05a-4c9e7776f8a9"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "3")
			//MySQL: Persistence layer - PORTAL ENROLL
			installOTKComponent([]string{"082be2e3-6399-4d51-8aad-a87715364537"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "4")
			//DMZ Components
			installOTKComponent([]string{"1f5dcaea-94a9-4bf7-8c9c-5a49be1a6003"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "5")

			//Post installation tasks
			for _, i := range gateway.DependsOn {
				stsgw := l7.GetGateway(i)
				if gateway.Hostname != "" {
					filePath = "./solutionkits/otk/actions/install/trustedcertificate.xml"
					URL = baseURL + "/restman/1.0/trustedCertificates"
					log.Println(stsgw.Name + " found")
					_, cert := getServerCertificate(stsgw.Hostname, stsgw.Port, filePath)
					_, err = restCall("POST", URL, "application/xml", cert, gateway.Username, gateway.Password, "")

					if err != nil {
						log.Println("Certificate already present on " + gateway.Name)
						util.ErrorCheck(err)
					}

					filePath = "./solutionkits/otk/actions/install/customedge.xml"
					URL = baseURL + "/restman/1.0/bundle"
					bundle := postInstallBundle(filePath, "https://"+stsgw.Hostname+":"+stsgw.Port, "")

					_, err = restCall("PUT", URL, "application/xml", bundle, gateway.Username, gateway.Password, "")
					if err != nil {
						log.Println("Bundle failed to upload")
						util.ErrorCheck(err)
					}

					//Enroll with Portal ???????
					if gateway.Portal.Enroll {
						filePath = "./solutionkits/otk/actions/install/portalselfenroll.install.xml"
						enrollWithPortal(filePath, gateway)
					}

				} else {
					log.Println("STS Gateway not found")
				}
			}

		case "sts":
			//Assertions + Configuration
			installOTKComponent([]string{"b74b063c-5151-4f7d-b4db-71f032cc2d46", "b74b063c-5151-4f7d-b4db-71f032cc2d47"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "1")
			//Shared OAuth Resources
			installOTKComponent([]string{"1f5dcaea-94a9-4bf7-8c9c-5a49be1a6001"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "2")
			//Shared Portal Resources
			installOTKComponent([]string{"0b0f9534-94f4-4cca-a05a-4c9e7776f8a9"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "3")
			//MySQL: Persistence layer
			installOTKComponent([]string{"082be2e3-6399-4d51-8aad-a87715364537"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "4")
			//MySQL: Portal Persistence Layer
			installOTKComponent([]string{"39efbb1d-4c10-4a88-9774-ece574845c94"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "5")
			//OVP + DMZ Components
			installOTKComponent([]string{"1f5dcaea-94a9-4bf7-8c9c-5a49be1a6004", "1f5dcaea-94a9-4bf7-8c9c-5a49be1a6008"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "6")
			//Internal Persistence Assertions
			installOTKComponent([]string{"1f5dcaea-94a9-4bf7-8c9c-5a49be1a6005", "1f5dcaea-94a9-4bf7-8c9c-5a49be1a6006", "1f5dcaea-94a9-4bf7-8c9c-5a49be1a6007", "8918de1b-d0ac-46c6-83a2-7ba4a0e5c1b0"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "7")

			//POST installation tasks

			//Import Certificate and bundle
			for _, i := range gateway.DependsOn {
				edgegw := l7.GetGateway(i)
				if gateway.Hostname != "" {
					filePath = "./solutionkits/otk/actions/install/trustedcertificate.xml"
					URL = baseURL + "/restman/1.0/trustedCertificates"
					log.Println(edgegw.Name + " found")
					x509, cert := getServerCertificate(edgegw.Hostname, edgegw.Port, filePath)
					_, err = restCall("POST", URL, "application/xml", cert, gateway.Username, gateway.Password, "")

					if err != nil {
						log.Println("Certificate already present on " + gateway.Name)
						util.ErrorCheck(err)
					} else {
						log.Println(edgegw.Name + " certificate loaded onto " + gateway.Name)
					}

					//Create FIP
					filePath = "./solutionkits/otk/actions/install/identityprovider.xml"
					URL = baseURL + "/restman/1.0/identityProviders"
					l7Fip := createFederatedIdentityProvider(filePath, "OTK FIP")
					l7Resp := Item{}
					resp, err := restCall("POST", URL, "application/xml", l7Fip, gateway.Username, gateway.Password, "")

					//Create FIP User
					_ = xml.Unmarshal(resp, &l7Resp)
					fIPId := l7Resp.ID
					filePath = "./solutionkits/otk/actions/install/user.xml"
					URL = baseURL + "/restman/1.0/identityProviders/" + fIPId + "/users"
					l7User := createFederatedUser(filePath, fIPId, x509.Subject.CommonName)
					l7Resp = Item{}
					resp, err = restCall("POST", URL, "application/xml", l7User, gateway.Username, gateway.Password, "")
					if err != nil {
						util.ErrorCheck(err)
					}
					//Create FIP User Certificate
					_ = xml.Unmarshal(resp, &l7Resp)
					URL = baseURL + "/restman/1.0/identityProviders/" + fIPId + "/users/" + l7Resp.ID + "/certificate"
					filePath = "./solutionkits/otk/actions/install/usercertificate.xml"
					l7UserCert := createFederatedUserCertificate(filePath, x509)
					resp, err = restCall("PUT", URL, "application/xml", l7UserCert, gateway.Username, gateway.Password, "")
					if err != nil {
						util.ErrorCheck(err)
					}
					//filePath = "./solutionkits/otk/actions/install/usercertificate.xml"
					_ = xml.Unmarshal(resp, &l7Resp)
					//Upload STS Bundle
					filePath = "./solutionkits/otk/actions/install/customsts.xml"
					URL = baseURL + "/restman/1.0/bundle"
					bundle := postInstallBundle(filePath, "https://"+edgegw.Hostname+":"+edgegw.Port, fIPId)

					_, err = restCall("PUT", URL, "application/xml", bundle, gateway.Username, gateway.Password, "")
					if err != nil {
						log.Println("Bundle failed to upload")
						util.ErrorCheck(err)
					}
				} else {
					log.Println("STS Gateway not found")
				}
			}
		default:
			//Performing Step 1
			installOTKComponent([]string{"b74b063c-5151-4f7d-b4db-71f032cc2d46", "b74b063c-5151-4f7d-b4db-71f032cc2d47"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "1")
			//2
			installOTKComponent([]string{"1f5dcaea-94a9-4bf7-8c9c-5a49be1a6001"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "2")
			//3
			installOTKComponent([]string{"0b0f9534-94f4-4cca-a05a-4c9e7776f8a9"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "3")
			//4
			installOTKComponent([]string{"082be2e3-6399-4d51-8aad-a87715364537"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "4")
			//5
			installOTKComponent([]string{"39efbb1d-4c10-4a88-9774-ece574845c94", "1f5dcaea-94a9-4bf7-8c9c-5a49be1a6003"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "5")
			//6
			installOTKComponent([]string{"1f5dcaea-94a9-4bf7-8c9c-5a49be1a6004", "1f5dcaea-94a9-4bf7-8c9c-5a49be1a6008"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "6")
			//7
			installOTKComponent([]string{"1f5dcaea-94a9-4bf7-8c9c-5a49be1a6005", "1f5dcaea-94a9-4bf7-8c9c-5a49be1a6006", "1f5dcaea-94a9-4bf7-8c9c-5a49be1a6007", "8918de1b-d0ac-46c6-83a2-7ba4a0e5c1b0"}, solutionKit.Version, URL, gateway.Username, gateway.Password, gateway.Name, "7")
		}
	} else {
		URL = baseURL + "/restman/1.0/solutionKitManagers"
		payload := &bytes.Buffer{}
		writer := multipart.NewWriter(payload)
		solutionKit.Name = strings.ReplaceAll(solutionKit.Name, " ", "")
		file, errFile := os.Open("./solutionkits/" + solutionKit.Name + "/solutionkit/" + solutionKit.Version + "/" + solutionKit.Name + "-" + solutionKit.Version + ".sskar")
		defer file.Close()
		part,
			errFile := writer.CreateFormFile("file", filepath.Base("./solutionkits/"+solutionKit.Name+"/solutionkit/"+solutionKit.Version+"/"+solutionKit.Name+"-"+solutionKit.Version+".sskar"))
		_, errFile = io.Copy(part, file)
		if errFile != nil {
			util.ErrorCheck(errFile)
		}

		err := writer.Close()
		if err != nil {
			util.ErrorCheck(err)
		}

		_, err = restCall("POST", URL, writer.FormDataContentType(), payload.Bytes(), gateway.Username, gateway.Password, "")
		if err != nil {
			util.ErrorCheck(err)
		} else {
			log.Println(solutionKit.Name + " installed on " + gateway.Name)
		}
	}
}

func restCall(method string, URL string, contentType string, data []byte, username string, password string, accessToken string) ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(method, URL, strings.NewReader(string(data)))

	req.Header.Set("Content-Type", contentType)

	if accessToken == "" {
		req.SetBasicAuth(username, password)
	} else {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	}

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return []byte{}, errors.New(resp.Status)
	}

	defer resp.Body.Close()

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	return bytes, nil
}

//TestGatewayConnection calls the Restman docs page, checks enabled and correct credentials
func TestGatewayConnection(host string, port string, username string, password string) error {
	URL := "https://" + host + ":" + port + "/ssg/ping"

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}

	req, err := http.NewRequest("GET", URL, nil)
	req.SetBasicAuth(username, password)

	_, err = client.Do(req)
	if err != nil {
		return err
	}

	return err
}

func installOTKComponent(id []string, version string, URL string, username string, password string, name string, step string) {
	payload := &bytes.Buffer{}
	writer := multipart.NewWriter(payload)

	file, errFile := os.Open("./solutionkits/otk/solutionkit/" + version + "/OAuthSolutionKit-" + version + ".sskar")
	defer file.Close()
	part,
		errFile := writer.CreateFormFile("file", filepath.Base("./solutionkits/otk/solutionkit/"+version+"/OAuthSolutionKit-"+version+".sskar"))
	_, errFile = io.Copy(part, file)
	if errFile != nil {
		util.ErrorCheck(errFile)
	}

	for _, i := range id {
		_ = writer.WriteField("solutionKitSelect", i)

	}

	err := writer.Close()
	if err != nil {
		util.ErrorCheck(err)
	}

	log.Println("Performing install step " + step + " on " + name)
	_, err = restCall("POST", URL, writer.FormDataContentType(), payload.Bytes(), username, password, "")
	if err != nil {
		util.ErrorCheck(err)
	} else {
		l7.UpdateGatewayStatus(name, "OAuthSolutionKit", step)
		log.Println("Step " + step + " complete on " + name)
	}
}

func getServerCertificate(hostname string, port string, filePath string) (*x509.Certificate, []byte) {

	conn, err := tls.Dial("tcp", hostname+":"+port, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		panic("failed to connect: " + err.Error())
	}
	// Get the ConnectionState struct as that's the one which gives us x509.Certificate struct
	cert := conn.ConnectionState().PeerCertificates[0]

	conn.Close()
	certRaw := base64.StdEncoding.EncodeToString([]byte(cert.Raw))
	data, err := ioutil.ReadFile(filePath)
	l7Cert := TrustedCertificate{}
	_ = xml.Unmarshal([]byte(data), &l7Cert)
	l7Cert.Name = cert.Subject.CommonName
	l7Cert.CertificateData.Encoded = string(certRaw)
	l7Cert.CertificateData.IssuerName = cert.Issuer.CommonName
	l7Cert.CertificateData.SubjectName = cert.Subject.CommonName
	l7Cert.Properties.Property[0].Key = "revocationCheckingEnabled"
	l7Cert.Properties.Property[0].BooleanValue = "true"
	l7Cert.Properties.Property[1].Key = "trustAnchor"
	l7Cert.Properties.Property[1].BooleanValue = "true"
	l7Cert.Properties.Property[2].Key = "trustedAsSamlAttestingEntity"
	l7Cert.Properties.Property[2].BooleanValue = "false"
	l7Cert.Properties.Property[3].Key = "trustedAsSamlIssuer"
	l7Cert.Properties.Property[3].BooleanValue = "false"
	l7Cert.Properties.Property[4].Key = "trustedForSigningClientCerts"
	l7Cert.Properties.Property[4].BooleanValue = "false"
	l7Cert.Properties.Property[5].Key = "trustedForSigningServerCerts"
	l7Cert.Properties.Property[5].BooleanValue = "true"
	l7Cert.Properties.Property[6].Key = "trustedForSsl"
	l7Cert.Properties.Property[6].BooleanValue = "true"
	l7Cert.Properties.Property[7].Key = "verifyHostname"
	l7Cert.Properties.Property[7].BooleanValue = "false"
	l7CertXML, err := xml.Marshal(l7Cert)
	if err != nil {
		util.ErrorCheck(err)
	}
	//return string(certRaw) cert.Subject.SerialNumber
	return cert, l7CertXML

}

func createFederatedIdentityProvider(filePath string, name string) []byte {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		util.ErrorCheck(err)
	}
	l7Fip := IdentityProvider{}
	_ = xml.Unmarshal([]byte(data), &l7Fip)
	l7Fip.Name = name
	l7FipXML, _ := xml.Marshal(l7Fip)

	return l7FipXML
}

func createFederatedUser(filePath string, providerID string, login string) []byte {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		util.ErrorCheck(err)
	}
	l7User := User{}

	_ = xml.Unmarshal([]byte(data), &l7User)
	l7User.ProviderID = providerID
	l7User.Login = login
	l7User.SubjectDn = "CN=" + login

	l7User.Properties.Property[2].StringValue = login
	l7UserXML, _ := xml.Marshal(l7User)
	//log.Println(string(l7UserXML))
	return l7UserXML
}

func createFederatedUserCertificate(filePath string, certificate *x509.Certificate) []byte {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		util.ErrorCheck(err)
	}
	l7UserCertificate := CertificateData{}

	_ = xml.Unmarshal([]byte(data), &l7UserCertificate)
	certRaw := base64.StdEncoding.EncodeToString([]byte(certificate.Raw))
	l7UserCertificate.Encoded = string(certRaw)
	// l7UserCertificate.IssuerName = certificate.Issuer.CommonName
	// l7UserCertificate.SubjectName = certificate.Subject.CommonName
	// l7UserCertificate.SerialNumber = certificate.Subject.SerialNumber
	l7UserXML, _ := xml.Marshal(l7UserCertificate)

	return l7UserXML
	//return []byte{}
}

func postInstallBundle(filePath string, hostname string, fIPId string) []byte {
	data, err := ioutil.ReadFile(filePath)
	l7Bundle := Bundle{}
	_ = xml.Unmarshal([]byte(data), &l7Bundle)

	if err != nil {
		util.ErrorCheck(err)
	}

	for index, i := range l7Bundle.References.Item {
		switch i.Name {
		case "OTK/Customizations/#OTK Storage Configuration", "OTK/Customizations/#OTK OVP Configuration":
			regexp, _ := regexp.Compile(`aHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0Mw==`)
			hostnameb64 := base64.StdEncoding.EncodeToString([]byte(hostname))
			match := regexp.ReplaceAllString(i.Resource.Policy.Resources.ResourceSet.Resource.Text, hostnameb64)
			i.Resource.Policy.Resources.ResourceSet.Resource.Text = match
			l7Bundle.References.Item[index] = i
		case "OTK/Customizations/Tooks/#OTK Client Context Variables", "OTK/Customizations/id_token/#OTK id_token configuration":
			regexp, _ := regexp.Compile(`aHR0cHM6Ly8ke2dhdGV3YXkuY2x1c3Rlci5ob3N0bmFtZX06ODQ0Mw==`)
			hostnameb64 := base64.StdEncoding.EncodeToString([]byte(hostname))
			match := regexp.ReplaceAllString(i.Resource.Policy.Resources.ResourceSet.Resource.Text, hostnameb64)
			i.Resource.Policy.Resources.ResourceSet.Resource.Text = match
			l7Bundle.References.Item[index] = i
		case "OTK/Customizations/authentication/OTK FIP Client Authentication Extension":
			regexp, _ := regexp.Compile(`0000000000000000fffffffffffffffe`)
			match := regexp.ReplaceAllString(i.Resource.Policy.Resources.ResourceSet.Resource.Text, fIPId)
			i.Resource.Policy.Resources.ResourceSet.Resource.Text = match
			l7Bundle.References.Item[index] = i
		}
	}
	l7BundleXML, _ := xml.Marshal(l7Bundle)
	return l7BundleXML
}

func enrollWithPortal(filePath string, gateway l7.Gateway) {

	//AuthResponse from Portal
	type AuthResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}

	type PortalProxy struct {
		Name           string `json:"name,omitempty"`
		DeploymentType string `json:"deploymentType"`
	}

	type ProxyResponse struct {
		UUID             string `json:"uuid"`
		Name             string `json:"name"`
		EnrollmentStatus string `json:"enrollmentStatus"`
		EnrollmentURL    string `json:"enrollmentUrl"`
		DeploymentType   string `json:"deploymentType"`
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		util.ErrorCheck(err)
	}

	_, err = restCall("PUT", "https://"+gateway.Hostname+":"+gateway.Port+"/restman/1.0/bundle", "application/xml", data, gateway.Username, gateway.Password, "")
	if err != nil {
		util.ErrorCheck(err)
	}

	authResponse := AuthResponse{}
	resp, err := restCall("POST", "https://"+gateway.Portal.Pssg.Host+":"+gateway.Portal.Pssg.Port+"/auth/oauth/v2/token", "application/x-www-form-urlencoded", []byte("grant_type=client_credentials&scope=OOB"), gateway.Portal.Pssg.APIKey, gateway.Portal.Pssg.SharedSecret, "")

	err = json.Unmarshal(resp, &authResponse)
	if err != nil {
		log.Println("Failed to retrieve access token")
		util.ErrorCheck(err)
	}

	proxyResponse := ProxyResponse{}
	proxyPayload := PortalProxy{Name: gateway.Portal.Proxy.Name, DeploymentType: gateway.Portal.Proxy.APIDeploymentType}
	data, err = json.Marshal(proxyPayload)
	if err != nil {
		util.ErrorCheck(err)
	}
	resp, err = restCall("POST", "https://"+gateway.Portal.Pssg.Host+":"+gateway.Portal.Pssg.Port+"/"+gateway.Portal.TenantID+"/deployments/1.0/proxies", "application/json", data, gateway.Portal.Pssg.APIKey, gateway.Portal.Pssg.SharedSecret, authResponse.AccessToken)
	if err != nil {
		log.Println("Failed to create proxy")
		util.ErrorCheck(err)
	}
	err = json.Unmarshal(resp, &proxyResponse)
	if err != nil {
		util.ErrorCheck(err)
	}

	//Will fix this later on...

	// appDeploymentType := PortalProxy{DeploymentType: gateway.Portal.Proxy.KeyDeploymentType}
	// data, err = json.Marshal(appDeploymentType)
	// if err != nil {
	// 	util.ErrorCheck(err)
	// }
	// resp, err = restCall("PUT", "https://"+gateway.Portal.Pssg.Host+":"+gateway.Portal.Pssg.Port+"/"+gateway.Portal.TenantID+"/deployments/0.1/proxies/"+proxyResponse.UUID+"/deployment-type/APPLICATION", "application/json", data, gateway.Portal.Pssg.APIKey, gateway.Portal.Pssg.SharedSecret, authResponse.AccessToken)
	// if err != nil {
	// 	log.Println("Failed to update proxy")
	// 	util.ErrorCheck(err)
	// }

	resp, err = restCall("POST", "https://"+gateway.Hostname+":"+gateway.Port+"/portal-self-enroll-service", "application/x-www-form-urlencoded", []byte("url="+url.QueryEscape(proxyResponse.EnrollmentURL)), gateway.Username, gateway.Password, "")
	if err != nil {
		log.Println("Failed to get proxy status")
		util.ErrorCheck(err)
	}
	log.Println(gateway.Name + " successfully enrolled with Portal")
	log.Println(string(resp))

}
