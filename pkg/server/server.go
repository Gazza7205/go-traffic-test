package server

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"

	"github.com/gazza7205/go-traffic-test/pkg/l7"
	"github.com/gazza7205/go-traffic-test/pkg/manager"
	"github.com/gazza7205/go-traffic-test/pkg/util"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

//PageVars variables that get rendered in HTML
type PageVars struct {
	Title                 string
	AvailableSolutionKits string
	Gateways              string
}

func render(w http.ResponseWriter, tmpl string, pageVars PageVars) {

	tmpl = fmt.Sprintf("static/templates/%s", tmpl) // prefix the name passed in with templates/
	t, err := template.ParseFiles(tmpl)             //parse the template file held in the templates folder

	if err != nil { // if there is an error
		log.Print("template parsing error: ", err) // log it
	}

	err = t.Execute(w, pageVars) //execute the template and pass in the variables to fill the gaps

	if err != nil { // if there is an error
		log.Print("template executing error: ", err) //log it
	}
}

//list available solution kits
func solutionkits(w http.ResponseWriter, r *http.Request) {
	resp := l7.ListSolutionKits()
	w.Header().Add("Content-Type", "application/json")
	w.Write([]byte(resp))
}

//manage gateways
func gateways(w http.ResponseWriter, r *http.Request) {
	gateways := manager.ListInstalledSolutionKits()
	for g := range gateways {
		gateways[g].Username = ""
		gateways[g].Password = ""
		for kit := range gateways[g].Kits {
			if gateways[g].Kits[kit].Database != nil {
				gateways[g].Kits[kit].Database = nil
			}
		}
	}

	out, err := json.Marshal(gateways)
	if err != nil {
		util.ErrorCheck(err)
	}
	w.Header().Add("Content-Type", "application/json")

	w.Write([]byte(out))
}

//Home renders home page
func Home(w http.ResponseWriter, req *http.Request) {
	pageVars := PageVars{
		Title: "Solution Kit Manager",
	}

	render(w, "home.html", pageVars)
}

//Start - starts server, takes in port string and mux router
func Start(port string) {
	router := mux.NewRouter()

	//Handle static files
	router.PathPrefix("/static").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	//UI Handler
	router.HandleFunc("/", Home)

	//API Routes
	router.HandleFunc("/api/v1/solutionkits", solutionkits)
	router.HandleFunc("/api/v1/gateways", gateways)
	//router.HandleFunc("/ws", InstallSolutionKit)

	//Start server
	log.Println("starting server on: " + port)
	log.Fatal(http.ListenAndServe(port, router))
}
