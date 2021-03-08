package database

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/gazza7205/go-traffic-test/pkg/util"
	_ "github.com/go-sql-driver/mysql"
	log "github.com/sirupsen/logrus"
)

//CreateMySQLDatabase creates the MySQL OTK database
func CreateMySQLDatabase(username string, password string, host string, port string, database string, version string, demo bool, databaseType string, gateway string) error {
	db, err := sql.Open("mysql", username+":"+password+"@tcp("+host+":"+port+")/")
	util.ErrorCheck(err)

	// close connection when queries are finished.
	defer db.Close()
	err = PingDB(db)
	if err != nil {
		return err
	}
	// query all data
	log.Print("Attempting database install for " + gateway)
	db.Begin()

	_, err = db.Exec("CREATE DATABASE " + database + ";")
	_, err = db.Exec("USE " + database + ";")
	util.ErrorCheck(err)

	otkdb, err := ioutil.ReadFile("./solutionkits/otk/solutionkit/" + version + "/database_scripts/mysql/otk_db_schema.sql")
	util.ErrorCheck(err)

	ExecQueryFromFile(db, otkdb)

	if demo {
		log.Print("Populating test data on " + gateway)
		otksampledata, err := ioutil.ReadFile("./solutionkits/otk/solutionkit/" + version + "/database_scripts/mysql/otk_db_testdata.sql")
		util.ErrorCheck(err)
		ExecQueryFromFile(db, otksampledata)
	}

	db.Close()
	return nil

}

//CreateOTKUser creates a database user for the OTK connection, this ensures root isn't used for the OTK connections.
func CreateOTKUser(username string, password string, host string, port string, databaseName string) error {
	db, err := sql.Open("mysql", username+":"+password+"@tcp("+host+":"+port+")/")
	util.ErrorCheck(err)

	// close connection when queries are finished.
	defer db.Close()
	err = PingDB(db)
	if err != nil {
		return err
	}

	log.Println("Attempting to create OTK Database")
	db.Begin()
	_, err = db.Exec("CREATE DATABASE " + databaseName + ";")

	// log.Print("Attempting to create OTK User")
	// _, err = db.Exec("GRANT ALL PRIVILEGES ON otk_db.* TO '" + username + "'@'%' IDENTIFIED BY '" + password + "'; FLUSH PRIVILEGES;"
	return nil
}

//ExecQueryFromFile - Executes multiple queries from file
func ExecQueryFromFile(db *sql.DB, raw []byte) {
	queries := strings.Split(string(raw), ";")
	for _, query := range queries {
		if len(strings.TrimSpace(query)) != 0 {
			_, err := db.Exec(query)
			util.ErrorCheck(err)
			if err != nil {
				fmt.Printf("%v", len(query))
			}
		}

	}

}

// PingDB - check database reachability
func PingDB(db *sql.DB) error {
	err := db.Ping()
	return err
}
