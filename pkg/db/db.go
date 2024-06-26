package db

import (
    "database/sql"
    "log"
    _ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func InitDB(dataSourceName string) {
    var err error
    DB, err = sql.Open("sqlite3", dataSourceName)
    if err != nil {
        log.Fatalf("Error opening database: %v\n", err)
    }
    if err = DB.Ping(); err != nil {
        log.Fatalf("Error connecting to the database: %v\n", err)
    }
    log.Println("Database connection established")
}
