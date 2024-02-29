package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)



func main() {
    // Connect to the database
   
    db, err := sql.Open("postgres", "dummy")
    if err != nil {
        panic(err)
    }
    defer db.Close()

    // Drop the table if it exists
    _, err = db.Exec("DROP TABLE IF EXISTS encrypted_files")
    if err != nil {
        panic(err)
    }

    // Create the table
    _, err = db.Exec(`CREATE TABLE encrypted_files (
        id SERIAL PRIMARY KEY,
        uuid UUID UNIQUE NOT NULL,
        filename VARCHAR(255) NOT NULL,
        data BYTEA NOT NULL
    )`)
    if err != nil {
        panic(err)
    }

    fmt.Println("Table 'encrypted_files' has been overridden successfully.")
}
