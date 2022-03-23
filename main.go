package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v4/pgxpool"
	"io"
	"net/http"
	"os"
	"strings"
)

var databasePool *pgxpool.Pool

type Response struct {
	Success bool   `json:"success"`
	Cause   string `json:"cause,omitempty"`
	Object  string `json:"object,omitempty"`
}

type RegisterFormInfo struct {
	Username string
	Password string
}

func internalServerErrorResponse(w http.ResponseWriter) {
	finalStruct := &Response{
		false,
		"Internal Server Error",
		"",
	}
	finalResponse, _ := json.Marshal(finalStruct)
	w.WriteHeader(500)
	io.WriteString(w, string(finalResponse))
}

func generateResponse(success bool, cause string, obj string) string {
	finalStruct := &Response{
		success,
		cause,
		obj,
	}
	finalResponse, _ := json.Marshal(finalStruct)
	return string(finalResponse)
}

func registerAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		io.WriteString(w, generateResponse(false, "Invalid Method", ""))
		return
	}
	details := RegisterFormInfo{
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
	}
	if details.Username == "" || details.Password == "" {

	}

	var res string
	err := databasePool.QueryRow(context.Background(), "select 'Hello, world!'").Scan(&res)
	if err != nil {
		internalServerErrorResponse(w)
		return
	}

	io.WriteString(w, generateResponse(
		true,
		"",
		res),
	)
}

func loadEnv() {
	dat, err := os.ReadFile(".env")
	if err != nil {
		println("Could not read .env file")
		return
	}
	contents := string(dat)
	lines := strings.Split(contents, "\n")
	for i, line := range lines {
		firstEquals := strings.Index(line, "=")
		if firstEquals == -1 {
			fmt.Printf("Invalid entry on line %d: No \"=\" found\n", i+1)
			continue
		}
		runes := []rune(line)
		key := string(runes[0:firstEquals])
		value := string(runes[firstEquals+1:])
		_ = os.Setenv(key, value)
	}
}

func main() {
	loadEnv()
	dbpool, err := pgxpool.Connect(context.Background(), os.Getenv("DATABASE_URL"))
	databasePool = dbpool
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not connect to database: %v\n", err)
		os.Exit(1)
	}
	defer dbpool.Close()
	http.HandleFunc("/api/register", registerAccount)

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		io.WriteString(os.Stderr, "Could not start server!")
		return
	}
}
