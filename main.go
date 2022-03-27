package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/golang/gddo/httputil/header"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var databasePool *pgxpool.Pool

type Response struct {
	Success bool   `json:"success"`
	Cause   string `json:"cause,omitempty"`
	Object  string `json:"object,omitempty"`
}

type AuthenticationInfo struct {
	Username string
	Password string
}

type NewProjectInfo struct {
	Name        string
	Public      bool
	Description string
}

func enforceValidPassword(password string, w http.ResponseWriter) bool {
	length := len(password)
	if length < 6 || length > 512 {
		sendResponse(w, http.StatusBadRequest, false, "Invalid password", "")
		return false
	}
	return true
}

func enforceValidUsername(username string, w http.ResponseWriter) bool {
	length := len(username)
	if strings.ContainsAny(username, " ") || length < 5 || length > 16 {
		sendResponse(w, http.StatusBadRequest, false, "Invalid username", "")
		return false
	}
	return true
}

func enforceNonEmptyValues(info AuthenticationInfo, w http.ResponseWriter) bool {
	if info.Username == "" || info.Password == "" {
		badRequestErrorResponse(w)
		return false
	}
	return true
}

func enforceMethod(method string, w http.ResponseWriter, r *http.Request) bool {
	if r.Method != method {
		sendResponse(w, http.StatusMethodNotAllowed, false, "Invalid Method", "")
		return false
	}
	return true
}

func badRequestErrorResponse(w http.ResponseWriter) {
	sendResponse(w, http.StatusBadRequest, false, "Invalid Request", "")
}

func internalServerErrorResponse(w http.ResponseWriter) {
	sendResponse(w, http.StatusInternalServerError, false, "Internal Server Error", "")
}

func sendResponse(w http.ResponseWriter, status int, success bool, cause string, obj string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(&Response{
		success,
		cause,
		obj,
	})
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	if r.Header.Get("Content-Type") != "" {
		value, _ := header.ParseValueAndParams(r.Header, "Content-Type")
		if value != "application/json" {
			return false
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&dst)
	if err != nil {
		return false
	}

	//check if there are more json objects in the request
	err = dec.Decode(&struct{}{})
	if err != io.EOF {
		return false
	}

	return true
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

func getUserIdFromJwt(w http.ResponseWriter, r *http.Request) int {
	tokenCookie, err := r.Cookie("jwt")
	if err != nil {
		sendResponse(w, http.StatusUnauthorized, false, "Unauthorized", "")
		return -1
	}

	token, err := jwt.ParseWithClaims(tokenCookie.Value, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err == nil {
		if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
			id, err := strconv.Atoi(claims.Issuer)
			if err == nil {
				return id
			} else {
				badRequestErrorResponse(w)
				return -1
			}
		}
	}
	badRequestErrorResponse(w)
	return -1
}

func createProject(w http.ResponseWriter, r *http.Request) {
	if !enforceMethod(http.MethodPost, w, r) {
		return
	}
	userid := getUserIdFromJwt(w, r)
	var details NewProjectInfo
	decodeSuccessful := decodeJSON(w, r, &details)
	if !decodeSuccessful {
		badRequestErrorResponse(w)
		return
	}
	_, err := databasePool.Exec(context.Background(), "insert into projects (id, owner, name, description, public) values (DEFAULT, $1, $2, $3, $4);", strconv.Itoa(userid), details.Name, details.Description, details.Public)
	if err != nil {
		if strings.Contains(err.Error(), "SQLSTATE 23505") {
			sendResponse(w, http.StatusConflict, false, "Project name already taken", "")
			return
		}
		internalServerErrorResponse(w)
		return
	}

	var id int
	err = databasePool.QueryRow(context.Background(), "select id from projects where name=$1", details.Name).Scan(&id)
	sendResponse(w, http.StatusCreated, true, "", strconv.Itoa(id))
}

func testJwt(w http.ResponseWriter, r *http.Request) {
	if !enforceMethod(http.MethodPost, w, r) {
		return
	}

	userid := getUserIdFromJwt(w, r)
	sendResponse(w, http.StatusOK, true, "", strconv.Itoa(userid))
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	if !enforceMethod(http.MethodPost, w, r) {
		return
	}
	var details AuthenticationInfo
	decodeSuccessful := decodeJSON(w, r, &details)
	if !decodeSuccessful || !enforceValidUsername(details.Username, w) {
		badRequestErrorResponse(w)
		return
	}

	var hashedPassword string
	var userid int
	err := databasePool.QueryRow(context.Background(), "select password_hash, id from users where LOWER(username) = LOWER('"+details.Username+"')").Scan(&hashedPassword, &userid)
	if err != nil {
		println(err.Error())
		badRequestErrorResponse(w)
		return
	}
	if !checkPasswordHash(details.Password, hashedPassword) {
		sendResponse(w, http.StatusBadRequest, false, "Invalid password", "")
		return
	}

	userIdString := strconv.Itoa(userid)
	claims := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.StandardClaims{
		Issuer:    userIdString,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 14).Unix(),
	})

	token, err := claims.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		internalServerErrorResponse(w)
	} else {
		cookie := http.Cookie{
			Name:     "jwt",
			Value:    token,
			HttpOnly: true,
		}
		http.SetCookie(w, &cookie)
		sendResponse(w, http.StatusOK, true, "", "")
	}
}

func registerAccount(w http.ResponseWriter, r *http.Request) {
	if !enforceMethod(http.MethodPost, w, r) {
		return
	}
	var details AuthenticationInfo
	decodeSuccessful := decodeJSON(w, r, &details)
	if !decodeSuccessful {
		badRequestErrorResponse(w)
		return
	}
	if !enforceNonEmptyValues(details, w) || !enforceValidUsername(details.Username, w) || !enforceValidPassword(details.Password, w) {
		return
	}

	hashedPassword, err := hashPassword(details.Password)
	if err != nil {
		internalServerErrorResponse(w)
		return
	}
	_, err = databasePool.Exec(context.Background(), "INSERT INTO users (id, username, password_hash)\nVALUES (DEFAULT, $1, $2);", details.Username, hashedPassword)
	if err != nil {
		//check if the username is a duplicate entry
		if strings.Contains(err.Error(), "SQLSTATE 23505") {
			sendResponse(w, http.StatusConflict, false, "Username already taken", "")
		} else {
			internalServerErrorResponse(w)
		}
		return
	}

	sendResponse(w, http.StatusCreated, true, "", "")
}

func main() {
	loadEnv()
	dbpool, err := pgxpool.Connect(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not connect to database: %v\n", err)
		os.Exit(1)
	}
	databasePool = dbpool
	defer dbpool.Close()

	http.HandleFunc("/api/register", registerAccount)
	http.HandleFunc("/api/login", loginUser)
	http.HandleFunc("/api/testJwt", testJwt)
	http.HandleFunc("/api/projects/create", createProject)

	println("starting server")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		io.WriteString(os.Stderr, "Could not start server!")
		return
	}
}
