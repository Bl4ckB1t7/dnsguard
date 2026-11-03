package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

type authStore struct {
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(password), err
}

func main() {
	output := flag.String("output", "auth.json", "path to the auth JSON file")
	username := flag.String("username", "admin", "login username")
	flag.Parse()
	if strings.TrimSpace(*username) == "" {
		fmt.Fprintln(os.Stderr, "username must not be empty")
		os.Exit(2)
	}
	password, err := readPassword("New password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read password: %v\n", err)
		os.Exit(1)
	}
	confirmation, err := readPassword("Confirm password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read confirmation: %v\n", err)
		os.Exit(1)
	}
	if password == "" || password != confirmation {
		fmt.Fprintln(os.Stderr, "passwords are empty or do not match")
		os.Exit(2)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash password: %v\n", err)
		os.Exit(1)
	}
	content, err := json.MarshalIndent(authStore{Username: *username, PasswordHash: string(hash)}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode auth file: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "create auth directory: %v\n", err)
		os.Exit(1)
	}
	temporary, err := os.CreateTemp(filepath.Dir(*output), ".auth-*.tmp")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temporary auth file: %v\n", err)
		os.Exit(1)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		fmt.Fprintf(os.Stderr, "set auth file permissions: %v\n", err)
		os.Exit(1)
	}
	if _, err := temporary.Write(content); err != nil {
		fmt.Fprintf(os.Stderr, "write auth file: %v\n", err)
		os.Exit(1)
	}
	if err := temporary.Sync(); err != nil {
		fmt.Fprintf(os.Stderr, "sync auth file: %v\n", err)
		os.Exit(1)
	}
	if err := temporary.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close auth file: %v\n", err)
		os.Exit(1)
	}
	if err := os.Rename(temporaryName, *output); err != nil {
		fmt.Fprintf(os.Stderr, "install auth file: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "Wrote bcrypt auth file: %s\n", *output)
}
