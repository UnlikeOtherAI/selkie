// home-bootstrap is an operator-only helper for one home-device enrollment.
// It uses the deployed server's database and signing secret, writes a ten-minute
// token to a new private file, and never prints credential material.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/unlikeotherai/selkie/internal/auth"
)

func run() error {
	reference := flag.String("uoa-reference", "", "existing stable UOA subject/reference of the home owner")
	output := flag.String("output", "", "new private token file")
	flag.Parse()
	secret := os.Getenv("INTERNAL_SESSION_SECRET")
	databaseURL := os.Getenv("DATABASE_URL")
	if *reference == "" || *output == "" || len(secret) < 32 || databaseURL == "" {
		return errors.New("existing UOA reference, output file, DATABASE_URL and deployed INTERNAL_SESSION_SECRET required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	database, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return errors.New("operator database connection failed")
	}
	defer database.Close(context.WithoutCancel(ctx))
	var userID string
	if queryErr := database.QueryRow(ctx, `SELECT id::text FROM users WHERE external_id=$1 AND status='active'`, *reference).Scan(&userID); queryErr != nil {
		return errors.New("existing active UOA reference not found; no identity was created")
	}
	now := time.Now()
	claims := jwt.RegisteredClaims{Issuer: auth.Issuer, Subject: userID, Audience: jwt.ClaimStrings{auth.AudienceAdmin}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute))}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		return errors.New("operator token signing failed")
	}
	// The operator-selected token file is created exclusively and never printed.
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("cannot create new private token file")
	}
	_, writeErr := file.WriteString(token)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("private token file write failed")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
