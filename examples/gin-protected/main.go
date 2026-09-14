package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/yonathanalulam/upsilonAuth/sdk/go/client"
	"github.com/yonathanalulam/upsilonAuth/sdk/go/middleware"
)

func main() {
	issuer := required("UPSILON_ISSUER")
	consumer, err := client.NewConsumer(issuer, required("UPSILON_CONSUMPTION_TOKEN"), nil, false)
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := middleware.New(middleware.Config{
		JWKSURL:        issuer + "/.well-known/jwks.json",
		RevocationsURL: issuer + "/.well-known/revocations.json",
		Issuer:         issuer,
		Audience:       "service:payments",
		RevocationMode: middleware.RevocationStrict,
		ConsumeLease:   consumer.Consume,
		ConstraintValues: func(_ *http.Request) map[string]string {
			return map[string]string{"environment": required("APP_ENVIRONMENT")}
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.POST(
		"/customers/:customerID/refunds",
		verifier.Require("payments:refund", func(c *gin.Context) string {
			return "customer/" + c.Param("customerID")
		}),
		func(c *gin.Context) { c.Status(http.StatusNoContent) },
	)
	if err := router.Run("127.0.0.1:8081"); err != nil {
		log.Fatal(err)
	}
}

func required(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}
