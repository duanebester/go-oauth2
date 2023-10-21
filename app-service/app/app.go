package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
	"golang.org/x/oauth2"
)

type AuthCodeResp struct {
	Code  string `query:"code"`
	State string `query:"state"`
}

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type AccessTokenResp struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

const CLIENT_ID = "fiber"
const CLIENT_SECRET = "ABCDEF"

const STATE = "1234zyx"
const REDIRECT = "https://localhost:8080/auth/callback"

func NewApp() *fiber.App {
	ctx := context.Background()
	conf := &oauth2.Config{
		ClientID:     CLIENT_ID,
		ClientSecret: CLIENT_SECRET,
		Scopes:       []string{"profile"},
		RedirectURL:  REDIRECT,
		Endpoint: oauth2.Endpoint{
			AuthStyle: oauth2.AuthStyleInParams,
			TokenURL:  "http://localhost:3000/token",
			AuthURL:   "http://localhost:3000/auth",
		},
	}

	views := html.New("./views", ".html")
	api := fiber.New(fiber.Config{
		AppName: "App Service",
		Views:   views,
	})
	api.Use(logger.New())
	api.Use(recover.New())

	api.Get("/", func(c *fiber.Ctx) error {
		url := conf.AuthCodeURL(STATE)
		return c.Render("login", fiber.Map{
			"LoginWithUrl": url,
		})
	})

	api.Get("/auth/callback", func(c *fiber.Ctx) error {
		// Parse Query Params
		codeResp := new(AuthCodeResp)
		if err := c.QueryParser(codeResp); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}

		// verify state matches
		if codeResp.State != STATE {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}

		// Use the custom HTTP client when requesting a token.
		httpClient := &http.Client{Timeout: 2 * time.Second}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

		tok, err := conf.Exchange(ctx, codeResp.Code)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}

		authClient := conf.Client(ctx, tok)
		resp, err := authClient.Get("http://localhost:3000/currentuser")
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body) // response body is []byte
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}

		var result *fiber.Map
		if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to the go struct pointer
			fmt.Println("Can not unmarshal JSON")
		}

		return c.Render("dashboard", result)
	})

	return api
}
