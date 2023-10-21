package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/lucsky/cuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	jwtware "github.com/gofiber/contrib/jwt"
)

const JWT_SECRET = "SECRET"

var DB *gorm.DB
var Cache *redis.Client

type Client struct {
	ID           string `gorm:"primaryKey"`
	Name         string `gorm:"uniqueIndex"`
	ClientSecret string `json:"-"`
	Website      string
	Logo         string
	RedirectURI  string         `json:"redirect_uri"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`
}

type LoginRequest struct {
	Identity string `json:"identity"`
	Password string `json:"password"`
}

type User struct {
	ID        uuid.UUID      `gorm:"primaryKey" json:"id"`
	Email     string         `gorm:"uniqueIndex" json:"email"`
	Password  string         `json:"-"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
	Profile   UserProfile    `json:"profile,omitempty"`
	Posts     []Post         `json:"posts,omitempty"`
}

type UserProfile struct {
	ID                uuid.UUID `json:"id"`
	UserID            uuid.UUID `json:"user_id"`
	ProfilePictureUrl string    `json:"profile_picture_url"`
	FirstName         string    `json:"first_name"`
	LastName          string    `json:"last_name"`
	Age               int       `json:"age"`
}

type Post struct {
	ID        uuid.UUID      `json:"id"`
	UserID    uuid.UUID      `json:"user_id"`
	Title     string         `json:"title"`
	Body      string         `json:"body"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

type AuthRequest struct {
	ResponseType string `json:"response_type" query:"response_type"`
	ClientID     string `json:"client_id" query:"client_id"`
	RedirectURI  string `json:"redirect_uri" query:"redirect_uri"`
	Scope        string `json:"scope" query:"scope"`
	State        string `json:"state" query:"state"`
}

type ConfirmAuthRequest struct {
	Identity  string `json:"identity"`
	Password  string `json:"password"`
	Authorize bool   `json:"authorize" query:"authorize"`
	State     string `json:"state" query:"state"`
	Scope     string `json:"scope" query:"scope"`
	ClientID  string `json:"client_id" query:"client_id"`
}

type TokenRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type" query:"grant_type"`
	Code         string `json:"code" form:"code" query:"code"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri" query:"redirect_uri"`
	ClientID     string `json:"client_id" form:"client_id" query:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret" query:"client_secret"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func Protected() fiber.Handler {
	return jwtware.New(jwtware.Config{
		ContextKey:   "jwt",
		SigningKey:   jwtware.SigningKey{Key: []byte(JWT_SECRET)},
		ErrorHandler: jwtError,
	})
}

func jwtError(c *fiber.Ctx, err error) error {
	if err.Error() == "Missing or malformed JWT" {
		return c.Status(fiber.StatusBadRequest).
			JSON(fiber.Map{"status": "error", "message": "Missing or malformed JWT", "data": nil})
	}
	return c.Status(fiber.StatusUnauthorized).
		JSON(fiber.Map{"status": "error", "message": "Invalid or expired JWT", "data": nil})
}

func main() {
	ctx := context.Background()
	err := godotenv.Load()
	if err != nil {
		panic("unable to load env file")
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		panic("DATABASE_URL is not set!")
	}

	DB, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Migrate the schema
	DB.AutoMigrate(&Client{}, &User{}, &UserProfile{}, &Post{})

	// Insert dummy client
	DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name", "website", "redirect_uri", "logo", "client_secret"}),
	}).Create(&Client{
		ID:           "1",
		Name:         "fiber",
		Website:      "http://localhost:8080",
		RedirectURI:  "http://localhost:8080/auth/callback",
		Logo:         "https://placehold.co/600x400",
		ClientSecret: "ABCDEF",
	})

	// Remove all users, posts, and profiles
	DB.Exec("DELETE FROM posts")
	DB.Exec("DELETE FROM user_profiles")
	DB.Exec("DELETE FROM users")
	// Insert dummy user
	hash, _ := hashPassword("pass")
	DB.Create(&User{
		ID:       uuid.New(),
		Email:    "jdoe",
		Password: hash,
		Profile: UserProfile{
			ID:                uuid.New(),
			ProfilePictureUrl: "https://placehold.co/600x400",
			FirstName:         "John",
			LastName:          "Doe",
			Age:               30,
		},
		Posts: []Post{
			{
				ID:    uuid.New(),
				Title: "My first post",
				Body:  "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
			},
			{
				ID:    uuid.New(),
				Title: "My second post",
				Body:  "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
			},
		},
	})

	Cache := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "redis", // no password set
		DB:       0,       // use default DB
	})

	views := html.New("./views", ".html")
	api := fiber.New(fiber.Config{
		AppName: "Authorization Service",
		Views:   views,
	})
	api.Use(logger.New())
	api.Use(recover.New())

	api.Get("/", func(c *fiber.Ctx) error {
		// Check cookie for access token
		accessToken := c.Cookies("auth-service-access-token")
		if accessToken == "" {
			log.Info("access token not found")
			return c.Redirect("/login")
		}

		// get user_id from accessToken
		token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
			return []byte(JWT_SECRET), nil
		})
		if err != nil {
			log.Info("failed to parse access token")
			return c.Redirect("/login")
		}

		userId, err := token.Claims.GetSubject()
		log.Infof("userId: %v", userId)
		if err != nil {
			log.Info("failed to get user id from access token")
			return c.Redirect("/login")
		}

		// Lookup user
		user := new(User)
		query := DB.Where("id = ?", userId)
		if strings.Contains(token.Claims.(jwt.MapClaims)["scope"].(string), "profile") {
			query = query.Preload("Profile")
		}
		if strings.Contains(token.Claims.(jwt.MapClaims)["scope"].(string), "posts") {
			query = query.Preload("Posts")
		}
		if err := query.First(&user).Error; err != nil {
			return c.Redirect("/login")
		}

		// hacky way to render the user data
		return c.Render("home", fiber.Map{
			"data": fiber.Map{
				"email": user.Email,
				"profile": fiber.Map{
					"picture":    user.Profile.ProfilePictureUrl,
					"first_name": user.Profile.FirstName,
					"last_name":  user.Profile.LastName,
				},
				"posts": []fiber.Map{
					{
						"title": user.Posts[0].Title,
						"body":  user.Posts[0].Body,
					},
					{
						"title": user.Posts[1].Title,
						"body":  user.Posts[1].Body,
					},
				},
			},
		})
	})

	api.Get("/login", func(c *fiber.Ctx) error {
		// render login page
		return c.Render("login", fiber.Map{})
	})

	api.Post("/login", func(c *fiber.Ctx) error {
		// Parse Request
		loginRequest := new(LoginRequest)
		if err := c.BodyParser(loginRequest); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}

		// Validate Params
		if loginRequest.Identity == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_identity"})
		}
		if loginRequest.Password == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_password"})
		}

		// Lookup user
		user := new(User)
		if err := DB.Where("email = ?", loginRequest.Identity).First(&user).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "user_not_found"})
		}

		// Check password
		if !CheckPasswordHash(loginRequest.Password, user.Password) {
			return c.Status(401).JSON(fiber.Map{"error": "not_authorized"})
		}

		// Generate the access token
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)
		claims["iss"] = "auth-service"
		claims["sub"] = user.ID
		claims["aud"] = "auth-service"
		claims["iat"] = time.Now().Unix()
		claims["exp"] = time.Now().Add(time.Hour * 6).Unix()
		claims["scope"] = "profile posts"

		// store token in secure cookie
		accessToken, err := token.SignedString([]byte(JWT_SECRET))
		if err != nil {
			log.Info("failed to generate access token")
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		c.Cookie(&fiber.Cookie{
			Name:     "auth-service-access-token",
			Value:    accessToken,
			Secure:   true,
			Expires:  time.Now().Add(6 * time.Hour),
			HTTPOnly: true,
		})

		return c.Redirect("/")
	})

	api.Get("/currentuser", Protected(), func(c *fiber.Ctx) error {
		token := c.Locals("jwt").(*jwt.Token)
		userId, err := token.Claims.GetSubject()
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "bad token"})
		}

		scope := token.Claims.(jwt.MapClaims)["scope"].(string)

		query := DB.Where("id = ?", userId)
		if strings.Contains(scope, "profile") {
			query = query.Preload("Profile")
		}
		if strings.Contains(scope, "posts") {
			query = query.Preload("Posts")
		}
		user := new(User)
		err = query.First(&user).Error
		if err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "user not found"})
		}
		return c.JSON(fiber.Map{"data": user})
	})

	api.Get("/auth", func(c *fiber.Ctx) error {
		// Parse Request
		authRequest := new(AuthRequest)
		if err := c.QueryParser(authRequest); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}

		// Validate Params
		if authRequest.ResponseType != "code" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_response_type"})
		}
		if authRequest.ClientID == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_client_id"})
		}
		if !strings.Contains(authRequest.RedirectURI, "https") {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_redirect_uri"})
		}
		if authRequest.Scope == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_scope"})
		}
		if authRequest.State == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_state"})
		}

		// Check for client
		client := new(Client)
		if err := DB.Where("name = ?", authRequest.ClientID).First(&client).Error; err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_client"})
		}

		// Generate temp code
		code, err := cuid.NewCrypto(rand.Reader)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "server_error"})
		}

		c.Cookie(&fiber.Cookie{
			Name:     "temp_auth_request_code",
			Value:    code,
			Secure:   true,
			Expires:  time.Now().Add(1 * time.Minute),
			HTTPOnly: true,
		})

		return c.Render("authorize_client", fiber.Map{
			"Logo":    client.Logo,
			"Name":    client.Name,
			"Website": client.Website,
			"State":   authRequest.State,
			"Scope":   authRequest.Scope,
			"Scopes":  strings.Split(authRequest.Scope, " "),
		})
	})

	api.Get("/confirm_auth", func(c *fiber.Ctx) error {
		// Get secure temp code from cookie
		tempCode := c.Cookies("temp_auth_request_code")
		c.ClearCookie("temp_auth_request_code")
		if tempCode == "" {
			log.Error("no temp code from cookie")
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}

		// Parse Query Params
		confirmAuthRequest := new(ConfirmAuthRequest)
		if err := c.QueryParser(confirmAuthRequest); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}

		// Validate Params
		if confirmAuthRequest.ClientID == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_client_id"})
		}
		if confirmAuthRequest.State == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_state"})
		}
		if confirmAuthRequest.Identity == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_identity"})
		}
		if confirmAuthRequest.Password == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_password"})
		}
		if confirmAuthRequest.Scope == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_scope"})
		}

		// Check for client
		client := new(Client)
		if err := DB.Where("name = ?", confirmAuthRequest.ClientID).First(&client).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "invalid_client"})
		}

		// Redirect based on deny
		if !confirmAuthRequest.Authorize {
			return c.Redirect(client.RedirectURI + "?error=access_denied" + "&state=" + confirmAuthRequest.State)
		}

		// Fetch the user
		user := new(User)
		if err := DB.Where("email = ?", confirmAuthRequest.Identity).First(&user).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "invalid_user"})
		}

		// Check password
		if !CheckPasswordHash(confirmAuthRequest.Password, user.Password) {
			return c.Status(401).JSON(fiber.Map{"error": "not_authorized"})
		}

		// Save the auth_code to our cache, set it to expire
		key := "auth_code:" + tempCode
		session := map[string]string{
			"client_id": client.Name,
			"user_id":   user.ID.String(),
			"scope":     confirmAuthRequest.Scope,
		}
		for k, v := range session {
			err := Cache.HSet(ctx, key, k, v).Err()
			if err != nil {
				panic(err)
			}
		}

		Cache.Expire(ctx, key, 60*time.Second)

		return c.Redirect(client.RedirectURI + "?code=" + tempCode + "&state=" + confirmAuthRequest.State)
	})

	api.Post("/token", func(c *fiber.Ctx) error {
		tokenRequest := new(TokenRequest)
		if err := c.BodyParser(tokenRequest); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}

		log.Infof("tokenRequest: %v", tokenRequest)

		// Validate Params
		if tokenRequest.ClientID == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_client_id"})
		}
		if tokenRequest.Code == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_code"})
		}
		if tokenRequest.RedirectURI == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_redirect_uri"})
		}
		if tokenRequest.GrantType == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_grant_type"})
		}
		if tokenRequest.ClientSecret == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_secret"})
		}

		// Look up auth session
		key := "auth_code:" + tokenRequest.Code
		authSession := Cache.HGetAll(ctx, key).Val()

		// remove key from cache
		Cache.Del(ctx, key)

		if len(authSession) == 0 {
			log.Info("authSession not found")
			return c.Status(400).JSON(fiber.Map{"error": "invalid_code"})
		}
		log.Infof("authSession: %v", authSession)

		// Check client matches session
		if tokenRequest.ClientID != authSession["client_id"] {
			log.Info("client ids do not match")
			return c.Status(400).JSON(fiber.Map{"error": "invalid_client"})
		}

		// Lookup client
		client := new(Client)
		if err := DB.Where("name = ?", tokenRequest.ClientID).First(&client).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "client_not_found"})
		}

		// Check client secret
		if tokenRequest.ClientSecret != client.ClientSecret {
			log.Info("client secret does not match")
			return c.Status(400).JSON(fiber.Map{"error": "invalid_secret"})
		}

		// Check redirect uri
		if tokenRequest.RedirectURI != client.RedirectURI {
			log.Info("redirect uri does not match")
			return c.Status(400).JSON(fiber.Map{"error": "invalid_redirect_uri"})
		}

		// Lookup user
		user := new(User)
		if err := DB.Where("id = ?", authSession["user_id"]).First(&user).Error; err != nil {
			log.Info("user not found")
			return c.Status(404).JSON(fiber.Map{"error": "user_not_found"})
		}

		// Generate the access token
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)
		claims["iss"] = "auth-service"
		claims["sub"] = user.ID
		claims["aud"] = client.Name
		claims["iat"] = time.Now().Unix()
		claims["exp"] = time.Now().Add(time.Hour * 6).Unix()
		claims["scope"] = authSession["scope"]

		accessToken, err := token.SignedString([]byte(JWT_SECRET))
		if err != nil {
			log.Info("failed to generate access token")
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		tokenResponse := &TokenResponse{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		return c.JSON(tokenResponse)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	api.Listen(fmt.Sprintf(":%s", port))
}
