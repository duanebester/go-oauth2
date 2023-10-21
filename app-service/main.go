package main

import (
	"app-service/app"
)

func main() {
	api := app.NewApp()
	api.Listen(":8080")
}
