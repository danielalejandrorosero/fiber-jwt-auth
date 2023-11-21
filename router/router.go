package router

import (
	"github.com/danielalejandrorosero/handlers"
	"github.com/danielalejandrorosero/middleware"
	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App) {
	app.Post("/signup", handlers.SignUp)
	app.Post("/signin", handlers.SignIn)
	app.Get("/logout", handlers.Logout)
	app.Get("/user", middleware.DeserializeUser, handlers.User)

}
