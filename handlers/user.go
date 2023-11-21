package handlers

import (
	"github.com/danielalejandrorosero/models"
	"github.com/gofiber/fiber/v2"
)

func User(c *fiber.Ctx) error {
	user := c.Locals("user").(models.User)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "succes", "data": fiber.Map{"user": user}})
}
