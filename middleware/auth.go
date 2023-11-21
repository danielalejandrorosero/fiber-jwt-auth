package middleware

import (
	"fmt"
	"strings"

	"github.com/danielalejandrorosero/config"
	"github.com/danielalejandrorosero/database"
	"github.com/danielalejandrorosero/models"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
)

func DeserializeUser(c *fiber.Ctx) error {
	var tokenString string
	authorization := c.Get("Authorization")

	if strings.HasPrefix(authorization, "Bearer") {
		tokenString = strings.TrimPrefix(authorization, "Bearer")
	} else if c.Cookies("token") != "" {
		tokenString = c.Cookies("token")
	}

	if tokenString == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "fail", "message": "no has iniciado sesion"})
	}

	tokenByte, err := jwt.Parse(tokenString, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("metodo de firma inesperado: %s", jwtToken.Header["alg"])
		}

		return []byte(config.Config("SECRET_KEY")), nil
	})

	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"stauts": "fail", "message": fmt.Sprintf("token invalido: %v", err)})
	}

	claims, ok := tokenByte.Claims.(jwt.MapClaims)
	if !ok || !tokenByte.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "fail", "message": "reclaod del token invalido"})
	}

	var user models.User
	db := database.DB
	db.First(&user, "id = ?", fmt.Sprint(claims["sub"]))

	if float64(user.ID) != claims["sub"] {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"status": "fail", "message": "el usuario al que pertenece ya no tiene token "})
	}
	c.Locals("user", &user)
	return c.Next()
}
