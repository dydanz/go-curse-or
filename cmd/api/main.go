package main

import (
	"fmt"
	"go-cursor/internal/config"
	"go-cursor/internal/handler"
	"go-cursor/internal/repository/postgres"
	"go-cursor/internal/repository/redis"
	"go-cursor/internal/service"
	"go-cursor/pkg/database"
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "go-cursor/internal/docs" // This is required for swagger
	"go-cursor/internal/middleware"
)

// @title           Go-Playground
// @version         1.0
// @description     Go-Playground - Random Go/Gin-Boilerplate Playground
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.swagger.io/support
// @contact.email  support@swagger.io

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8080
// @BasePath  /api

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

// @Security BearerAuth
func main() {
	// Load config
	cfg := config.LoadConfig()

	// Initialize PostgreSQL
	db, err := database.NewPostgresConnection(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize Redis
	rdb := database.NewRedisConnection(cfg)
	defer rdb.Close()

	// Initialize repositories
	userRepo := postgres.NewUserRepository(db)
	cacheRepo := redis.NewCacheRepository(rdb)
	authRepo := postgres.NewAuthRepository(db, &cfg.Auth)

	// Initialize services
	userService := service.NewUserService(userRepo, cacheRepo)
	authService := service.NewAuthService(userRepo, authRepo)

	// Initialize handlers
	userHandler := handler.NewUserHandler(userService)
	authHandler := handler.NewAuthHandler(authService)

	// Initialize Gin router
	r := gin.Default()

	// CORS middleware
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:8080"}
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	r.Use(cors.New(config))

	// Swagger documentation - must be before routes
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Public routes
	auth := r.Group("/api/auth")
	{
		auth.POST("/register", authHandler.Register)
		auth.POST("/verify", authHandler.Verify)
		auth.POST("/login", authHandler.Login)
	}

	// Protected routes
	api := r.Group("/api")
	api.Use(middleware.AuthMiddleware(authRepo))
	{
		api.POST("/auth/logout", authHandler.Logout)
		users := api.Group("/users")
		{
			users.GET("/me", userHandler.GetMe)
			users.GET("", userHandler.GetAll)
			users.GET("/:id", userHandler.GetByID)
			users.POST("", userHandler.Create)
			users.PUT("/:id", userHandler.Update)
			users.DELETE("/:id", userHandler.Delete)
		}
	}

	// Add static file handling
	r.Static("/static", "./internal/static")
	r.LoadHTMLGlob("internal/static/*.html")

	// Add routes for HTML pages
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", nil)
	})

	r.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", nil)
	})

	// Protected HTML routes
	r.GET("/dashboard", middleware.AuthMiddleware(authRepo), func(c *gin.Context) {
		c.HTML(http.StatusOK, "dashboard.html", nil)
	})

	// Add CSRF middleware
	r.Use(middleware.CSRFMiddleware())

	// Run migrations
	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName)
	if err := database.RunMigrations(dbURL); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			if err := authRepo.CleanupExpiredAttempts(); err != nil {
				log.Printf("Failed to cleanup expired attempts: %v", err)
			}
		}
	}()

	// Start server
	r.Run(":8080")
}
