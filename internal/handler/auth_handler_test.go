package handler_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"go-cursor/internal/domain"
	"go-cursor/internal/handler"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAuthService is a mock implementation of the auth service
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(req *domain.RegistrationRequest) (*domain.User, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockAuthService) Login(req *domain.LoginRequest) (*domain.AuthToken, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.AuthToken), args.Error(1)
}

func (m *MockAuthService) Logout(userID string) error {
	return m.Called(userID).Error(0)
}

func setupTest() (*gin.Engine, *MockAuthService) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	authHandler := handler.NewAuthHandler(mockService)

	router := gin.Default()
	router.POST("/auth/register", authHandler.Register)
	router.POST("/auth/login", authHandler.Login)
	router.POST("/auth/logout", authHandler.Logout)

	return router, mockService
}

func TestRegister(t *testing.T) {
	router, mockService := setupTest()

	t.Run("Success", func(t *testing.T) {
		mockUser := &domain.User{
			ID:     "123e4567-e89b-12d3-a456-426614174000",
			Email:  "test@example.com",
			Name:   "Test User",
			Phone:  "1234567890",
			Status: domain.UserStatusActive,
		}
		mockService.On("Register", mock.AnythingOfType("*domain.RegistrationRequest")).Return(mockUser, nil).Once()

		body := []byte(`{
			"email": "test@example.com",
			"password": "password123",
			"name": "Test User",
			"phone": "1234567890"
		}`)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response domain.User
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, mockUser.Name, response.Name)
	})

	t.Run("Failure", func(t *testing.T) {
		mockService.On("Register", mock.AnythingOfType("*domain.RegistrationRequest")).Return(nil, errors.New("email already exists")).Once()

		body := []byte(`{
			"email": "test@example.com",
			"password": "password123",
			"name": "Test User",
			"phone": "1234567890"
		}`)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

}

func TestLogin(t *testing.T) {
	router, mockService := setupTest()

	t.Run("Success", func(t *testing.T) {
		mockToken := &domain.AuthToken{
			UserID:    "123e4567-e89b-12d3-a456-426614174000",
			TokenHash: "someRandomToken",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		mockService.On("Login", mock.AnythingOfType("*domain.LoginRequest")).Return(mockToken, nil).Once()

		body := []byte(`{
			"email": "test@example.com",
			"password": "password123"
		}`)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response domain.LoginResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, mockToken.TokenHash, response.Token)
	})

	t.Run("Failure", func(t *testing.T) {
		mockService.On("Login", mock.AnythingOfType("*domain.LoginRequest")).Return(nil, errors.New("invalid credentials")).Once()

		body := []byte(`{
			"email": "test@example.com",
			"password": "wrongpassword"
		}`)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

}

func TestLogout(t *testing.T) {
	router, mockService := setupTest()

	t.Run("Success", func(t *testing.T) {
		userID := "123e4567-e89b-12d3-a456-426614174000"
		mockService.On("Logout", userID).Return(nil).Once()

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer someRandomToken")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Failure", func(t *testing.T) {
		userID := "non-existent-id"
		mockService.On("Logout", userID).Return(errors.New("user not found")).Once()

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer someRandomToken")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
