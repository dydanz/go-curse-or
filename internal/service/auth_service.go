package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"go-playground/internal/domain"
	"go-playground/internal/repository/redis"
	"math/big"
	"time"

	"context"
	"log"

	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	userRepo    domain.UserRepository
	authRepo    domain.AuthRepository
	sessionRepo redis.SessionRepository
}

func NewAuthService(userRepo domain.UserRepository, authRepo domain.AuthRepository, sessionRepo redis.SessionRepository) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		authRepo:    authRepo,
		sessionRepo: sessionRepo,
	}
}

func (s *AuthService) Register(req *domain.RegistrationRequest) (*domain.User, error) {
	// Check if email already exists
	existingUser, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, errors.New("email already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create user
	createReq := &domain.CreateUserRequest{
		Email:    req.Email,
		Password: string(hashedPassword),
		Name:     req.Name,
		Phone:    req.Phone,
	}

	user, err := s.userRepo.Create(context.Background(), createReq)
	if err != nil {
		return nil, err
	}

	// Generate and store OTP
	otp := s.generateOTP()
	verification := &domain.RegistrationVerification{
		UserID:    user.ID,
		OTP:       otp,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if err := s.authRepo.CreateVerification(verification); err != nil {
		return nil, err
	}

	// TODO: Send OTP via email
	log.Printf("OTP for %s: %s", user.Email, otp)

	return user, nil
}

func (s *AuthService) VerifyRegistration(req *domain.VerificationRequest) error {
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		return fmt.Errorf("error getting user: %v", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if user.Status == domain.UserStatusActive {
		return fmt.Errorf("user already verified")
	}

	verification, err := s.authRepo.GetVerification(user.ID, req.OTP)
	if err != nil {
		return fmt.Errorf("verification error: %v", err)
	}

	// Start transaction
	tx, err := s.authRepo.BeginTx()
	if err != nil {
		return fmt.Errorf("transaction error: %v", err)
	}
	defer tx.Rollback()

	// Mark verification as used
	if err := s.authRepo.MarkVerificationUsedTx(tx, verification.ID); err != nil {
		return fmt.Errorf("error marking verification used: %v", err)
	}

	// Update user status
	user.Status = domain.UserStatusActive
	if err := s.userRepo.UpdateTx(tx, user); err != nil {
		return fmt.Errorf("error updating user status: %v", err)
	}

	return tx.Commit()
}

func (s *AuthService) Login(req *domain.LoginRequest) (*domain.AuthToken, error) {
	// Check login attempts
	attempt, err := s.authRepo.UpdateLoginAttempts(req.Email, true)
	if err != nil {
		return nil, err
	}

	if attempt.LockedUntil.After(time.Now()) {
		return nil, fmt.Errorf("account temporarily locked. Try again after %v", attempt.LockedUntil)
	}

	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if user.Status != domain.UserStatusActive {
		return nil, fmt.Errorf("account not verified")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Reset login attempts on successful login
	if _, err := s.authRepo.UpdateLoginAttempts(req.Email, false); err != nil {
		return nil, err
	}

	// Generate token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(tokenBytes)

	// Store the raw token
	authToken := &domain.AuthToken{
		UserID:    user.ID,
		TokenHash: token, // Store raw token
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if err := s.authRepo.CreateToken(authToken); err != nil {
		return nil, err
	}

	// Store session data
	if err := s.sessionRepo.StoreSession(context.Background(), user.ID, token, authToken.ExpiresAt); err != nil {
		log.Printf("Failed to store session: %v", err)
	}

	return authToken, nil
}

func (s *AuthService) generateOTP() string {
	const digits = "0123456789"
	result := make([]byte, 6)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "000000" // fallback OTP
		}
		result[i] = digits[num.Int64()]
	}
	return string(result)
}

func (s *AuthService) Logout(userID string, tokenHash string) error {
	s.sessionRepo.DeleteSession(context.Background(), userID)
	return s.authRepo.InvalidateToken(userID)
}
