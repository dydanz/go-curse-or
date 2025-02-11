package service

import (
	"crypto/rand"
	"encoding/hex"
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
		return nil, err
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("error hashing password: %v", err)
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
		return nil, fmt.Errorf("error creating user: %v", err)
	}

	// Generate and store OTP
	otp := s.generateOTP()
	verification := &domain.RegistrationVerification{
		UserID:    user.ID,
		OTP:       otp,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if err := s.authRepo.CreateVerification(verification); err != nil {
		return nil, fmt.Errorf("error creating verification: %v", err)
	}

	// TODO: Send OTP via email
	log.Printf("OTP for %s: %s", user.Email, otp)

	return user, nil
}

func (s *AuthService) VerifyRegistration(req *domain.VerificationRequest) error {
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		return err
	}
	if user == nil {
		return err
	}

	if user.Status == domain.UserStatusActive {
		return err
	}

	verification, err := s.authRepo.GetVerification(user.ID, req.OTP)
	if err != nil {
		return err
	}

	// Start transaction
	tx, err := s.authRepo.BeginTx()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Mark verification as used
	if err := s.authRepo.MarkVerificationUsedTx(tx, verification.ID); err != nil {
		return err
	}

	// Update user status
	user.Status = domain.UserStatusActive
	if err := s.userRepo.UpdateTx(tx, user); err != nil {
		return err
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
		return nil, err
	}

	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, err
	}

	if user.Status != domain.UserStatusActive {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, err
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
		TokenHash: token,
		UserName:  user.Name,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	fmt.Println("user.Name ", user.Name)

	if err := s.authRepo.CreateToken(authToken); err != nil {
		return nil, err
	}

	// Store session data
	if err := s.sessionRepo.StoreSession(context.Background(), user.ID, token, authToken.ExpiresAt); err != nil {
		return nil, err
	}

	return authToken, nil
}

func (s *AuthService) GetUserByEmail(email string) (*domain.User, error) {
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, err
	}
	return user, nil
}

func (s *AuthService) GetVerificationByUserID(userID string) (*domain.RegistrationVerification, error) {
	verification, err := s.authRepo.GetLatestVerification(userID)
	if err != nil {
		return nil, err
	}
	return verification, nil
}

func (s *AuthService) GetRandomActiveUser() (*domain.User, error) {
	user, err := s.userRepo.GetRandomActiveUser()
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, err
	}
	return user, nil
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
