package service

import (
	"errors"
	"go-cursor/internal/domain"
	"go-cursor/internal/repository/postgres"
	"go-cursor/internal/repository/redis"
	"log"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	userRepo  *postgres.UserRepository
	cacheRepo *redis.CacheRepository
}

func NewUserService(userRepo *postgres.UserRepository, cacheRepo *redis.CacheRepository) *UserService {
	return &UserService{
		userRepo:  userRepo,
		cacheRepo: cacheRepo,
	}
}

func (s *UserService) Create(req *domain.CreateUserRequest) (*domain.User, error) {
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

	now := time.Now()
	user := &domain.User{
		ID:        uuid.New().String(),
		Email:     req.Email,
		Password:  string(hashedPassword),
		Name:      req.Name,
		Phone:     req.Phone,
		CreatedAt: now,
		UpdatedAt: now,
	}

	createdUser, err := s.userRepo.Create(user)
	if err != nil {
		return nil, err
	}

	// Clear password before returning
	createdUser.Password = ""
	return createdUser, nil
}

func (s *UserService) GetByID(id string) (*domain.User, error) {
	// Try to get from cache first
	if user, err := s.cacheRepo.GetUser(id); err == nil && user != nil {
		user.Status = user.Status
		return user, nil
	}

	// If not in cache, get from database
	user, err := s.userRepo.GetByID(id)
	if err != nil {
		return nil, err
	}

	// Convert status to string representation
	user.Status = user.Status

	// Store in cache for future requests
	if err := s.cacheRepo.SetUser(user); err != nil {
		log.Printf("Failed to cache user: %v", err)
	}

	return user, nil
}

func (s *UserService) GetAll() ([]domain.User, error) {
	usersPtr, err := s.userRepo.GetAll()
	if err != nil {
		return nil, err
	}

	users := make([]domain.User, len(usersPtr))
	for i, u := range usersPtr {
		users[i] = *u
		users[i].Password = ""
	}

	return users, nil
}

func (s *UserService) Update(id string, req *domain.UpdateUserRequest) (*domain.User, error) {
	// Get existing user
	user, err := s.userRepo.GetByID(id)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("user not found")
	}

	// Update fields
	user.Name = req.Name
	user.Phone = req.Phone
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(user); err != nil {
		return nil, err
	}

	// Clear password before returning
	user.Password = ""
	return user, nil
}

func (s *UserService) Delete(id string) error {
	// Get existing user
	user, err := s.userRepo.GetByID(id)
	if err != nil {
		return err
	}
	if user == nil {
		return errors.New("user not found")
	}

	return s.userRepo.Delete(id)
}
