package service

import (
	"context"
	"go-playground/internal/domain"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type MerchantCustomersService struct {
	customerRepo domain.MerchantCustomersRepository
}

func NewMerchantCustomersService(customerRepo domain.MerchantCustomersRepository) *MerchantCustomersService {
	return &MerchantCustomersService{customerRepo: customerRepo}
}

func (s *MerchantCustomersService) Create(ctx context.Context, req *domain.CreateMerchantCustomerRequest) (*domain.MerchantCustomer, error) {

	// Check if customer already exists with email or phone
	existingByEmail, err := s.customerRepo.GetByEmail(ctx, req.Email)
	if existingByEmail != nil {
		return nil, err
	}

	existingByPhone, err := s.customerRepo.GetByPhone(ctx, req.Phone)
	if existingByPhone != nil {
		return nil, err
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	customer := &domain.MerchantCustomer{
		MerchantID: req.MerchantID,
		Email:      req.Email,
		Password:   string(hashedPassword),
		Name:       req.Name,
		Phone:      req.Phone,
	}

	if err := s.customerRepo.Create(ctx, customer); err != nil {
		return nil, err
	}

	return customer, nil

}

func (s *MerchantCustomersService) GetByID(ctx context.Context, id uuid.UUID) (*domain.MerchantCustomer, error) {

	customer, err := s.customerRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return customer, nil
}

func (s *MerchantCustomersService) GetByEmail(ctx context.Context, email string) (*domain.MerchantCustomer, error) {
	customer, err := s.customerRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	return customer, nil
}

func (s *MerchantCustomersService) GetByPhone(ctx context.Context, phone string) (*domain.MerchantCustomer, error) {
	return s.customerRepo.GetByPhone(ctx, phone)
}

func (s *MerchantCustomersService) GetByMerchantID(ctx context.Context, merchantID uuid.UUID) ([]*domain.MerchantCustomer, error) {
	return s.customerRepo.GetByMerchantID(ctx, merchantID)
}

func (s *MerchantCustomersService) Update(ctx context.Context, id uuid.UUID, req *domain.UpdateMerchantCustomerRequest) (*domain.MerchantCustomer, error) {
	customer, err := s.customerRepo.GetByID(ctx, id)
	if err != nil || customer == nil {
		return nil, err
	}

	// Check if email is being changed and if it's already taken
	if req.Email != "" && req.Email != customer.Email {
		existingByEmail, _ := s.customerRepo.GetByEmail(ctx, req.Email)
		if existingByEmail != nil {
			return nil, err
		}
		customer.Email = req.Email
	}

	// Check if phone is being changed and if it's already taken
	if req.Phone != "" && req.Phone != customer.Phone {
		existingByPhone, _ := s.customerRepo.GetByPhone(ctx, req.Phone)
		if existingByPhone != nil {
			return nil, err
		}
		customer.Phone = req.Phone
	}

	// Update other fields if provided
	if req.Name != "" {
		customer.Name = req.Name
	}

	// Update password if provided
	if req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		customer.Password = string(hashedPassword)
	}

	if err := s.customerRepo.Update(ctx, customer); err != nil {
		return nil, err
	}

	return customer, nil

}

func (s *MerchantCustomersService) ValidateCredentials(ctx context.Context, email, password string) (*domain.MerchantCustomer, error) {
	customer, err := s.customerRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(customer.Password), []byte(password))
	if err != nil {
		return nil, err
	}

	return customer, nil

}
