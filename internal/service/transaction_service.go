package service

import (
	"context"
	"time"

	"go-playground/internal/domain"

	"github.com/google/uuid"
)

type TransactionService struct {
	transactionRepo domain.TransactionRepository
	pointsService   domain.PointsServiceInterface
	eventRepo       domain.EventLogRepository
}

func NewTransactionService(
	transactionRepo domain.TransactionRepository,
	pointsService domain.PointsServiceInterface,
	eventRepo domain.EventLogRepository,
) *TransactionService {
	return &TransactionService{
		transactionRepo: transactionRepo,
		pointsService:   pointsService,
		eventRepo:       eventRepo,
	}
}

func (s *TransactionService) Create(req *domain.CreateTransactionRequest) (*domain.Transaction, error) {
	tx := &domain.Transaction{
		TransactionID:     uuid.New(),
		MerchantID:        req.MerchantID,
		CustomerID:        req.CustomerID,
		ProgramID:         req.ProgramID,
		BranchID:          req.BranchID,
		TransactionType:   req.TransactionType,
		TransactionAmount: req.TransactionAmount,
		Status:            "pending",
		CreatedAt:         time.Now(),
	}

	if err := s.transactionRepo.Create(context.Background(), tx); err != nil {
		return nil, err
	}

	// Calculate points based on transaction amount and type
	var points int
	switch tx.TransactionType {
	case "purchase":
		points = int(tx.TransactionAmount) // Example: 1 point per currency unit
	case "refund":
		points = -int(tx.TransactionAmount)
	case "bonus":
		points = int(tx.TransactionAmount * 2) // Example: Double points for bonus
	}

	// Update points balance if applicable
	if points != 0 {
		if err := s.pointsService.EarnPoints(context.Background(), tx.CustomerID, tx.ProgramID, points, &tx.TransactionID); err != nil {
			return nil, err
		}
	}

	// Log the transaction event, make async
	txIDStr := tx.TransactionID.String()
	event := &domain.EventLog{
		EventType:   "transaction_created",
		UserID:      tx.CustomerID.String(),
		ReferenceID: &txIDStr,
		Details: map[string]interface{}{
			"merchant_id":        tx.MerchantID,
			"transaction_type":   tx.TransactionType,
			"transaction_amount": tx.TransactionAmount,
			"points_earned":      points,
			"branch_id":          tx.BranchID,
		},
	}
	if err := s.eventRepo.Create(event); err != nil {
		return nil, err
	}

	return tx, nil
}

func (s *TransactionService) GetByID(id string) (*domain.Transaction, error) {
	txID, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}
	return s.transactionRepo.GetByID(context.Background(), txID)
}

func (s *TransactionService) GetByCustomerID(customerID string) ([]*domain.Transaction, error) {
	custID, err := uuid.Parse(customerID)
	if err != nil {
		return nil, err
	}
	txs, _, err := s.transactionRepo.GetByCustomerIDWithPagination(context.Background(), custID, 0, -1)
	return txs, err
}

func (s *TransactionService) GetByCustomerIDWithPagination(customerID string, offset, limit int) ([]*domain.Transaction, int64, error) {
	custID, err := uuid.Parse(customerID)
	if err != nil {
		return nil, 0, err
	}
	return s.transactionRepo.GetByCustomerIDWithPagination(context.Background(), custID, offset, limit)
}

func (s *TransactionService) GetByMerchantID(merchantID string) ([]*domain.Transaction, error) {
	merchID, err := uuid.Parse(merchantID)
	if err != nil {
		return nil, err
	}
	return s.transactionRepo.GetByMerchantID(context.Background(), merchID)
}

func (s *TransactionService) UpdateStatus(id string, status string) error {
	txID, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	return s.transactionRepo.UpdateStatus(context.Background(), txID, status)
}

func (s *TransactionService) SetPointsService(pointsService domain.PointsServiceInterface) {
	s.pointsService = pointsService
}
