package service

import (
	"context"
	"errors"
	"log"

	"go-playground/internal/domain"

	"github.com/google/uuid"
)

type RedemptionService struct {
	redemptionRepo     domain.RedemptionRepository
	rewardsRepo        domain.RewardsRepository
	pointsService      domain.PointsService
	transactionService domain.TransactionService
	eventRepo          domain.EventLogRepository
}

func NewRedemptionService(
	redemptionRepo domain.RedemptionRepository,
	rewardsRepo domain.RewardsRepository,
	pointsService domain.PointsService,
	transactionService domain.TransactionService,
	eventRepo domain.EventLogRepository,
) *RedemptionService {
	return &RedemptionService{
		redemptionRepo:     redemptionRepo,
		rewardsRepo:        rewardsRepo,
		pointsService:      pointsService,
		transactionService: transactionService,
		eventRepo:          eventRepo,
	}
}

func (s *RedemptionService) Create(ctx context.Context, redemption *domain.Redemption) error {
	// Check if reward exists and is active
	reward, err := s.rewardsRepo.GetByID(redemption.RewardID)
	if reward == nil || err != nil {
		return errors.New("reward not found")
	}
	if !reward.IsActive {
		return errors.New("reward is not available")
	}

	// Parse user ID and program ID to UUID
	customerID, err := uuid.Parse(redemption.MerchantCustomersID.String())
	if err != nil {
		return errors.New("invalid user ID format")
	}
	// Check if user has enough points
	balance, err := s.pointsService.GetBalance(ctx, customerID, reward.ProgramID)
	if err != nil {
		return err
	}
	if balance.Balance < reward.PointsRequired {
		return errors.New("insufficient points")
	}

	// Set points_used in redemption record
	redemption.PointsUsed = reward.PointsRequired

	// Create redemption record
	redemptions, err := s.redemptionRepo.Create(ctx, redemption)
	if err != nil {
		return err
	}
	redemption = redemptions[0]

	// Deduct points by creating a redemption transaction
	transaction, err := s.transactionService.Create(ctx, &domain.CreateTransactionRequest{
		MerchantCustomersID: redemption.MerchantCustomersID,
		MerchantID:          uuid.Nil, // filled in by the transaction service
		ProgramID:           reward.ProgramID,
		TransactionType:     "redemption",
		TransactionAmount:   float64(reward.PointsRequired),
	})
	if err != nil {
		log.Printf("error creating redemption transaction for redemption id: %s, error: %v", redemption.ID, err)
		return err
	}

	log.Println("transaction record for redemption id: ", redemption.ID, "paired tx-id: ", transaction.TransactionID)

	// Log the redemption event
	event := &domain.EventLog{
		EventType:   string(domain.RewardRedeemed),
		ActorID:     redemption.MerchantCustomersID.String(),
		ActorType:   string(domain.MerchantUserActorType),
		ReferenceID: func() *string { s := redemption.ID.String(); return &s }(),
		Details: map[string]interface{}{
			"reward_id":     redemption.RewardID,
			"points_used":   reward.PointsRequired,
			"redemption_id": redemption.ID,
			"program_id":    reward.ProgramID,
		},
	}

	go s.eventRepo.Create(ctx, event)

	return nil
}

func (s *RedemptionService) GetByID(id string) (*domain.Redemption, error) {
	return s.redemptionRepo.GetByID(context.Background(), uuid.MustParse(id))
}

func (s *RedemptionService) GetByUserID(userID string) ([]*domain.Redemption, error) {
	return s.redemptionRepo.GetByUserID(context.Background(), uuid.MustParse(userID))
}

func (s *RedemptionService) UpdateStatus(ctx context.Context, id string, status string) error {
	redemption, err := s.redemptionRepo.GetByID(context.Background(), uuid.MustParse(id))
	if err != nil {
		return err
	}

	oldStatus := redemption.Status
	redemption.Status = domain.RedemptionStatus(status)

	// If canceling a pending redemption, refund the points
	if oldStatus == "pending" && status == "canceled" {
		reward, err := s.rewardsRepo.GetByID(redemption.RewardID)
		if err != nil {
			return err
		}
		customerID, err := uuid.Parse(redemption.MerchantCustomersID.String())
		if err != nil {
			return errors.New("invalid user ID format")
		}

		refundID := uuid.New()
		_, err = s.pointsService.EarnPoints(ctx, &domain.PointsTransaction{
			CustomerID:    customerID.String(),
			ProgramID:     reward.ProgramID.String(),
			Points:        reward.PointsRequired,
			Type:          "refund",
			TransactionID: refundID.String(),
		})
		if err != nil {
			return err
		}
	}

	return s.redemptionRepo.Update(ctx, redemption)
}

func (s *RedemptionService) SetPointsService(pointsService domain.PointsService) {
	s.pointsService = pointsService
}
