package postgres

import (
	"go-playground/internal/domain"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

type MockRewardsRepository struct {
	mock.Mock
}

func (m *MockRewardsRepository) GetByID(id uuid.UUID) (*domain.Reward, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Reward), args.Error(1)
}

func (m *MockRewardsRepository) GetAll(activeOnly bool) ([]domain.Reward, error) {
	args := m.Called(activeOnly)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Reward), args.Error(1)
}

func (m *MockRewardsRepository) Create(reward *domain.Reward) error {
	args := m.Called(reward)
	return args.Error(0)
}

func (m *MockRewardsRepository) Update(reward *domain.Reward) error {
	args := m.Called(reward)
	return args.Error(0)
}

func (m *MockRewardsRepository) Delete(id uuid.UUID) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockRewardsRepository) GetByProgramID(programID uuid.UUID) ([]*domain.Reward, error) {
	args := m.Called(programID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.Reward), args.Error(1)
}
