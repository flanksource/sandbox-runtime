package srt

import (
	"sync"
	"time"
)

type SandboxViolationEvent struct {
	Line           string    `json:"line"`
	Command        string    `json:"command,omitempty"`
	EncodedCommand string    `json:"encodedCommand,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
}

type SandboxViolationStore struct {
	mu         sync.RWMutex
	violations []SandboxViolationEvent
	totalCount int
	maxSize    int
}

func NewSandboxViolationStore() *SandboxViolationStore {
	return &SandboxViolationStore{maxSize: 100}
}

func (s *SandboxViolationStore) AddViolation(v SandboxViolationEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.violations = append(s.violations, v)
	s.totalCount++
	if len(s.violations) > s.maxSize {
		s.violations = append([]SandboxViolationEvent{}, s.violations[len(s.violations)-s.maxSize:]...)
	}
}

func (s *SandboxViolationStore) GetViolations(limit int) []SandboxViolationEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit >= len(s.violations) {
		out := make([]SandboxViolationEvent, len(s.violations))
		copy(out, s.violations)
		return out
	}
	start := len(s.violations) - limit
	out := make([]SandboxViolationEvent, limit)
	copy(out, s.violations[start:])
	return out
}

func (s *SandboxViolationStore) GetViolationsForCommand(command string) []SandboxViolationEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	needle := EncodeSandboxedCommand(command)
	out := make([]SandboxViolationEvent, 0)
	for _, v := range s.violations {
		if v.EncodedCommand == needle {
			out = append(out, v)
		}
	}
	return out
}

func (s *SandboxViolationStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.violations = nil
}

func (s *SandboxViolationStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.violations)
}

func (s *SandboxViolationStore) TotalCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.totalCount
}
