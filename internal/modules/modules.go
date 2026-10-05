package modules

import (
	"context"
	"errors"
	"sync"

	"aether/internal/config"
	"aether/internal/report"
)

// ErrNotImplemented is returned by module stubs that have not yet been implemented.
var ErrNotImplemented = errors.New("module not implemented")

// ErrNotApplicable is returned when a module requires a live system and cannot run in offline mode.
var ErrNotApplicable = errors.New("not applicable (offline mode)")

// Module represents a specialized threat-hunting inspection module.
type Module interface {
	Name() string
	Description() string
	Run(ctx context.Context, cfg *config.Config, rep report.Reporter) error
}

var (
	registryMu sync.RWMutex
	registry   = make(map[string]Module)
)

// Register adds a module to the global hunting registry.
func Register(m Module) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[m.Name()] = m
}

// GetModules returns all registered threat-hunting modules.
func GetModules() []Module {
	registryMu.RLock()
	defer registryMu.RUnlock()

	result := make([]Module, 0, len(registry))
	for _, m := range registry {
		result = append(result, m)
	}
	return result
}
