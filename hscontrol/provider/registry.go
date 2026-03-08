package provider

import (
	"fmt"
	"sync"
)

// ConstructorFunc creates a new Provider instance.
type ConstructorFunc func() Provider

var (
	registryMu   sync.RWMutex
	constructors = make(map[string]ConstructorFunc)
)

// Register adds a provider constructor to the global registry.
func Register(name string, fn ConstructorFunc) {
	registryMu.Lock()
	defer registryMu.Unlock()
	constructors[name] = fn
}

// Get returns a new Provider instance for the given name, or an error
// if no provider is registered under that name.
func Get(name string) (Provider, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	fn, ok := constructors[name]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %q", name)
	}

	return fn(), nil
}

// Registered returns the names of all registered providers.
func Registered() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	names := make([]string, 0, len(constructors))
	for name := range constructors {
		names = append(names, name)
	}

	return names
}
