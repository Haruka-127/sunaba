package session

import (
	"fmt"
	"reflect"

	"sunaba/internal/modelcatalog"
	"sunaba/internal/usersettings"
)

// ModelAuthSnapshot is immutable authority for one Agent Session. Callers
// create a new value for every activation; changing global settings cannot
// alter an already-started Session.
type ModelAuthSnapshot struct {
	Mode   modelcatalog.AuthMode
	Models []modelcatalog.Model
}

// LoadModelAuthSnapshot reads the current global mode exactly once and checks
// the Project allowlist before any Session resources are created.
func LoadModelAuthSnapshot(store *usersettings.Store, allowedModels []string) (ModelAuthSnapshot, error) {
	if store == nil {
		return ModelAuthSnapshot{}, fmt.Errorf("global settings store is required before Agent Session start")
	}
	settings, err := store.Load()
	if err != nil {
		return ModelAuthSnapshot{}, fmt.Errorf("load global authentication mode before Agent Session start: %w", err)
	}
	return SnapshotModelAuth(settings, allowedModels)
}

// SnapshotModelAuth resolves authentication-specific metadata without trying
// another authentication method when the configured one is incompatible.
func SnapshotModelAuth(settings usersettings.Settings, allowedModels []string) (ModelAuthSnapshot, error) {
	if err := settings.Validate(); err != nil {
		return ModelAuthSnapshot{}, err
	}
	models, err := modelcatalog.Resolve(settings.ModelAuth, allowedModels)
	if err != nil {
		return ModelAuthSnapshot{}, fmt.Errorf("Project model allowlist is incompatible with global %s authentication: %w; change the allowlist with 'sunaba model set' or explicitly select another global method with 'sunaba model auth oauth|api-key'", settings.ModelAuth, err)
	}
	return cloneModelAuthSnapshot(ModelAuthSnapshot{Mode: settings.ModelAuth, Models: models}), nil
}

func validateModelAuthSnapshot(snapshot ModelAuthSnapshot) error {
	if err := modelcatalog.ValidateAuthMode(snapshot.Mode); err != nil {
		return fmt.Errorf("Agent Session Model authentication snapshot is invalid: %w", err)
	}
	ids := make([]string, len(snapshot.Models))
	for index := range snapshot.Models {
		ids[index] = snapshot.Models[index].ID
	}
	expected, err := modelcatalog.Resolve(snapshot.Mode, ids)
	if err != nil || !reflect.DeepEqual(expected, snapshot.Models) {
		return fmt.Errorf("Agent Session Model authentication snapshot metadata is invalid")
	}
	return nil
}

func cloneModelAuthSnapshot(snapshot ModelAuthSnapshot) ModelAuthSnapshot {
	cloned := ModelAuthSnapshot{Mode: snapshot.Mode, Models: make([]modelcatalog.Model, len(snapshot.Models))}
	copy(cloned.Models, snapshot.Models)
	for index := range cloned.Models {
		cloned.Models[index].Input = append([]string(nil), snapshot.Models[index].Input...)
		cloned.Models[index].Output = append([]string(nil), snapshot.Models[index].Output...)
	}
	return cloned
}

// ModelAuthentication returns a copy of the active Session snapshot.
func (s *Session) ModelAuthentication() ModelAuthSnapshot {
	if s == nil {
		return ModelAuthSnapshot{}
	}
	return cloneModelAuthSnapshot(s.modelAuth)
}
