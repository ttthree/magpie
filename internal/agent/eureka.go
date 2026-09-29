package agent

// Eureka (the desktop assistant at ~/.eureka) takes models of one's own from
// its custom-model endpoints, kept as a JSON array inside its sealed
// credential store, not from a billing mode: an endpoint has a base URL, a
// key and the models it serves, and Eureka lists those models in its own
// picker under whichever runtime they fit. Adding magpie there leaves the
// user's billing mode (GitHub Copilot, a custom API, …) exactly as it is.
//
// magpie's gateway serves Chat Completions, Responses and Anthropic Messages
// on one address, so one endpoint with those three protocols covers every
// runtime Eureka can drive a custom model from. The model is picked per task
// in Eureka's window, so what magpie sets is whether its models are in that
// picker — the same as ZCode or WorkBuddy.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/yetone/magpie/internal/gateway"
)

// eurekaCustomModelsAccount is where Eureka keeps its custom-model endpoints:
// a JSON array, stringified, in the sealed store under custom_models_config.
const eurekaCustomModelsAccount = "custom_models_config::global"

// eurekaEndpointID is the id magpie's endpoint keeps, so a session that
// picked one of its models goes on resolving across catalog refreshes.
const eurekaEndpointID = "magpie"

// eurekaProtocolVersion is the validation generation Eureka stamps on a
// protocol it has probed; magpie's gateway answers all three, so magpie
// records them as passed at the current version.
const eurekaProtocolVersion = 2

// eurekaAPITypes are the three protocols Eureka can drive a custom model
// from, in its own names.
var eurekaAPITypes = []string{"openai/chat-completions", "openai/responses", "anthropic/messages"}

// eurekaConfigDir is where Eureka keeps config.json and credentials.enc:
// $CRAFT_CONFIG_DIR when set, else the legacy ~/.craft-agent once it looks
// configured, else ~/.eureka. It mirrors Eureka's own resolution.
func eurekaConfigDir(home string) string {
	if v := strings.TrimSpace(os.Getenv("CRAFT_CONFIG_DIR")); v != "" {
		return v
	}
	legacy := filepath.Join(home, ".craft-agent")
	for _, name := range []string{"config.json", "credentials.enc", "workspaces"} {
		if _, err := os.Stat(filepath.Join(legacy, name)); err == nil {
			return legacy
		}
	}
	return filepath.Join(home, ".eureka")
}

// eurekaEndpoint is one custom-model endpoint as magpie writes its own.
type eurekaEndpoint struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	BaseURL string         `json:"baseUrl"`
	Models  []eurekaCModel `json:"models"`
	Enabled bool           `json:"enabled"`
	APIKey  string         `json:"apiKey,omitempty"`
}

// eurekaCModel is one model of an endpoint.
type eurekaCModel struct {
	ID        string           `json:"id"`
	Provider  string           `json:"provider,omitempty"`
	Protocols []eurekaProtocol `json:"protocols"`
	Metadata  map[string]any   `json:"metadata,omitempty"`
}

// eurekaProtocol is one API a model is available on.
type eurekaProtocol struct {
	APIType           string `json:"apiType"`
	Status            string `json:"status"`
	ValidatedAt       int64  `json:"validatedAt,omitempty"`
	ValidationVersion int    `json:"validationVersion,omitempty"`
}

func eureka(home string) *Agent {
	dir := eurekaConfigDir(home)
	return &Agent{
		ID: "eureka", Name: "Eureka", Icon: "eureka",
		Dir: dir, Path: filepath.Join(dir, "config.json"),
		Notice: func() string {
			if Running(`Eureka\.app/`, `(^|/)Eureka( |$)`) {
				return "Eureka reads its custom models when a task starts — open a new task to see magpie's models."
			}
			return ""
		},
		Sync: func() error {
			if !eurekaHasMagpie(dir) {
				return nil
			}
			return eurekaWriteEndpoint(dir, true)
		},
		Fields: []Field{{
			Key: "provider", Label: "provider",
			Get: func() string {
				if eurekaHasMagpie(dir) {
					return magpieID
				}
				return ""
			},
			Set: func(v string) error { return eurekaWriteEndpoint(dir, v != "") },
			Options: func(map[string]string) []Option {
				return []Option{{Value: magpieID, Label: "magpie", Icon: "magpie", Note: "every magpie model in Eureka's picker"}}
			},
		}},
	}
}

// eurekaRawEndpoints is Eureka's custom-model list as stored: each entry kept
// raw so a rewrite of magpie's own leaves every other endpoint, and every
// field magpie does not know, exactly as it was. A store magpie cannot read
// is an error, so nothing is clobbered.
func eurekaRawEndpoints(dir string) ([]json.RawMessage, error) {
	store, _, err := eurekaOpenStore(dir)
	if err != nil || store == nil {
		return nil, err
	}
	creds, err := eurekaCredentials(store)
	if err != nil {
		return nil, err
	}
	raw := eurekaCredValue(creds, eurekaCustomModelsAccount)
	if raw == "" {
		return nil, nil
	}
	var eps []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &eps); err != nil {
		return nil, fmt.Errorf("Eureka's custom models aren't a list magpie can read: %w", err)
	}
	return eps, nil
}

// eurekaHasMagpie reports whether magpie's endpoint is in the store.
func eurekaHasMagpie(dir string) bool {
	eps, _ := eurekaRawEndpoints(dir)
	for _, raw := range eps {
		var e struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &e) == nil && e.ID == eurekaEndpointID {
			return true
		}
	}
	return false
}

// eurekaWriteEndpoint puts magpie's custom-model endpoint into the store (on)
// or takes it out (off), leaving every other endpoint where it is.
func eurekaWriteEndpoint(dir string, on bool) error {
	eps, err := eurekaRawEndpoints(dir)
	if err != nil {
		return err
	}
	kept := make([]json.RawMessage, 0, len(eps)+1)
	at := -1
	for _, raw := range eps {
		var e struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &e) == nil && e.ID == eurekaEndpointID {
			if at < 0 {
				at = len(kept)
			}
			continue
		}
		kept = append(kept, raw)
	}
	if !on {
		if at < 0 {
			return nil
		}
		return eurekaSaveEndpoints(dir, kept)
	}
	b, err := json.Marshal(eurekaMagpieEndpoint())
	if err != nil {
		return err
	}
	if at < 0 {
		at = len(kept)
	}
	return eurekaSaveEndpoints(dir, slices.Concat(kept[:at], []json.RawMessage{b}, kept[at:]))
}

// eurekaSaveEndpoints writes the endpoint list back into the sealed store.
func eurekaSaveEndpoints(dir string, eps []json.RawMessage) error {
	store, salt, err := eurekaOpenStore(dir)
	if err != nil {
		return err
	}
	if store == nil {
		store = newEurekaStore()
	}
	creds, err := eurekaCredentials(store)
	if err != nil {
		return err
	}
	if len(eps) == 0 {
		delete(creds, eurekaCustomModelsAccount)
	} else {
		b, err := json.Marshal(eps)
		if err != nil {
			return err
		}
		eurekaSetCredValue(creds, eurekaCustomModelsAccount, string(b))
	}
	return eurekaSaveStore(dir, store, creds, salt)
}

// eurekaMagpieEndpoint is magpie's endpoint: the gateway URL, its key for
// Eureka, and the catalog as custom models that pass all three protocols.
func eurekaMagpieEndpoint() eurekaEndpoint {
	now := time.Now().UnixMilli()
	models := []eurekaCModel{}
	for _, m := range magpieModels("eureka") {
		detected := map[string]any{"toolCalling": true, "vision": m.Images, "reasoning": len(m.Efforts) > 0}
		if m.Context > 0 {
			detected["contextWindow"] = m.Context
		}
		if m.Output > 0 {
			detected["maxOutputTokens"] = m.Output
		}
		protocols := make([]eurekaProtocol, 0, len(eurekaAPITypes))
		for _, apiType := range eurekaAPITypes {
			protocols = append(protocols, eurekaProtocol{APIType: apiType, Status: "valid",
				ValidatedAt: now, ValidationVersion: eurekaProtocolVersion})
		}
		models = append(models, eurekaCModel{
			ID:        m.ID,
			Provider:  eurekaVisualProvider(m.ID),
			Protocols: protocols,
			Metadata:  map[string]any{"detected": detected},
		})
	}
	return eurekaEndpoint{
		ID: eurekaEndpointID, Name: "magpie",
		BaseURL: gateway.URL(), Models: models, Enabled: true,
		APIKey: gateway.TokenFor("eureka"),
	}
}

// eurekaVisualProvider is the logo Eureka draws for a model, as its own
// inferCustomModelVisualProvider does: the vendor named by "provider/model".
func eurekaVisualProvider(id string) string {
	ns, model, ok := strings.Cut(strings.ToLower(id), "/")
	if !ok {
		ns, model = "", ns
	}
	switch {
	case ns == "deepseek" || strings.HasPrefix(model, "deepseek-"):
		return "deepseek"
	case ns == "qwen" || strings.HasPrefix(model, "qwen"):
		return "qwen"
	case ns == "kimi" || ns == "moonshot" || strings.HasPrefix(model, "kimi-") || strings.HasPrefix(model, "moonshot-"):
		return "kimi"
	case ns == "minimax" || strings.HasPrefix(model, "minimax-"):
		return "minimax"
	case ns == "stepfun" || strings.HasPrefix(model, "step-"):
		return "stepfun"
	case ns == "z-ai" || ns == "zai" || ns == "zhipu" || strings.HasPrefix(model, "glm-"):
		return "zai"
	case ns == "anthropic" || strings.HasPrefix(model, "claude-"):
		return "anthropic"
	case ns == "google" || strings.HasPrefix(model, "gemini-"):
		return "google"
	case ns == "openai" || strings.HasPrefix(model, "gpt-") || strings.HasPrefix(model, "codex"):
		return "openai"
	}
	return "custom"
}
