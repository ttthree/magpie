package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/gateway"
	"github.com/yetone/magpie/internal/provider"
)

// eurekaTestHome is a sandbox HOME with Eureka's config dir, a billing mode
// already chosen, and one provider for magpie to serve.
func eurekaTestHome(t *testing.T) (home, dir string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CRAFT_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	if err := provider.Save(provider.Provider{ID: "deepseek", Name: "DeepSeek", Chat: "https://api.deepseek.com/v1", Key: "k", Models: []string{"pro"}}); err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(home, ".eureka")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"authType":"github_copilot","workspaces":[],"petVisible":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return home, dir
}

func eurekaConfigRaw(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// eurekaStoredEndpoints reads the custom-model endpoints back out of the
// sealed store, as Eureka would.
func eurekaStoredEndpoints(t *testing.T, dir string) []map[string]any {
	t.Helper()
	store, _, err := eurekaOpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if store == nil {
		return nil
	}
	creds, err := eurekaCredentials(store)
	if err != nil {
		t.Fatal(err)
	}
	raw := eurekaCredValue(creds, eurekaCustomModelsAccount)
	if raw == "" {
		return nil
	}
	var eps []map[string]any
	if err := json.Unmarshal([]byte(raw), &eps); err != nil {
		t.Fatalf("endpoints: %v (%s)", err, raw)
	}
	return eps
}

// eurekaPutCred writes a credential into a fresh or existing store.
func eurekaPutCred(t *testing.T, dir, account, value string) {
	t.Helper()
	store, salt, err := eurekaOpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if store == nil {
		store = newEurekaStore()
	}
	creds, err := eurekaCredentials(store)
	if err != nil {
		t.Fatal(err)
	}
	eurekaSetCredValue(creds, account, value)
	if err := eurekaSaveStore(dir, store, creds, salt); err != nil {
		t.Fatal(err)
	}
}

func eurekaCred(t *testing.T, dir, account string) string {
	t.Helper()
	store, _, err := eurekaOpenStore(dir)
	if err != nil || store == nil {
		return ""
	}
	creds, err := eurekaCredentials(store)
	if err != nil {
		return ""
	}
	return eurekaCredValue(creds, account)
}

func TestEurekaAddsCustomModelEndpoint(t *testing.T) {
	home, dir := eurekaTestHome(t)
	before := eurekaConfigRaw(t, dir)
	a := eureka(home)
	f := a.Field("provider")

	if err := f.Set("magpie"); err != nil {
		t.Fatal(err)
	}
	if got := f.Get(); got != "magpie" {
		t.Fatalf("get: %q", got)
	}
	// the billing mode is untouched
	if after := eurekaConfigRaw(t, dir); after != before {
		t.Fatalf("config.json changed:\n%s", after)
	}
	eps := eurekaStoredEndpoints(t, dir)
	if len(eps) != 1 {
		t.Fatalf("endpoints: %v", eps)
	}
	ep := eps[0]
	if ep["id"] != "magpie" || ep["name"] != "magpie" || ep["enabled"] != true {
		t.Fatalf("endpoint: %v", ep)
	}
	if ep["baseUrl"] != gateway.URL() {
		t.Fatalf("baseUrl: %v, want %v", ep["baseUrl"], gateway.URL())
	}
	if ep["apiKey"] != gateway.TokenFor("eureka") {
		t.Fatalf("apiKey: %v", ep["apiKey"])
	}
	models, _ := ep["models"].([]any)
	if len(models) != 1 {
		t.Fatalf("models: %v", models)
	}
	m := models[0].(map[string]any)
	if m["id"] != "deepseek/pro" {
		t.Fatalf("model id: %v", m["id"])
	}
	protocols, _ := m["protocols"].([]any)
	types := map[string]bool{}
	for _, raw := range protocols {
		p := raw.(map[string]any)
		if p["status"] != "valid" || p["validationVersion"].(float64) != eurekaProtocolVersion {
			t.Fatalf("protocol: %v", p)
		}
		types[p["apiType"].(string)] = true
	}
	for _, want := range eurekaAPITypes {
		if !types[want] {
			t.Fatalf("protocol %q missing: %v", want, types)
		}
	}

	var found bool
	for _, o := range f.Options(map[string]string{}) {
		if o.Value == "magpie" {
			found = true
		}
	}
	if !found {
		t.Fatal("magpie not offered")
	}
}

func TestEurekaLeavesOtherEndpointsAndBillingMode(t *testing.T) {
	home, dir := eurekaTestHome(t)
	mine := `[{"id":"mine","name":"My endpoint","baseUrl":"https://mine.example","models":[],"enabled":true,"apiKey":"sk-mine"}]`
	eurekaPutCred(t, dir, eurekaCustomModelsAccount, mine)
	eurekaPutCred(t, dir, "craft_oauth::global", "keep-me")

	f := eureka(home).Field("provider")
	if err := f.Set("magpie"); err != nil {
		t.Fatal(err)
	}
	eps := eurekaStoredEndpoints(t, dir)
	if len(eps) != 2 || eps[0]["id"] != "mine" || eps[1]["id"] != "magpie" {
		t.Fatalf("after add: %v", eps)
	}
	// the user's own endpoint is exactly as it was
	if b, _ := json.Marshal(eps[0]); !strings.Contains(string(b), `"apiKey":"sk-mine"`) {
		t.Fatalf("own endpoint changed: %s", b)
	}

	// turning magpie off takes only magpie's endpoint out
	if err := f.Set(""); err != nil {
		t.Fatal(err)
	}
	eps = eurekaStoredEndpoints(t, dir)
	if len(eps) != 1 || eps[0]["id"] != "mine" {
		t.Fatalf("after remove: %v", eps)
	}
	if v := eurekaCred(t, dir, "craft_oauth::global"); v != "keep-me" {
		t.Fatalf("craft_oauth: %q", v)
	}
	if f.Get() != "" {
		t.Fatalf("get after remove: %q", f.Get())
	}
	if got := eurekaConfigRaw(t, dir); got != `{"authType":"github_copilot","workspaces":[],"petVisible":true}` {
		t.Fatalf("config.json changed: %s", got)
	}
}
