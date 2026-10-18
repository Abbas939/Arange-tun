package webui

import (
	"encoding/json"
	"github.com/mahdi-byte64/arange-tun/internal/manage"
	"net/http"
)

func (s *server) handleAdvancedImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	var req struct {
		Name    string `json:"name"`
		Config  string `json:"config"`
		Replace bool   `json:"replace"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	if err := manage.ImportAdvanced(req.Name, req.Config, req.Replace); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}
