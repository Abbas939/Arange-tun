package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPanelRejectsCrossOriginMutation(t *testing.T) {
	h := securePanel(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct {
		origin, site string
		want         int
	}{
		{"http://panel.example", "same-origin", 204}, {"http://evil.example", "same-site", 403}, {"null", "", 403}, {"", "cross-site", 403}, {"", "", 204},
	} {
		r := httptest.NewRequest("POST", "http://panel.example/api/password", nil)
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Sec-Fetch-Site", tc.site)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("origin %q: got %d want %d", tc.origin, w.Code, tc.want)
		}
		if w.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatal("panel can be framed")
		}
	}
}
