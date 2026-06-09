package authsvc

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func magicServer(t *testing.T) (*Server, *recManager) {
	t.Helper()
	mgr := newRecManager(&Slot{SlotName: "x", State: "claimed"})
	s, _ := newP4Server(t, "", Upstreams{
		Nomad: okNomad("pool-x"), Hub: okHub(), Store: mgr, Minio: mockMinio{},
	})
	return s, mgr
}

func issueCode(t *testing.T, s *Server, body string) string {
	t.Helper()
	rr := postJSON(t, s, "/auth/cli-token", body, map[string]string{"Content-Type": "application/json"})
	if rr.Code != http.StatusOK {
		t.Fatalf("cli-token status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		Code string `json:"code"`
		TTL  int    `json:"ttl"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Code == "" || out.TTL <= 0 {
		t.Fatalf("bad cli-token resp: %s", rr.Body.String())
	}
	return out.Code
}

func TestCLIToken_MissingBody(t *testing.T) {
	s, _ := magicServer(t)
	rr := postJSON(t, s, "/auth/cli-token", "", map[string]string{"Content-Type": "application/json"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rr.Code)
	}
}

func TestCLIToken_NomadTokenRequired(t *testing.T) {
	s, _ := magicServer(t)
	rr := postJSON(t, s, "/auth/cli-token", `{"next":"/"}`, map[string]string{"Content-Type": "application/json"})
	if rr.Code != http.StatusBadRequest || decodeErr(t, rr) != "nomad_token required" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestRedeem_SetsCookie_RedirectsToNext(t *testing.T) {
	s, _ := magicServer(t)
	code := issueCode(t, s, `{"nomad_token":"t","next":"https://workbench.seedling.abc-cluster.cloud/lab","portal":"workbench"}`)
	rr := httptestGET(t, s, "/auth/redeem?code="+code, nil)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "/lab") {
		t.Errorf("location=%q", loc)
	}
	if sc := rr.Header().Get("Set-Cookie"); !strings.Contains(sc, sessionCookieName+"=") {
		t.Errorf("missing session cookie: %q", sc)
	}
}

func TestRedeem_SingleUse(t *testing.T) {
	s, _ := magicServer(t)
	code := issueCode(t, s, `{"nomad_token":"t","next":"/"}`)
	first := httptestGET(t, s, "/auth/redeem?code="+code, nil)
	if first.Code != http.StatusFound {
		t.Fatalf("first redeem status=%d", first.Code)
	}
	second := httptestGET(t, s, "/auth/redeem?code="+code, nil)
	if second.Code != http.StatusFound || !strings.Contains(second.Header().Get("Location"), "link_expired") {
		t.Errorf("second redeem should fail link_expired, got status=%d loc=%q",
			second.Code, second.Header().Get("Location"))
	}
}

func TestRedeem_MissingCode(t *testing.T) {
	s, _ := magicServer(t)
	rr := httptestGET(t, s, "/auth/redeem", nil)
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "missing_code") {
		t.Fatalf("status=%d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
}

func TestRedeem_GrafanaPortalGoesToLogin(t *testing.T) {
	s, _ := magicServer(t)
	code := issueCode(t, s, `{"nomad_token":"t","next":"https://grafana.seedling.abc-cluster.cloud/","portal":"grafana"}`)
	rr := httptestGET(t, s, "/auth/redeem?code="+code, nil)
	if loc := rr.Header().Get("Location"); loc != "/login" {
		t.Errorf("grafana redeem should go to /login, got %q", loc)
	}
}

func TestCLIToken_MinioPortalPrefetchesJWT(t *testing.T) {
	s, _ := magicServer(t)
	// portal=minio → ConsoleLogin pre-fetch stores minio_token in the code.
	code := issueCode(t, s, `{"nomad_token":"t","portal":"minio","next":"/"}`)
	// Redeem via /auth/minio-login should set the MinIO token cookie.
	rr := httptestGET(t, s, "/auth/minio-login?code="+code, nil)
	if rr.Code != http.StatusFound {
		t.Fatalf("minio-login status=%d", rr.Code)
	}
	if sc := rr.Header().Get("Set-Cookie"); !strings.Contains(sc, "token=mock-jwt-x") {
		t.Errorf("expected MinIO token cookie, got %q", sc)
	}
}

func TestCLIToken_SuspendedSlotRejected(t *testing.T) {
	mgr := newRecManager(&Slot{SlotName: "x", State: "suspended"})
	s, _ := newP4Server(t, "", Upstreams{Nomad: okNomad("pool-x"), Hub: okHub(), Store: mgr, Minio: mockMinio{}})
	rr := postJSON(t, s, "/auth/cli-token", `{"nomad_token":"t","next":"/"}`, map[string]string{"Content-Type": "application/json"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403 body=%s", rr.Code, rr.Body.String())
	}
}
