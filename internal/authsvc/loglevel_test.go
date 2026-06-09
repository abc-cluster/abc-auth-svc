package authsvc

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"
)

func TestLogLevel_RequiresOperator(t *testing.T) {
	s, _ := newP4Server(t, opTok, Upstreams{Nomad: okNomad("pool-x"), Hub: okHub()})
	rr := httptestGET(t, s, "/manage/log-level", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rr.Code)
	}
}

func TestLogLevel_GET_ReportsMutability(t *testing.T) {
	s, _ := newP4Server(t, opTok, Upstreams{Nomad: okNomad("pool-x"), Hub: okHub()})
	// No LevelVar wired → mutable=false.
	rr := httptestGET(t, s, "/manage/log-level", opHdr(opTok))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	var out struct {
		Level   string `json:"level"`
		Mutable bool   `json:"mutable"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.Mutable {
		t.Errorf("mutable should be false without a LevelVar")
	}
}

func TestLogLevel_POST_NotMutableWithoutLevelVar(t *testing.T) {
	s, _ := newP4Server(t, opTok, Upstreams{Nomad: okNomad("pool-x"), Hub: okHub()})
	rr := postJSON(t, s, "/manage/log-level", `{"level":"debug"}`,
		map[string]string{"X-Operator-Token": opTok, "Content-Type": "application/json"})
	if rr.Code != http.StatusConflict || decodeErr(t, rr) != "level_not_mutable" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestLogLevel_POST_ChangesLevelLive(t *testing.T) {
	s, _ := newP4Server(t, opTok, Upstreams{Nomad: okNomad("pool-x"), Hub: okHub()})
	lv := new(slog.LevelVar)
	lv.Set(L1)
	s.SetLevelVar(lv)

	rr := postJSON(t, s, "/manage/log-level", `{"level":"trace"}`,
		map[string]string{"X-Operator-Token": opTok, "Content-Type": "application/json"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if lv.Level() != L3 {
		t.Errorf("level not set to trace (L3): got %v", lv.Level())
	}
	// GET should now report trace + mutable.
	g := httptestGET(t, s, "/manage/log-level", opHdr(opTok))
	var out struct {
		Level   string `json:"level"`
		Mutable bool   `json:"mutable"`
	}
	_ = json.Unmarshal(g.Body.Bytes(), &out)
	if out.Level != "trace" || !out.Mutable {
		t.Errorf("GET after set: level=%q mutable=%v", out.Level, out.Mutable)
	}
}

func TestLogLevel_POST_InvalidLevel(t *testing.T) {
	s, _ := newP4Server(t, opTok, Upstreams{Nomad: okNomad("pool-x"), Hub: okHub()})
	lv := new(slog.LevelVar)
	s.SetLevelVar(lv)
	rr := postJSON(t, s, "/manage/log-level", `{"level":"shout"}`,
		map[string]string{"X-Operator-Token": opTok, "Content-Type": "application/json"})
	if rr.Code != http.StatusBadRequest || decodeErr(t, rr) != "invalid_level" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}
