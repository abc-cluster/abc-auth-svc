package authsvc

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestManageListSlots_RequiresOperator(t *testing.T) {
	mgr := newRecManager(&Slot{SlotName: "x", State: "claimed"})
	s, _ := newP4Server(t, opTok, Upstreams{Nomad: okNomad("pool-x"), Hub: okHub(), Store: mgr})
	rr := httptestGET(t, s, "/manage/slots", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rr.Code)
	}
}

func TestManageListSlots_OK_StripsSecrets(t *testing.T) {
	mgr := newRecManager(&Slot{
		ID: "id1", SlotName: "calm_dassie", GroupName: "mbhg-hostgen", State: "claimed",
		MinioAccessKey: "slot-calm_dassie",
		// secrets that MUST NOT appear:
		MinioSecretKey: "SECRET-MS", NomadTokenSecret: "SECRET-NT", ClaimCode: "SECRET-CODE",
	})
	s, _ := newP4Server(t, opTok, Upstreams{Nomad: okNomad("pool-x"), Hub: okHub(), Store: mgr})
	rr := httptestGET(t, s, "/manage/slots", opHdr(opTok))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, secret := range []string{"SECRET-MS", "SECRET-NT", "SECRET-CODE"} {
		if strings.Contains(body, secret) {
			t.Errorf("secret %q leaked in list response:\n%s", secret, body)
		}
	}
	var list []publicSlot
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 1 || list[0].SlotName != "calm_dassie" || list[0].MinioAccessKey != "slot-calm_dassie" {
		t.Errorf("list wrong: %+v", list)
	}
}

func TestManageGetSlot_NotFound(t *testing.T) {
	mgr := newRecManager(nil)
	s, _ := newP4Server(t, opTok, Upstreams{Nomad: okNomad("pool-x"), Hub: okHub(), Store: mgr})
	rr := httptestGET(t, s, "/manage/slots/ghost", opHdr(opTok))
	if rr.Code != http.StatusNotFound || decodeErr(t, rr) != "not_found" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestManageGetSlot_OK_StripsSecrets(t *testing.T) {
	mgr := newRecManager(&Slot{ID: "id1", SlotName: "x", State: "claimed",
		MinioSecretKey: "SECRET-MS", NomadTokenSecret: "SECRET-NT"})
	s, _ := newP4Server(t, opTok, Upstreams{Nomad: okNomad("pool-x"), Hub: okHub(), Store: mgr})
	rr := httptestGET(t, s, "/manage/slots/x", opHdr(opTok))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "SECRET-") {
		t.Errorf("secret leaked: %s", rr.Body.String())
	}
}
