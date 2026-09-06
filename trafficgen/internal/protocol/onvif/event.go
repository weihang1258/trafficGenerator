package onvif

// event.go — config → resolved-event translation: parameters extraction,
// deterministic MessageID allocation, UsernameToken resolution (nonce from
// MessageID, digest per WSS §4.2), and same_as_response transaction-
// interaction references (design §5/§6).
import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ReqEvent is one resolved transaction (builder-facing shape).
type ReqEvent struct {
	Service    string
	Operation  string
	Action     string
	MessageID  string
	To         string
	Auth       *ReqAuth
	URI        string
	Method     string
	Categories []string
	// StreamSetup is the GetStreamUri wrapper (Stream/Protocol).
	StreamSetup *StreamSetupParam
	// Velocity is the ContinuousMove tt:PTZSpeed (decimal attribute text).
	Velocity *VelocityParam
	// ProfileToken carries the operation's token parameter.
	ProfileToken string
	// Timeout / MessageLimit are the PullMessages mandatory pair (Timeout
	// also ContinuousMove's optional duration).
	Timeout      string
	MessageLimit int64
	PanTilt      *bool
	Zoom         *bool
	// Filter / InitialTerminationTime are CreatePullPointSubscription
	// optional parameters.
	Filter                string
	InitialTerminationTime string
	// FaultNS declares the ter: namespace on the request envelope (unused
	// on requests; reserved for fixture symmetry).
	FaultNS bool
	// WireFault is propagated from config (design §7); when set the
	// generator renders an error response instead of a 2xx success.
	WireFault string
}

// ReqAuth is the resolved UsernameToken.
type ReqAuth struct {
	Username string
	Password string
	Digest   string
	NonceRaw []byte
	NonceB64 string
	Created  string
}

// StreamSetupParam is the GetStreamUri StreamSetup fixture.
type StreamSetupParam struct {
	Stream   string // RTP-Unicast | RTP-Multicast
	Protocol string // RTSP | UDP | TCP ...
}

// VelocityParam is the tt:PTZSpeed decimal attribute pair.
type VelocityParam struct{ X, Y string }

// ResolveEvent translates one ONVIFEvent into a ReqEvent against its
// session context (same-session event list for same_as_response refs).
func ResolveEvent(ev core.ONVIFEvent, sessEvents []core.ONVIFEvent, idx int) (*ReqEvent, error) {
	prefix := "s"
	return resolveEventWithPrefix(ev, sessEvents, idx, prefix)
}

// resolveEventWithPrefix carries the envelope prefix through to the rendered
// event (default "s"; the prefix-variant fixture uses "soapenv").
func resolveEventWithPrefix(ev core.ONVIFEvent, sessEvents []core.ONVIFEvent, idx int, prefix string) (*ReqEvent, error) {
	svc, ok := services[ev.Service]
	if !ok {
		return nil, fmt.Errorf("onvif: service %q is not one of the four services (device/media/ptz/events)", ev.Service)
	}
	if !svc.Ops[ev.Operation] {
		return nil, fmt.Errorf("onvif: operation %q is not a %s-service operation (WSDL operation set)", ev.Operation, ev.Service)
	}
	r := &ReqEvent{
		Service:    ev.Service,
		Operation:  ev.Operation,
		Action:     RequestAction(ev.Service, ev.Operation),
		URI:        svc.DefaultURI,
		Method:     "POST",
		To:         ev.To,
		WireFault:  ev.WireFault,
	}
	if ev.Action != "" {
		r.Action = ev.Action
	}
	if ev.URI != "" {
		r.URI = ev.URI
	}
	if ev.Method != "" {
		r.Method = ev.Method
	}
	r.MessageID = ev.MessageID
	if r.MessageID == "" || r.MessageID == "auto" {
		// Explicit per-event fixture (urn:uuid:) pins both request
		// wsa:MessageID and response wsa:RelatesTo — deterministic so
		// same_as assertions can target the exact value. Auto allocation
		// (no fixture) falls back to a deterministic per-index UUID.
		r.MessageID = defaultMessageID(svc, ev.Operation, idx)
	}
	if ev.Auth != nil {
		a := ev.Auth
		created := a.Created
		if created == "" {
			created = "2026-09-01T00:00:00Z"
		}
		var nonceRaw []byte
		nonceB64 := a.Nonce
		if nonceB64 == "" {
			sum := sha256.Sum256([]byte(r.MessageID))
			nonceRaw = sum[:16]
			nonceB64 = base64.StdEncoding.EncodeToString(nonceRaw)
		} else {
			var err error
			nonceRaw, err = base64.StdEncoding.DecodeString(nonceB64)
			if err != nil {
				nonceRaw = []byte(nonceB64)
			}
		}
		r.Auth = &ReqAuth{
			Username: a.Username, Password: a.Password,
			Digest: ComputeDigest(nonceRaw, created, a.Password),
			NonceRaw: nonceRaw, NonceB64: nonceB64, Created: created,
		}
	}
	// wsa:To same_as_response reference resolution.
	if ev.To != "" {
		v, err := resolveRef(ev.To, sessEvents, idx, "subscription_reference")
		if err != nil {
			return nil, err
		}
		if v != "" {
			r.To = v
		}
	}
	// Parameters extraction (per-operation shapes).
	p := ev.Parameters
	if p != nil {
		if cats, ok := p["category"].([]interface{}); ok {
			for _, c := range cats {
				if s, ok := c.(string); ok {
					r.Categories = append(r.Categories, s)
				}
			}
		}
		if ss, ok := p["stream_setup"].(map[string]interface{}); ok {
			r.StreamSetup = &StreamSetupParam{
				Stream:   str(ss["stream"]),
				Protocol: str(ss["protocol"]),
			}
		}
		if v := str(p["profile_token"]); v != "" {
			resolved, err := resolveRef(v, sessEvents, idx, "profiles")
			if err != nil {
				return nil, err
			}
			r.ProfileToken = firstNonEmpty(resolved, v)
		}
		if v, ok := p["timeout"].(string); ok {
			r.Timeout = v
		}
		if v, ok := p["message_limit"].(json.Number); ok {
			n, _ := v.Int64()
			r.MessageLimit = n
		} else if f, ok := p["message_limit"].(float64); ok {
			r.MessageLimit = int64(f)
		}
		if v, ok := p["pan_tilt"].(bool); ok {
			r.PanTilt = &v
		}
		if v, ok := p["zoom"].(bool); ok {
			r.Zoom = &v
		}
		if v, ok := p["filter"].(string); ok {
			r.Filter = v
		}
		if v, ok := p["initial_termination_time"].(string); ok {
			r.InitialTerminationTime = v
		}
		if v, ok := p["velocity"].(map[string]interface{}); ok {
			r.Velocity = &VelocityParam{X: str(v["x"]), Y: str(v["y"])}
		}
	}
	return r, nil
}

// defaultMessageID allocates a deterministic urn:uuid: for events without an
// explicit fixture MessageID (design §6: "auto" = 运行期分配). Distinct per
// (service, operation, index) so multi-transaction sessions get distinct IDs
// (testcase §4 #18/#25/#52.MessageID distinct 口径）.
func defaultMessageID(svc *ServiceInfo, operation string, idx int) string {
	h := fmt.Sprintf("%s/%s/%d", svc.WirePrefix, operation, idx)
	sum := sha256.Sum256([]byte(h))
	// UUID v4-shaped rendering from the hash (version/variant bits pinned):
	// 8-4-4-4-12 hex, version nibble 4, variant bits 10.
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]),
		uint16(b[4])<<8|uint16(b[5]),
		uint16(b[6])<<8|uint16(b[7]),
		uint16(b[8])<<8|uint16(b[9]),
		uint64(b[10])<<40|uint64(b[11])<<32|uint64(b[12])<<24|uint64(b[13])<<16|uint64(b[14])<<8|uint64(b[15]))
}

func str(v interface{}) string {
	s, _ := v.(string)
	return s
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// resolveRef resolves "same_as_response:<eventIdx>.<path>" references
// against the same-session event list (design §5 事务交互):
//   - "…subscription_reference" must reference a CreatePullPointSubscription
//     event whose response declares the subscription endpoint (anchor
//     "subscription" on violation);
//   - "…profiles[<i>].token" must reference a GetProfiles event whose
//     response declares profiles (anchor "correlation" on violation).
func resolveRef(ref string, sessEvents []core.ONVIFEvent, selfIdx int, kind string) (string, error) {
	const prefix = "same_as_response:"
	if !strings.HasPrefix(ref, prefix) {
		return "", nil
	}
	rest := strings.TrimPrefix(ref, prefix)
	dot := strings.Index(rest, ".")
	if dot < 0 {
		return "", fmt.Errorf("onvif: same_as_response reference %q is malformed (want <event>.<path>)", ref)
	}
	idxStr, path := rest[:dot], rest[dot+1:]
	var idx int
	if _, err := fmt.Sscanf(idxStr, "%d", &idx); err != nil {
		return "", fmt.Errorf("onvif: same_as_response reference %q has a non-numeric event index", ref)
	}
	if idx < 0 || idx >= len(sessEvents) {
		return "", fmt.Errorf("onvif: subscription reference points at event %d which does not exist in this session (subscription source)", idx)
	}
	if idx >= selfIdx {
		return "", fmt.Errorf("onvif: subscription reference points forward at event %d (must reference an earlier response)", idx)
	}
	target := sessEvents[idx]
	switch {
	case strings.HasPrefix(path, "subscription_reference"):
		if target.Operation != "CreatePullPointSubscription" {
			return "", fmt.Errorf("onvif: subscription reference points at %q, not a CreatePullPointSubscription event (subscription source)", target.Operation)
		}
		if target.Response == nil || target.Response.SubscriptionReference == "" {
			return "", fmt.Errorf("onvif: referenced event %d declares no subscription_reference in its response (subscription reference)", idx)
		}
		return target.Response.SubscriptionReference, nil
	case strings.HasPrefix(path, "profiles["):
		if target.Operation != "GetProfiles" {
			return "", fmt.Errorf("onvif: token correlation references %q, not a GetProfiles event (correlation)", target.Operation)
		}
		if target.Response == nil || len(target.Response.Profiles) == 0 {
			return "", fmt.Errorf("onvif: referenced event %d declares no profiles in its response (correlation)", idx)
		}
		// The fixture carries a small profile list; index parsing is not
		// needed for the single-profile correlation — return the first.
		return target.Response.Profiles[0].Token, nil
	}
	return "", fmt.Errorf("onvif: same_as_response path %q is not a referenceable response field", path)
}
