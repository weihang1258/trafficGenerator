// Package onvif implements the ONVIF terminal layer (Core Spec Ver. 26.06,
// [ip→tcp→http→onvif] chain, plaintext HTTP/1.1 main profile
// onvif_soap12_http).
//
// Wire-format authority: docs/protocol-designs/67-onvif-design.md v2.1.1 §3 —
// SOAP 1.2 envelope encoding (§3.2), WS-Addressing headers + the response
// Action derivation rule (§3.3: strip a trailing "Request" then append
// "Response"), WS-Security UsernameToken (§3.4), the four services' eleven
// operations with WSDL-verified shapes (§3.5: tds/trt/tptz(ver20)/tev
// namespaces, plural Profiles, tds-local NetworkInterfaces, tt: payload
// elements), SOAP 1.2 Fault (§3.6), and the pinned HTTP header sets (§3.1).
//
// The generator emits complete HTTP frames as MessageEvents; the http layer
// forwards them verbatim (identity transformer) and the tcp layer owns
// segmentation, handshake, and teardown.
package onvif

// Namespace URIs (design §3.2/§3.3/§3.5 tables; WSDL-verified).
const (
	NSSoapEnv = "http://www.w3.org/2003/05/soap-envelope"
	NSWsa     = "http://www.w3.org/2005/08/addressing"
	NSwsnt    = "http://docs.oasis-open.org/wsn/b-2"
	NStds     = "http://www.onvif.org/ver10/device/wsdl"
	NStrt     = "http://www.onvif.org/ver10/media/wsdl"
	NStev     = "http://www.onvif.org/ver10/events/wsdl"
	NStptz    = "http://www.onvif.org/ver20/ptz/wsdl"
	NStt      = "http://www.onvif.org/ver10/schema"
	NSter     = "http://www.onvif.org/ver10/error"
	NSsecext  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	NSutility = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"

	// FaultActionURI is the wsa:Action for SOAP Faults (Core Spec §9.9).
	FaultActionURI = "http://www.w3.org/2005/08/addressing/soap/fault"
	// ConcreteSetDialect is the ONVIF topic expression dialect.
	ConcreteSetDialect = "http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet"

	// PasswordDigestType / NonceEncodingType (WSS UsernameToken Profile).
	PasswordDigestType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
	NonceEncodingType  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
)

// ServiceInfo describes one ONVIF service: its wire-prefix (WSDL-verified:
// device→tds, media→trt, ptz→tptz(ver20), events→tev), namespace, default
// endpoint path, and WSDL operations.
type ServiceInfo struct {
	// WirePrefix is the element/parameter prefix on the wire (§3.5
	// elementFormDefault=qualified): "tds"/"trt"/"tptz"/"tev" per the
	// WSDL target namespaces — distinct from the config service key
	// (device/media/ptz/events).
	WirePrefix string
	NS         string
	DefaultURI string
	Ops        map[string]bool
}

// services is the four-service registry (design §3.5; operation sets are the
// eleven WSDL-verified operations this version carries). The map key is the
// config service name; WirePrefix is the wire prefix (WSDL 实测：设备服务
// 顶层元素 tds:GetSystemDateAndTime，media→trt:，ptz→tptz:，events→tev:）。
var services = map[string]*ServiceInfo{
	"device": {WirePrefix: "tds", NS: NStds, DefaultURI: "/onvif/device_service",
		Ops: map[string]bool{
			"GetSystemDateAndTime": true, "GetCapabilities": true,
			"GetDeviceInformation": true, "GetNetworkInterfaces": true,
		}},
	"media": {WirePrefix: "trt", NS: NStrt, DefaultURI: "/onvif/media_service",
		Ops: map[string]bool{
			"GetProfiles": true, "GetStreamUri": true, "GetSnapshotUri": true,
		}},
	"ptz": {WirePrefix: "tptz", NS: NStptz, DefaultURI: "/onvif/ptz_service",
		Ops: map[string]bool{
			"ContinuousMove": true, "Stop": true,
		}},
	"events": {WirePrefix: "tev", NS: NStev, DefaultURI: "/onvif/event_service",
		Ops: map[string]bool{
			"CreatePullPointSubscription": true, "PullMessages": true,
		}},
}

// Service resolves a service name (nil when unknown).
func Service(name string) *ServiceInfo { return services[name] }

// RequestAction derives the request wsa:Action for an operation (WSDL
// soapAction forms; the two events-service ops carry the PortType/prefix
// forms per Core Spec §9.10.3/§9.10.5).
func RequestAction(service, operation string) string {
	switch operation {
	case "CreatePullPointSubscription":
		return NStev + "/EventPortType/CreatePullPointSubscriptionRequest"
	case "PullMessages":
		return NStev + "/PullPointSubscription/PullMessagesRequest"
	}
	svc := services[service]
	if svc == nil {
		return ""
	}
	return svc.NS + "/" + operation
}

// ResponseAction derives the response wsa:Action from the effective request
// Action (design §3.3 D-1: strip a trailing "Request" if present, then
// append "Response").
func ResponseAction(requestAction string) string {
	const reqSuffix = "Request"
	const respSuffix = "Response"
	a := requestAction
	if strings_HasSuffix(a, reqSuffix) {
		a = a[:len(a)-len(reqSuffix)]
	}
	return a + respSuffix
}

// strings_HasSuffix avoids importing strings in this table file.
func strings_HasSuffix(s, suf string) bool {
	if len(s) < len(suf) {
		return false
	}
	return s[len(s)-len(suf):] == suf
}

// requiresAuth reports whether an operation is READ_SYSTEM (Core Spec
// §5.9.4.3): unauthenticated requests must carry an auth declaration or an
// explicit error-response (401 challenge / 400 auth Fault) declaration.
func requiresAuth(operation string) bool {
	return operation == "GetDeviceInformation" || operation == "GetNetworkInterfaces"
}
