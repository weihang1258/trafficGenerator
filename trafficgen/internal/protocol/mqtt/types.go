// Package mqtt implements the MQTT protocol planner (MQTT 3.1.1 / MQTT 5.0).
// Types are re-exported as aliases from core for convenience.
package mqtt

import "github.com/trafficgen/trafficgen/internal/core"

// MQTTConfig configures the MQTT protocol planner (3.1.1 / 5.0).
// Alias of core.MQTTConfig for convenience within the mqtt package.
type MQTTConfig = core.MQTTConfig

// MQTTWill is the CONNECT Will Message configuration.
type MQTTWill = core.MQTTWill

// MQTTMessage is one PUBLISH exchange.
type MQTTMessage = core.MQTTMessage

// MQTTSubscribe is one SUBSCRIBE/SUBACK exchange.
type MQTTSubscribe = core.MQTTSubscribe

// MQTTTopicFilter is one topic filter in a SUBSCRIBE.
type MQTTTopicFilter = core.MQTTTopicFilter

// MQTTProperty is one MQTT 5.0 property.
type MQTTProperty = core.MQTTProperty

// MQTTSession overrides the top-level MQTTConfig fields for one client session.
type MQTTSession = core.MQTTSession
