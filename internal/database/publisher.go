// Net Watcher - Event Publisher Interface
// This provides a decoupled way for the watcher to publish events to WebSocket clients
package database

// EventPublisher defines an interface for publishing events to subscribers
type EventPublisher interface {
	PublishEvent(event interface{})
}

// Global event publisher (set by web server)
var globalPublisher EventPublisher

// SetEventPublisher sets the global event publisher
func SetEventPublisher(p EventPublisher) {
	globalPublisher = p
}

// PublishEvent publishes an event to the global publisher if set
func PublishEvent(event interface{}) {
	if globalPublisher != nil {
		globalPublisher.PublishEvent(event)
	}
}
