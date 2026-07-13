package auth_provider

import (
	"fmt"
	"net/http"

	"github.com/0TrustCloud/logger"
)

const idpService = "idp"

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	return r.RemoteAddr
}

func (p *Provider) logIDP(level, actor, action, message string) {
	if p.Logger == nil {
		return
	}
	p.Logger.Emit(logger.LogItem{
		Level:   level,
		Service: idpService,
		Actor:   actor,
		Action:  action,
		Message: message,
	})
}

func (p *Provider) logIDPAudit(actor, action, message string) {
	p.logIDP("AUDIT", actor, action, message)
}

func (p *Provider) logIDPInfo(action, message string) {
	p.logIDP("INFO", "", action, message)
}

func (p *Provider) logIDPError(action, message string) {
	p.logIDP("ERROR", "", action, message)
}

func (p *Provider) logIDPRequest(r *http.Request, action, detail string) {
	actor := r.URL.Query().Get("username")
	if actor == "" {
		actor = "-"
	}
	p.logIDPInfo(action, fmt.Sprintf("%s from %s", detail, clientIP(r)))
}

func (p *Provider) logIDPRequestErr(r *http.Request, action, detail string) {
	actor := r.URL.Query().Get("username")
	if actor == "" {
		actor = "-"
	}
	p.logIDPError(action, fmt.Sprintf("%s from %s", detail, clientIP(r)))
}