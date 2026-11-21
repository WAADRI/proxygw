package panel

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"proxygw/internal/model"
	"proxygw/internal/settings"
)

// settingsResponse is the GET /api/v1/settings payload.
type settingsResponse struct {
	Current   model.Settings          `json:"current"`
	Defaults  model.Settings          `json:"defaults"`
	Version   int                     `json:"version"`
	UpdatedBy string                  `json:"updated_by,omitempty"`
	History   []settings.HistoryEntry `json:"history"`
}

// settingsMutationResponse is the PUT/undo/reset payload.
type settingsMutationResponse struct {
	Current model.Settings `json:"current"`
	Version int            `json:"version"`
}

// handleSettingsGet serves GET /api/v1/settings.
func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	history := s.opts.Settings.History()
	if history == nil {
		history = []settings.HistoryEntry{}
	}
	resp := settingsResponse{
		Current:  s.opts.Settings.Current(),
		Defaults: s.opts.Settings.Defaults(),
		Version:  s.opts.Settings.Version(),
		History:  history,
	}
	// The manager does not expose the actor of the current version; the newest
	// history entry records the apply that produced it.
	if len(history) > 0 {
		resp.UpdatedBy = history[len(history)-1].UpdatedBy
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleSettingsPut serves PUT /api/v1/settings with strict decoding and
// validation. On failure the previous settings stay in effect (422).
func (s *Server) handleSettingsPut(w http.ResponseWriter, r *http.Request) {
	var raw struct {
		Settings json.RawMessage `json:"settings"`
	}
	if !s.readJSON(w, r, &raw, true, true) {
		return
	}
	if len(raw.Settings) == 0 || string(raw.Settings) == "null" {
		s.writeValidationError(w, "缺少 settings 对象", fieldError{Field: "settings", Message: "需要完整的 settings 对象"})
		return
	}
	next, err := settings.DecodeOverride(raw.Settings)
	if err != nil {
		s.writeValidationError(w, "运行设置校验失败", parseSettingsFieldError(err))
		return
	}
	actor := sessionUsername(r)
	if err := s.opts.Settings.Apply(next, actor); err != nil {
		s.writeValidationError(w, "运行设置应用失败", parseSettingsFieldError(err))
		return
	}
	s.auditRequest(r, "settings.update", "", "ok", map[string]string{
		"version":  itoa(s.opts.Settings.Version()),
		"strategy": next.Scheduler.Strategy,
	})
	s.log.Info("运行设置已更新", "version", s.opts.Settings.Version(),
		"strategy", next.Scheduler.Strategy, "actor", actor)
	s.notify()
	s.writeJSON(w, http.StatusOK, settingsMutationResponse{
		Current: s.opts.Settings.Current(),
		Version: s.opts.Settings.Version(),
	})
}

// handleSettingsUndo serves POST /api/v1/settings/undo.
func (s *Server) handleSettingsUndo(w http.ResponseWriter, r *http.Request) {
	actor := sessionUsername(r)
	current, err := s.opts.Settings.Undo(actor)
	if err != nil {
		if errors.Is(err, settings.ErrNoUndo) {
			s.writeError(w, http.StatusConflict, "conflict", "没有可撤销的运行设置版本", nil)
			return
		}
		s.writeInternalError(w, err, "撤销运行设置失败")
		return
	}
	s.auditRequest(r, "settings.undo", "", "ok", map[string]string{"version": itoa(s.opts.Settings.Version())})
	s.log.Info("运行设置已撤销", "version", s.opts.Settings.Version(), "actor", actor)
	s.notify()
	s.writeJSON(w, http.StatusOK, settingsMutationResponse{Current: current, Version: s.opts.Settings.Version()})
}

// handleSettingsReset serves POST /api/v1/settings/reset.
func (s *Server) handleSettingsReset(w http.ResponseWriter, r *http.Request) {
	actor := sessionUsername(r)
	if err := s.opts.Settings.ResetToDefaults(actor); err != nil {
		s.writeInternalError(w, err, "恢复默认运行设置失败")
		return
	}
	s.auditRequest(r, "settings.reset", "", "ok", map[string]string{"version": itoa(s.opts.Settings.Version())})
	s.log.Info("运行设置已恢复默认", "version", s.opts.Settings.Version(), "actor", actor)
	s.notify()
	s.writeJSON(w, http.StatusOK, settingsMutationResponse{
		Current: s.opts.Settings.Current(),
		Version: s.opts.Settings.Version(),
	})
}

// parseSettingsFieldError extracts a field name from a settings validation or
// JSON decoding error. Validation errors look like "scheduler.strategy:
// unsupported strategy ..." so the prefix before the first ": " is the field.
func parseSettingsFieldError(err error) fieldError {
	message := err.Error()
	message = strings.TrimPrefix(message, "settings: ")
	message = strings.TrimPrefix(message, "invalid JSON: ")
	if idx := strings.Index(message, "json: unknown field "); idx >= 0 {
		name := strings.Trim(strings.TrimPrefix(message[idx:], "json: unknown field "), `"`)
		return fieldError{Field: name, Message: "未知字段"}
	}
	if idx := strings.Index(message, ": "); idx > 0 && idx < 160 {
		field := message[:idx]
		if isValidFieldToken(field) {
			return fieldError{Field: field, Message: message[idx+2:]}
		}
	}
	return fieldError{Field: "settings", Message: message}
}
