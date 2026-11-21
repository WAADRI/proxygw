package panel

import (
	"net/http"
	"strings"

	"proxygw/internal/acl"
	"proxygw/internal/model"
)

// aclListResponse is the GET/PUT /rules/acl payload.
type aclListResponse struct {
	Items         []model.ACLRule `json:"items"`
	DefaultAction string          `json:"default_action"`
}

// aclForcedResponse is the GET /rules/acl/forced payload.
type aclForcedResponse struct {
	Items []acl.ForcedRule `json:"items"`
}

// aclRuleRequest is the create/update body for ACL rules.
type aclRuleRequest struct {
	Order     *int      `json:"order"`
	SrcCIDRs  *[]string `json:"src_cidrs"`
	Domains   *[]string `json:"domains"`
	Ports     *[]string `json:"ports"`
	Protocols *[]string `json:"protocols"`
	Action    *string   `json:"action"`
	Note      *string   `json:"note"`
}

// apply copies the provided fields onto rule.
func (req *aclRuleRequest) apply(rule *model.ACLRule) {
	if req.Order != nil {
		rule.Order = *req.Order
	}
	if req.SrcCIDRs != nil {
		rule.SrcCIDRs = *req.SrcCIDRs
	}
	if req.Domains != nil {
		rule.Domains = *req.Domains
	}
	if req.Ports != nil {
		rule.Ports = *req.Ports
	}
	if req.Protocols != nil {
		rule.Protocols = *req.Protocols
	}
	if req.Action != nil {
		rule.Action = strings.ToLower(strings.TrimSpace(*req.Action))
	}
	if req.Note != nil {
		rule.Note = strings.TrimSpace(*req.Note)
	}
}

// handleACLGet serves GET /api/v1/rules/acl.
func (s *Server) handleACLGet(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, s.aclList())
}

// aclList builds the ACL list response from the rule store.
func (s *Server) aclList() aclListResponse {
	items := s.opts.Rules.ACL()
	if items == nil {
		items = []model.ACLRule{}
	}
	return aclListResponse{Items: items, DefaultAction: s.opts.Settings.Current().DefaultACLAction}
}

// handleACLReplace serves PUT /api/v1/rules/acl (full replacement).
func (s *Server) handleACLReplace(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Items *[]model.ACLRule `json:"items"`
	}
	if !s.readJSON(w, r, &req, true, false) {
		return
	}
	if req.Items == nil {
		s.writeValidationError(w, "缺少 items 字段", fieldError{Field: "items", Message: "全量替换需要 items 数组"})
		return
	}
	candidate := *req.Items
	if err := s.opts.ACL.SetRules(candidate); err != nil {
		s.writeValidationError(w, "ACL 规则校验失败", parseStoreFieldError(err, "items"))
		return
	}
	if err := s.opts.Rules.SetACL(candidate); err != nil {
		s.syncACLEngine()
		s.writeValidationError(w, "ACL 规则保存失败", parseStoreFieldError(err, "items"))
		return
	}
	s.syncACLEngine()
	s.auditRequest(r, "acl.replace", "", "ok", map[string]string{"count": itoa(len(candidate))})
	s.log.Info("ACL 规则已全量替换", "count", len(candidate), "actor", sessionUsername(r))
	s.notify()
	s.writeJSON(w, http.StatusOK, s.aclList())
}

// handleACLCreate serves POST /api/v1/rules/acl.
func (s *Server) handleACLCreate(w http.ResponseWriter, r *http.Request) {
	var req aclRuleRequest
	if !s.readJSON(w, r, &req, true, false) {
		return
	}
	rule := model.ACLRule{}
	req.apply(&rule)
	rule.ID = "" // POST always creates; ignore any client supplied id
	current := s.opts.Rules.ACL()
	candidate := append(append([]model.ACLRule(nil), current...), rule)
	if err := s.opts.ACL.SetRules(candidate); err != nil {
		s.writeValidationError(w, "ACL 规则校验失败", parseStoreFieldError(err, "items"))
		return
	}
	created, err := s.opts.Rules.UpsertACL(rule)
	if err != nil {
		s.syncACLEngine()
		s.writeValidationError(w, "ACL 规则保存失败", parseStoreFieldError(err, "items"))
		return
	}
	s.syncACLEngine()
	s.auditRequest(r, "acl.create", created.ID, "ok", map[string]string{"action": created.Action})
	s.notify()
	s.writeJSON(w, http.StatusOK, created)
}

// handleACLUpdate serves PATCH /api/v1/rules/acl/{id}.
func (s *Server) handleACLUpdate(w http.ResponseWriter, r *http.Request) {
	ruleID := strings.TrimSpace(r.PathValue("id"))
	current := s.opts.Rules.ACL()
	existing, found := findACLRule(current, ruleID)
	if !found {
		s.writeError(w, http.StatusNotFound, "not_found", "ACL 规则不存在", nil)
		return
	}
	var req aclRuleRequest
	if !s.readJSON(w, r, &req, true, false) {
		return
	}
	req.apply(&existing)
	candidate := make([]model.ACLRule, 0, len(current))
	for _, rule := range current {
		if rule.ID == ruleID {
			candidate = append(candidate, existing)
			continue
		}
		candidate = append(candidate, rule)
	}
	if err := s.opts.ACL.SetRules(candidate); err != nil {
		s.writeValidationError(w, "ACL 规则校验失败", parseStoreFieldError(err, "items"))
		return
	}
	updated, err := s.opts.Rules.UpsertACL(existing)
	if err != nil {
		s.syncACLEngine()
		s.writeValidationError(w, "ACL 规则保存失败", parseStoreFieldError(err, "items"))
		return
	}
	s.syncACLEngine()
	s.auditRequest(r, "acl.update", ruleID, "ok", nil)
	s.notify()
	s.writeJSON(w, http.StatusOK, updated)
}

// handleACLDelete serves DELETE /api/v1/rules/acl/{id}.
func (s *Server) handleACLDelete(w http.ResponseWriter, r *http.Request) {
	ruleID := strings.TrimSpace(r.PathValue("id"))
	if _, found := findACLRule(s.opts.Rules.ACL(), ruleID); !found {
		s.writeError(w, http.StatusNotFound, "not_found", "ACL 规则不存在", nil)
		return
	}
	if err := s.opts.Rules.DeleteACL(ruleID); err != nil {
		s.writeInternalError(w, err, "删除 ACL 规则失败")
		return
	}
	s.syncACLEngine()
	s.auditRequest(r, "acl.delete", ruleID, "ok", nil)
	s.notify()
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleACLForced serves GET /api/v1/rules/acl/forced.
func (s *Server) handleACLForced(w http.ResponseWriter, r *http.Request) {
	items := s.opts.ACL.ForcedDenies()
	if items == nil {
		items = []acl.ForcedRule{}
	}
	s.writeJSON(w, http.StatusOK, aclForcedResponse{Items: items})
}

// findACLRule returns the rule with the given id.
func findACLRule(rules []model.ACLRule, ruleID string) (model.ACLRule, bool) {
	for _, rule := range rules {
		if rule.ID == ruleID {
			return rule, true
		}
	}
	return model.ACLRule{}, false
}

// syncACLEngine hot-reloads the ACL engine from the rule store. The store is
// the source of truth; a compile failure can only mean a bug, so it is logged
// instead of surfacing a request error at this point.
func (s *Server) syncACLEngine() {
	if err := s.opts.ACL.SetRules(s.opts.Rules.ACL()); err != nil {
		s.log.Error("ACL 引擎热加载失败", "error", err)
	}
}

// --- sticky blacklist ------------------------------------------------------

// stickyListResponse is the GET /rules/sticky payload.
type stickyListResponse struct {
	Items []model.StickyRule `json:"items"`
}

// stickyRuleRequest is the create/update body for sticky rules.
type stickyRuleRequest struct {
	Enabled    *bool             `json:"enabled"`
	Note       *string           `json:"note"`
	Target     *model.TargetSpec `json:"target"`
	NodeGroups *[]string         `json:"node_groups"`
	NodeIDs    *[]string         `json:"node_ids"`
}

// stickyPreviewRequest is the POST /rules/sticky/preview body.
type stickyPreviewRequest struct {
	Host   string   `json:"host"`
	IP     string   `json:"ip"`
	Port   int      `json:"port"`
	NodeID string   `json:"node_id"`
	Groups []string `json:"groups"`
}

// stickyPreviewResponse is the preview result.
type stickyPreviewResponse struct {
	Hit          bool   `json:"hit"`
	RuleID       string `json:"rule_id,omitempty"`
	Reason       string `json:"reason,omitempty"`
	ForcedNodeID string `json:"forced_node_id,omitempty"`
}

// apply copies the provided fields onto rule.
func (req *stickyRuleRequest) apply(rule *model.StickyRule) {
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if req.Note != nil {
		rule.Note = strings.TrimSpace(*req.Note)
	}
	if req.Target != nil {
		rule.Target = *req.Target
	}
	if req.NodeGroups != nil {
		rule.NodeGroups = *req.NodeGroups
	}
	if req.NodeIDs != nil {
		rule.NodeIDs = *req.NodeIDs
	}
}

// handleStickyList serves GET /api/v1/rules/sticky.
func (s *Server) handleStickyList(w http.ResponseWriter, r *http.Request) {
	items := s.opts.Rules.Sticky()
	if items == nil {
		items = []model.StickyRule{}
	}
	s.writeJSON(w, http.StatusOK, stickyListResponse{Items: items})
}

// handleStickyCreate serves POST /api/v1/rules/sticky.
func (s *Server) handleStickyCreate(w http.ResponseWriter, r *http.Request) {
	var req stickyRuleRequest
	if !s.readJSON(w, r, &req, true, false) {
		return
	}
	rule := model.StickyRule{Enabled: true}
	req.apply(&rule)
	rule.ID = ""
	if strings.TrimSpace(rule.Note) == "" {
		// The rules store requires a note for new rules; the panel form marks it
		// optional, so derive a readable summary instead of rejecting the rule.
		rule.Note = stickyNoteFromRule(rule)
	}
	previous := s.opts.Rules.Sticky()
	created, err := s.opts.Rules.UpsertSticky(rule)
	if err != nil {
		s.writeValidationError(w, "粘性黑名单规则无效", parseStoreFieldError(err, "items"))
		return
	}
	if err := s.syncStickyEngine(previous); err != nil {
		s.writeValidationError(w, "粘性黑名单规则编译失败", parseStoreFieldError(err, "items"))
		return
	}
	s.auditRequest(r, "sticky.create", created.ID, "ok", map[string]string{"note": created.Note})
	s.notify()
	s.writeJSON(w, http.StatusOK, created)
}

// handleStickyUpdate serves PATCH /api/v1/rules/sticky/{id}.
func (s *Server) handleStickyUpdate(w http.ResponseWriter, r *http.Request) {
	ruleID := strings.TrimSpace(r.PathValue("id"))
	stored := s.opts.Rules.Sticky()
	existing, found := findStickyRule(stored, ruleID)
	if !found {
		s.writeError(w, http.StatusNotFound, "not_found", "粘性黑名单规则不存在", nil)
		return
	}
	var req stickyRuleRequest
	if !s.readJSON(w, r, &req, true, false) {
		return
	}
	req.apply(&existing)
	previous := append([]model.StickyRule(nil), stored...)
	updated, err := s.opts.Rules.UpsertSticky(existing)
	if err != nil {
		s.writeValidationError(w, "粘性黑名单规则无效", parseStoreFieldError(err, "items"))
		return
	}
	if err := s.syncStickyEngine(previous); err != nil {
		s.writeValidationError(w, "粘性黑名单规则编译失败", parseStoreFieldError(err, "items"))
		return
	}
	s.auditRequest(r, "sticky.update", ruleID, "ok", map[string]string{"enabled": boolText(updated.Enabled)})
	s.notify()
	s.writeJSON(w, http.StatusOK, updated)
}

// handleStickyDelete serves DELETE /api/v1/rules/sticky/{id}.
func (s *Server) handleStickyDelete(w http.ResponseWriter, r *http.Request) {
	ruleID := strings.TrimSpace(r.PathValue("id"))
	stored := s.opts.Rules.Sticky()
	if _, found := findStickyRule(stored, ruleID); !found {
		s.writeError(w, http.StatusNotFound, "not_found", "粘性黑名单规则不存在", nil)
		return
	}
	previous := append([]model.StickyRule(nil), stored...)
	if err := s.opts.Rules.DeleteSticky(ruleID); err != nil {
		s.writeInternalError(w, err, "删除粘性黑名单规则失败")
		return
	}
	if err := s.syncStickyEngine(previous); err != nil {
		s.writeInternalError(w, err, "粘性黑名单规则热加载失败")
		return
	}
	s.auditRequest(r, "sticky.delete", ruleID, "ok", nil)
	s.notify()
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleStickyPreview serves POST /api/v1/rules/sticky/preview.
func (s *Server) handleStickyPreview(w http.ResponseWriter, r *http.Request) {
	if s.opts.Sched == nil {
		s.writeUnavailable(w, "调度器")
		return
	}
	var req stickyPreviewRequest
	if !s.readJSON(w, r, &req, true, false) {
		return
	}
	if req.Port < 0 || req.Port > 65535 {
		s.writeValidationError(w, "端口非法", fieldError{Field: "port", Message: "期望 0-65535"})
		return
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		host = strings.TrimSpace(req.IP)
	}
	target := model.RequestTarget{
		Protocol: model.ProtoHTTP,
		Host:     host,
		Port:     req.Port,
	}
	preview := s.opts.Sched.PreviewSticky(target, strings.TrimSpace(req.NodeID), req.Groups)
	resp := stickyPreviewResponse{
		Hit:          preview.Hit,
		RuleID:       preview.RuleID,
		Reason:       preview.Reason,
		ForcedNodeID: preview.ForcedNodeID,
	}
	if resp.Hit && resp.Reason == "" {
		resp.Reason = s.stickyRuleReason(preview.RuleID)
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// stickyRuleReason renders a human readable reason for a rule id.
func (s *Server) stickyRuleReason(ruleID string) string {
	if ruleID == "" {
		return "命中粘性黑名单规则"
	}
	if rule, found := findStickyRule(s.opts.Rules.Sticky(), ruleID); found && strings.TrimSpace(rule.Note) != "" {
		return "命中粘性黑名单规则：" + strings.TrimSpace(rule.Note)
	}
	return "命中粘性黑名单规则 " + ruleID
}

// stickyNoteFromRule derives a readable note for a rule created without one.
func stickyNoteFromRule(rule model.StickyRule) string {
	parts := make([]string, 0, 4)
	if len(rule.Target.Domains) > 0 {
		parts = append(parts, "域名 "+strings.Join(rule.Target.Domains, ","))
	}
	if len(rule.Target.CIDRs) > 0 {
		parts = append(parts, "CIDR "+strings.Join(rule.Target.CIDRs, ","))
	}
	if len(rule.NodeGroups) > 0 {
		parts = append(parts, "节点组 "+strings.Join(rule.NodeGroups, ","))
	}
	if len(rule.NodeIDs) > 0 {
		parts = append(parts, "节点 "+strings.Join(rule.NodeIDs, ","))
	}
	if len(parts) == 0 {
		return "未命名粘性黑名单规则"
	}
	note := "粘性黑名单：" + strings.Join(parts, "；")
	if len(note) > 512 {
		note = note[:512]
	}
	return note
}

// findStickyRule returns the sticky rule with the given id.
func findStickyRule(stored []model.StickyRule, ruleID string) (model.StickyRule, bool) {
	for _, rule := range stored {
		if rule.ID == ruleID {
			return rule, true
		}
	}
	return model.StickyRule{}, false
}

// syncStickyEngine pushes the stored sticky rules into the running scheduler.
// On a compile failure the previous rule set is restored in the store so store
// and scheduler never diverge.
func (s *Server) syncStickyEngine(previous []model.StickyRule) error {
	if s.opts.Sched == nil {
		return nil
	}
	if err := s.opts.Sched.SetRules(s.opts.Rules.Sticky()); err != nil {
		if rollbackErr := s.opts.Rules.SetSticky(previous); rollbackErr != nil {
			s.log.Error("粘性黑名单规则回滚失败", "error", rollbackErr)
		}
		return err
	}
	return nil
}
