package panel

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"proxygw/internal/groups"
	"proxygw/internal/model"
)

// groupResponse is one item of GET /api/v1/groups: the stored group plus the
// realtime member count.
type groupResponse struct {
	model.Group
	MemberCount int `json:"member_count"`
}

// groupsListResponse is the GET /api/v1/groups payload.
type groupsListResponse struct {
	Items []groupResponse `json:"items"`
}

// groupRequest is the create/update body for node groups.
type groupRequest struct {
	Name        *string           `json:"name"`
	Description *string           `json:"description"`
	Match       *model.GroupMatch `json:"match"`
	NodesAdd    *[]string         `json:"nodes_add"`
	NodesRemove *[]string         `json:"nodes_remove"`
}

// handleGroupsList serves GET /api/v1/groups.
func (s *Server) handleGroupsList(w http.ResponseWriter, r *http.Request) {
	stored := s.opts.Groups.List()
	counts := s.groupMemberCounts()
	items := make([]groupResponse, 0, len(stored))
	for _, group := range stored {
		items = append(items, groupResponse{Group: group, MemberCount: counts[group.ID]})
	}
	s.writeJSON(w, http.StatusOK, groupsListResponse{Items: items})
}

// handleGroupCreate serves POST /api/v1/groups.
func (s *Server) handleGroupCreate(w http.ResponseWriter, r *http.Request) {
	var req groupRequest
	if !s.readJSON(w, r, &req, true, false) {
		return
	}
	if req.Name == nil || strings.TrimSpace(*req.Name) == "" {
		s.writeValidationError(w, "节点组名称不能为空", fieldError{Field: "name", Message: "不能为空"})
		return
	}
	group := model.Group{Name: strings.TrimSpace(*req.Name)}
	group.Description = stringValue(req.Description)
	if req.Match != nil {
		group.Match = *req.Match
	}
	group.NodesAdd = stringSliceValue(req.NodesAdd)
	group.NodesRemove = stringSliceValue(req.NodesRemove)

	created, err := s.opts.Groups.Upsert(group)
	if err != nil {
		s.writeValidationError(w, "节点组创建失败", parseStoreFieldError(err, "name"))
		return
	}
	s.auditRequest(r, "group.create", created.ID, "ok", map[string]string{"name": created.Name})
	s.log.Info("节点组已创建", "group_id", created.ID, "name", created.Name, "actor", sessionUsername(r))
	s.notify()
	s.writeJSON(w, http.StatusOK, groupResponse{Group: created, MemberCount: s.groupMemberCount(created.ID)})
}

// handleGroupUpdate serves PATCH /api/v1/groups/{id}.
func (s *Server) handleGroupUpdate(w http.ResponseWriter, r *http.Request) {
	groupID := strings.TrimSpace(r.PathValue("id"))
	existing, ok := s.opts.Groups.Get(groupID)
	if !ok {
		s.writeError(w, http.StatusNotFound, "not_found", "节点组不存在", nil)
		return
	}
	var req groupRequest
	if !s.readJSON(w, r, &req, true, false) {
		return
	}
	next := existing
	if req.Name != nil {
		next.Name = strings.TrimSpace(*req.Name)
	}
	if req.Description != nil {
		next.Description = strings.TrimSpace(*req.Description)
	}
	if req.Match != nil {
		next.Match = *req.Match
	}
	if req.NodesAdd != nil {
		next.NodesAdd = *req.NodesAdd
	}
	if req.NodesRemove != nil {
		next.NodesRemove = *req.NodesRemove
	}
	updated, err := s.opts.Groups.Upsert(next)
	if err != nil {
		if errors.Is(err, groups.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "not_found", "节点组不存在", nil)
			return
		}
		s.writeValidationError(w, "节点组更新失败", parseStoreFieldError(err, "name"))
		return
	}
	s.auditRequest(r, "group.update", groupID, "ok", map[string]string{"name": updated.Name})
	s.log.Info("节点组已更新", "group_id", groupID, "name", updated.Name, "actor", sessionUsername(r))
	s.notify()
	s.writeJSON(w, http.StatusOK, groupResponse{Group: updated, MemberCount: s.groupMemberCount(groupID)})
}

// groupInUseError is the 409 payload when a group is still referenced.
type groupInUseError struct {
	Error       string       `json:"error"`
	Message     string       `json:"message"`
	Credentials []string     `json:"credentials,omitempty"`
	Fields      []fieldError `json:"field_errors,omitempty"`
}

// handleGroupDelete serves DELETE /api/v1/groups/{id}.
func (s *Server) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	groupID := strings.TrimSpace(r.PathValue("id"))
	group, ok := s.opts.Groups.Get(groupID)
	if !ok {
		s.writeError(w, http.StatusNotFound, "not_found", "节点组不存在", nil)
		return
	}
	if users := s.credentialsReferencingGroup(groupID); len(users) > 0 {
		s.writeJSON(w, http.StatusConflict, groupInUseError{
			Error:       "group_in_use",
			Message:     "节点组仍被代理凭据引用，请先解除绑定",
			Credentials: users,
		})
		return
	}
	if err := s.opts.Groups.Delete(groupID); err != nil {
		if errors.Is(err, groups.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "not_found", "节点组不存在", nil)
			return
		}
		s.writeInternalError(w, err, "删除节点组失败")
		return
	}
	s.auditRequest(r, "group.delete", groupID, "ok", map[string]string{"name": group.Name})
	s.log.Info("节点组已删除", "group_id", groupID, "name", group.Name, "actor", sessionUsername(r))
	s.notify()
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// groupMembersResponse is the GET /groups/{id}/members payload.
type groupMembersResponse struct {
	Nodes []model.Node `json:"nodes"`
	Count int          `json:"count"`
}

// handleGroupMembers previews the current members of one group.
func (s *Server) handleGroupMembers(w http.ResponseWriter, r *http.Request) {
	groupID := strings.TrimSpace(r.PathValue("id"))
	if _, ok := s.opts.Groups.Get(groupID); !ok {
		s.writeError(w, http.StatusNotFound, "not_found", "节点组不存在", nil)
		return
	}
	members := s.groupMembers(groupID)
	s.writeJSON(w, http.StatusOK, groupMembersResponse{Nodes: members, Count: len(members)})
}

// groupMembers resolves the realtime members of one group.
func (s *Server) groupMembers(groupID string) []model.Node {
	nodeList := s.opts.Registry.List()
	members := make([]model.Node, 0, len(nodeList))
	for i := range nodeList {
		node := &nodeList[i]
		if containsString(s.opts.Groups.ForNode(node), groupID) {
			members = append(members, *node)
		}
	}
	sortNodes(members)
	return members
}

// groupMemberCount returns the number of nodes currently in one group.
func (s *Server) groupMemberCount(groupID string) int {
	return len(s.groupMembers(groupID))
}

// groupMemberCounts counts members for every group in one registry pass.
func (s *Server) groupMemberCounts() map[string]int {
	counts := make(map[string]int)
	nodeList := s.opts.Registry.List()
	for i := range nodeList {
		node := &nodeList[i]
		for _, groupID := range s.opts.Groups.ForNode(node) {
			counts[groupID]++
		}
	}
	return counts
}

// credentialsReferencingGroup returns the usernames of credentials that bind the
// given group explicitly.
func (s *Server) credentialsReferencingGroup(groupID string) []string {
	credentials := s.opts.Auth.List()
	users := make([]string, 0)
	for _, cred := range credentials {
		if containsString(cred.Groups, groupID) {
			users = append(users, cred.Username)
		}
	}
	sort.Strings(users)
	return users
}

// stringValue dereferences an optional string.
func stringValue(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}

// stringSliceValue dereferences and copies an optional string slice.
func stringSliceValue(v *[]string) []string {
	if v == nil {
		return nil
	}
	if len(*v) == 0 {
		return nil
	}
	out := make([]string, len(*v))
	copy(out, *v)
	return out
}
