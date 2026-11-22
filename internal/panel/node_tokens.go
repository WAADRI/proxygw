package panel

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"proxygw/internal/model"
	"proxygw/internal/nodesauth"
)

// Node token management. The clear-text token is returned exactly once by the
// issue endpoint; the list endpoint only exposes metadata (never a digest).

var nodeTokenNodeIDRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// nodeTokenView is the panel-safe view of one node token.
type nodeTokenView struct {
	NodeID    string    `json:"node_id"`
	Note      string    `json:"note,omitempty"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

type nodeTokenListResponse struct {
	Items []nodeTokenView `json:"items"`
}

type nodeTokenIssueRequest struct {
	NodeID string `json:"node_id"`
	Note   string `json:"note"`
}

type nodeTokenIssueResponse struct {
	Token string        `json:"token"` // returned once, never persisted in clear text
	Node  nodeTokenView `json:"node"`
}

func nodeTokenViewFrom(t model.NodeToken) nodeTokenView {
	return nodeTokenView{
		NodeID:    t.NodeID,
		Note:      t.Note,
		Revoked:   t.Revoked,
		CreatedAt: t.CreatedAt,
	}
}

// handleNodeTokensList serves GET /api/v1/nodes/tokens.
func (s *Server) handleNodeTokensList(w http.ResponseWriter, r *http.Request) {
	if s.opts.NodeTokens == nil {
		s.writeUnavailable(w, "节点令牌管理")
		return
	}
	tokens := s.opts.NodeTokens.List()
	items := make([]nodeTokenView, 0, len(tokens))
	for _, token := range tokens {
		// The wildcard token is a config-only shared secret; the panel cannot
		// revoke it and must not pretend it is a per-node credential.
		if token.NodeID == "*" {
			continue
		}
		items = append(items, nodeTokenViewFrom(token))
	}
	s.writeJSON(w, http.StatusOK, nodeTokenListResponse{Items: items})
}

// handleNodeTokenIssue serves POST /api/v1/nodes/tokens. The generated token is
// shown in the response once and is never logged.
func (s *Server) handleNodeTokenIssue(w http.ResponseWriter, r *http.Request) {
	if s.opts.NodeTokens == nil {
		s.writeUnavailable(w, "节点令牌管理")
		return
	}
	var req nodeTokenIssueRequest
	if !s.readJSON(w, r, &req, true, true) {
		return
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if !nodeTokenNodeIDRe.MatchString(nodeID) || nodeID == "*" {
		s.writeValidationError(w, "节点 ID 格式不正确", fieldError{
			Field: "node_id", Message: "需为 1-64 位 [A-Za-z0-9_.:-]，且不能使用 *",
		})
		return
	}
	note := strings.TrimSpace(req.Note)
	if len(note) > 256 {
		s.writeValidationError(w, "备注过长", fieldError{
			Field: "note", Message: "备注最多 256 字节",
		})
		return
	}
	token, err := s.opts.NodeTokens.Issue(nodeID, note)
	if err != nil {
		if errors.Is(err, nodesauth.ErrInvalidNodeID) {
			s.writeValidationError(w, "节点 ID 格式不正确", fieldError{
				Field: "node_id", Message: "节点 ID 不合法",
			})
			return
		}
		s.writeInternalError(w, err, "签发节点令牌失败")
		return
	}
	s.auditRequest(r, "token.create", nodeID, "ok", map[string]string{"note": note})
	s.log.Info("节点令牌已签发", "node_id", nodeID, "note", note)
	s.writeJSON(w, http.StatusCreated, nodeTokenIssueResponse{
		Token: token,
		Node: nodeTokenView{
			NodeID:    nodeID,
			Note:      note,
			CreatedAt: s.now().UTC(),
		},
	})
}

// handleNodeTokenRevoke serves DELETE /api/v1/nodes/tokens/{id}. It invalidates
// every token of the node and kicks its live sessions.
func (s *Server) handleNodeTokenRevoke(w http.ResponseWriter, r *http.Request) {
	if s.opts.NodeTokens == nil {
		s.writeUnavailable(w, "节点令牌管理")
		return
	}
	nodeID := strings.TrimSpace(r.PathValue("id"))
	if nodeID == "" {
		s.writeError(w, http.StatusNotFound, "not_found", "节点不存在", nil)
		return
	}
	if nodeID == "*" {
		s.writeValidationError(w, "共享令牌只能通过服务端配置管理", fieldError{
			Field: "node_id", Message: "不能在面板吊销 * 共享令牌",
		})
		return
	}
	if err := s.opts.NodeTokens.Revoke(nodeID); err != nil {
		if errors.Is(err, nodesauth.ErrInvalidNodeID) {
			s.writeValidationError(w, "节点 ID 格式不正确", fieldError{
				Field: "node_id", Message: "节点 ID 不合法",
			})
			return
		}
		s.writeInternalError(w, err, "吊销节点令牌失败")
		return
	}
	if s.opts.Tunnel != nil {
		if err := s.opts.Tunnel.KickNode(nodeID, "token_revoked", "节点令牌已被管理员吊销"); err != nil {
			s.log.Debug("令牌吊销后强制下线节点失败", "node_id", nodeID, "error", err)
		}
	}
	s.auditRequest(r, "token.revoke", nodeID, "ok", nil)
	s.log.Info("节点令牌已吊销", "node_id", nodeID)
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
