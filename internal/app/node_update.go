package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"proxygw/internal/protocol"
)

const (
	nodeUpdatePollInterval = 2 * time.Second
	nodeUpdateNodeTimeout  = 10 * time.Minute
)

// nodeUpdateManager drives rolling binary node updates. The queue lives in the
// server process, so closing the browser does not abort an update.
type nodeUpdateManager struct {
	srv *Server

	mu      sync.Mutex
	running bool
	current string
	queue   []string
}

func newNodeUpdateManager(srv *Server) *nodeUpdateManager {
	return &nodeUpdateManager{srv: srv}
}

// StartNodeUpdate queues exactly one node.
func (m *nodeUpdateManager) StartNodeUpdate(nodeID string) error {
	if m == nil {
		return errors.New("节点更新管理器未初始化")
	}
	_, err := m.start([]string{nodeID})
	return err
}

// StartRollingUpdate queues a rolling update and returns how many nodes were
// accepted. A second concurrent update request is rejected.
func (m *nodeUpdateManager) StartRollingUpdate(nodeIDs []string) (int, error) {
	if m == nil {
		return 0, errors.New("节点更新管理器未初始化")
	}
	return m.start(nodeIDs)
}

func (m *nodeUpdateManager) start(nodeIDs []string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		if m.current != "" {
			return 0, fmt.Errorf("已有节点更新任务进行中（%s）", m.current)
		}
		return 0, errors.New("已有节点更新任务进行中")
	}
	seen := make(map[string]struct{}, len(nodeIDs))
	queue := make([]string, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		queue = append(queue, id)
	}
	if len(queue) == 0 {
		return 0, errors.New("没有可更新的节点")
	}
	m.running = true
	m.queue = queue
	go m.run(queue)
	return len(queue), nil
}

func (m *nodeUpdateManager) run(queue []string) {
	defer func() {
		m.mu.Lock()
		m.running = false
		m.current = ""
		m.queue = nil
		m.mu.Unlock()
	}()
	for _, nodeID := range queue {
		m.mu.Lock()
		m.current = nodeID
		m.mu.Unlock()
		if err := m.updateOne(nodeID); err != nil {
			m.srv.logger.Error("滚动节点更新中止", "node_id", nodeID, "error", err)
			return
		}
	}
}

func (m *nodeUpdateManager) updateOne(nodeID string) error {
	node, ok := m.srv.registry.Get(nodeID)
	if !ok {
		return fmt.Errorf("节点 %s 不存在", nodeID)
	}
	if !node.Online {
		return fmt.Errorf("节点 %s 已离线", nodeID)
	}
	if node.Runtime == "docker" || !node.UpdateCapable {
		return fmt.Errorf("节点 %s 不支持二进制在线更新", nodeID)
	}
	cmd := protocol.UpdateCommand{
		CommandID:  newUpdateCommandID(),
		Repository: "WAADRI/proxygw",
	}
	if err := m.srv.tunnel.UpdateNode(nodeID, cmd); err != nil {
		return fmt.Errorf("下发更新指令失败: %w", err)
	}
	// Clear a stale success from a previous update before polling this command.
	m.srv.registry.UpdateNodeUpdate(nodeID, protocol.UpdateStatus{
		State:          protocol.UpdateChecking,
		CurrentVersion: node.Version,
		Message:        "更新指令已下发",
		UpdatedAt:      time.Now().UnixMilli(),
	})
	m.srv.logger.Info("节点更新指令已下发", "event", "node.update_dispatched", "node_id", nodeID)
	deadline := time.Now().Add(nodeUpdateNodeTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(nodeUpdatePollInterval)
		current, ok := m.srv.registry.Get(nodeID)
		if !ok || current.Update == nil {
			continue
		}
		switch current.Update.State {
		case protocol.UpdateSuccess:
			m.srv.logger.Info("节点更新成功", "event", "node.update_success",
				"node_id", nodeID, "version", current.Update.CurrentVersion)
			return nil
		case protocol.UpdateFailed, protocol.UpdateRolledBack:
			msg := current.Update.Error
			if msg == "" {
				msg = current.Update.Message
			}
			return fmt.Errorf("节点 %s 更新失败: %s", nodeID, msg)
		}
	}
	return fmt.Errorf("节点 %s 更新超时（%s）", nodeID, nodeUpdateNodeTimeout)
}

func newUpdateCommandID() string {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("cmd-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf[:])
}

// ---- panel.NodeUpdatesAPI ----

type nodeUpdateAPIAdapter struct{ srv *Server }

func (a *nodeUpdateAPIAdapter) StartNodeUpdate(nodeID string) error {
	return a.srv.nodeUpdates.StartNodeUpdate(nodeID)
}

func (a *nodeUpdateAPIAdapter) StartRollingUpdate(nodeIDs []string) (int, error) {
	return a.srv.nodeUpdates.StartRollingUpdate(nodeIDs)
}
