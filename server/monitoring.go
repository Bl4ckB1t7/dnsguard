package main

import (
	"net/http"
	"time"
)

func monitoringStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !monitoringTokenValid(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "monitoring authentication required"})
		return
	}

	nodes := liveDNSNodes()
	dnsMu.RLock()
	pendingPublish := !rpzRulesEqual(state.Rules, state.Published)
	ruleCount := len(state.Rules)
	dnsMu.RUnlock()
	runtime := rpzStatusSnapshot()
	healthyNodes := 0
	for _, node := range nodes {
		if node.Status == "healthy" {
			healthyNodes++
		}
	}
	status := "ok"
	if len(nodes) == 0 || healthyNodes != len(nodes) || pendingPublish || runtime.JobStatus == "failed" {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           status,
		"nodes":            len(nodes),
		"healthyNodes":     healthyNodes,
		"rules":            ruleCount,
		"pendingPublish":   pendingPublish,
		"publishJobStatus": runtime.JobStatus,
		"time":             time.Now().UTC().Format(time.RFC3339),
	})
}
