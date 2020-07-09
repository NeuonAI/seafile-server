package main

import (
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/haiwen/seafile-server/fileserver/repomgr"
	"github.com/haiwen/seafile-server/fileserver/share"
)

const (
	seafileServerChannelEvent = "seaf_server.event"
	seafileServerChannelStats = "seaf_server.stats"
	tokenExpireTime           = 7200
	permExpireTime            = 7200
)

var (
	tokenCache sync.Map
	permCache  sync.Map
)

type tokenInfo struct {
	repoID     string
	email      string
	expireTime int64
}

type permInfo struct {
	perm       string
	expireTime int64
}

type repoEventData struct {
	eType      string
	user       string
	ip         string
	repoID     string
	path       string
	clientName string
}

func permissionCheckCB(rsp http.ResponseWriter, r *http.Request) *appError {
	queries := r.URL.Query()

	op := queries.Get("op")
	if op != "download" && op != "upload" {
		return &appError{nil, "", http.StatusBadRequest}
	}

	clientID := queries.Get("client_id")
	if clientID != "" && len(clientID) != 40 {
		return &appError{nil, "", http.StatusBadRequest}
	}

	clientVer := queries.Get("client_ver")
	if clientVer != "" {
		status := validateClientVer(clientVer)
		if status != http.StatusOK {
			return &appError{nil, "", status}
		}
	}

	clientName := queries.Get("client_name")
	if clientName != "" {
		clientName = html.UnescapeString(clientName)
	}

	vars := mux.Vars(r)
	repoID := vars["repoid"]
	repo := repomgr.Get(repoID)
	if repo == nil {
		msg := "repo was deleted"
		return &appError{nil, msg, http.StatusBadRequest}
	}

	token := r.Header.Get("Seafile-Repo-Token")
	user, err := getUserByToken(token, repoID, true)
	if err != nil {
		log.Printf("Failed to get email by token %s: %v", token, err)
		return &appError{nil, "", http.StatusInternalServerError}
	}
	permStatus := checkPermission(repoID, token, user, op, true)
	if permStatus != http.StatusOK {
		return &appError{nil, "", permStatus}
	}
	ip := getClientIPAddr(r)
	if ip == "" {
		log.Printf("%s Failed to get client ip", token)
		return &appError{nil, "", http.StatusInternalServerError}
	}

	if op == "download" {
		onRepoOper("repo-download-sync", repoID, user, ip, clientName)
	}
	if clientID != "" && clientName != "" {
		exists, err := repomgr.TokenPeerInfoExists(token)
		if err != nil {
			log.Printf("Failed to check is the token %s exists: %v", token, err)
			return &appError{nil, "", http.StatusInternalServerError}
		}
		if !exists {
			if err := repomgr.AddTokenPeerInfo(token, clientID, ip, clientName, clientVer, int64(time.Now().Second())); err != nil {
				log.Printf("Failed to add token peer info: %v", err)
				return &appError{nil, "", http.StatusInternalServerError}
			}
		} else {
			if err := repomgr.UpdateTokenPeerInfo(token, clientID, clientVer, int64(time.Now().Second())); err != nil {
				log.Printf("Failed to update token peer info: %v", err)
				return &appError{nil, "", http.StatusInternalServerError}
			}
		}
	}
	return &appError{nil, "ok", http.StatusOK}
}

func checkPermission(repoID, token, user, op string, skipCache bool) int {
	var info *permInfo
	if !skipCache {
		if value, ok := permCache.Load(fmt.Sprintf("%s:%s", repoID, user)); ok {
			info = value.(*permInfo)
		}
	}
	if info != nil {
		if info.perm == "r" && op == "upload" {
			return http.StatusForbidden
		}
		return http.StatusOK
	}

	status, err := repomgr.GetRepoStatus(repoID)
	if err != nil {
		log.Printf("Failed to get repo status by repo id %s: %v", repoID, err)
		return http.StatusInternalServerError
	}
	if status != repomgr.RepoStatusNormal && status != -1 {
		return http.StatusForbidden
	}

	perm := share.CheckPerm(repoID, user)
	if perm != "" {
		info = new(permInfo)
		info.perm = perm
		info.expireTime = int64(time.Now().Second()) + permExpireTime
		permCache.Store(fmt.Sprintf("%s:%s", repoID, user), info)
		if perm == "r" && op == "upload" {
			return http.StatusForbidden
		}
		return http.StatusOK
	}
	return http.StatusForbidden
}

func getUserByToken(token string, repoID string, skipCache bool) (string, error) {
	var user string
	if token == "" {
		return user, nil
	}

	if value, ok := tokenCache.Load(token); ok {
		info := value.(*tokenInfo)
		user = info.email
		return user, nil
	}

	user, err := repomgr.GetEmailByToken(repoID, token)
	if err != nil {
		log.Printf("Failed to get email by token %s: %v", token, err)
		return "", err
	}
	if user == "" {
		return "", nil
	}
	info := new(tokenInfo)
	info.email = user
	info.expireTime = int64(time.Now().Second()) + tokenExpireTime
	info.repoID = repoID
	tokenCache.Store(token, info)
	return user, nil
}

func validateClientVer(clientVer string) int {
	versions := strings.Split(clientVer, ".")
	if len(versions) != 3 {
		return http.StatusBadRequest
	}
	if _, err := strconv.Atoi(versions[0]); err != nil {
		return http.StatusBadRequest
	}
	if _, err := strconv.Atoi(versions[1]); err != nil {
		return http.StatusBadRequest
	}
	if _, err := strconv.Atoi(versions[2]); err != nil {
		return http.StatusBadRequest
	}

	return http.StatusOK
}

func getClientIPAddr(r *http.Request) string {
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	addr := strings.TrimSpace(strings.Split(xForwardedFor, ",")[0])
	ip := net.ParseIP(addr)
	if ip != nil {
		return ip.String()
	}

	addr = strings.TrimSpace(r.Header.Get("X-Real-Ip"))
	ip = net.ParseIP(addr)
	if ip != nil {
		return ip.String()
	}

	if addr, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		ip = net.ParseIP(addr)
		if ip != nil {
			return ip.String()
		}
	}

	return ""
}

func onRepoOper(eType, repoID, user, ip, clientName string) {
	rData := new(repoEventData)
	vInfo, err := repomgr.GetVirtualRepoInfo(repoID)

	if err != nil {
		log.Printf("Failed to get virtual repo info by repo id %s: %v", repoID, err)
		return
	}
	if vInfo != nil {
		rData.repoID = vInfo.OriginRepoID
		rData.path = vInfo.Path
	} else {
		rData.repoID = repoID
	}
	rData.eType = eType
	rData.user = user
	rData.ip = ip
	rData.clientName = clientName

	publishRepoEvent(rData)
}

func publishRepoEvent(rData *repoEventData) {
	if rData.path == "" {
		rData.path = "/"
	}
	buf := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s",
		rData.eType, rData.user, rData.ip,
		rData.clientName, rData.repoID, rData.path)
	rpcclient.Call("publish_event", seafileServerChannelEvent, buf)
}
