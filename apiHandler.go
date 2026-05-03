package main

import (
	"encoding/json"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// NON AUTH

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
	w.Header().Set("Content-Type", "application/json")

	data := struct {
		Message string
		Status  string
	}{
		Message: "Goサーバーからのメッセージです！接続成功！",
		Status:  "success",
	}

	json.NewEncoder(w).Encode(data)
}

type RegisterRequest struct {
	Username string
	Password string
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "不正なデータ形式です"})
		return
	}
	if req.Username == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "ユーザー名とパスワードは必須です"})
		return
	}
	var existingUser User
	if err := db.Where("username = ?", req.Username).First(&existingUser).Error; err == nil {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "そのユーザー名は既に存在しています"})
		return
	}

	if len(req.Password) < 6 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "パスワードは6文字以上にしてください"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "パスワードの暗号化に失敗しました"})
		return
	}

	newUser := User{
		Username:     req.Username,
		PasswordHash: string(hashedPassword),
		DisplayName:  req.Username,
	}

	if err := db.Create(&newUser).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "ユーザー情報をDBに登録できませんでした"})
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "ユーザー登録が完了しました", "status": "success"})
}

type LoginRequest struct {
	Username string
	Password string
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "不正なデータ形式です"})
		return
	}

	var user User
	if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "ユーザー名またはパスワードが違います"})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "ユーザー名またはパスワードが違います"})
		return
	}

	claims := jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), //24hourの有効期限
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "認証トークンの作成に失敗しました"})
		return
	}

	log.Printf("User(ID:%d, Username:\"%s\") has logged in\n", user.ID, user.Username)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "ログイン成功",
		"token":   tokenString, // これがReact側で保存する通行証
	})
}

// WITH AUTH

type ModifyUserRequest struct {
	Username      string
	DisplayName   string
	IconURL       string
	ThemeColor    string
	StatusMessage string
}

func modifyUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req ModifyUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "不正なデータ形式です"})
		return
	}

	var user User
	if err := db.Where("id = ?", r.Context().Value("user_id")).First(&user).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "存在しないユーザーからのリクエストです"})
		return
	}

	if req.Username == "" || req.ThemeColor == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "ユーザー名とパスワード、カラーは空欄にできません"})
		return
	}

	if req.Username != user.Username {
		var existingUser User
		if err := db.Where("username = ?", req.Username).First(&existingUser).Error; err == nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "そのユーザー名は既に使われています"})
			return
		}
	}

	user.Username = req.Username

	if req.DisplayName == "" {
		user.DisplayName = user.Username
	} else {
		user.DisplayName = req.DisplayName
	}
	if req.IconURL == "" {
		user.IconURL = "default_icon.png"
	} else {
		user.IconURL = req.IconURL
	}
	user.ThemeColor = req.ThemeColor
	user.StatusMessage = req.StatusMessage

	if err := db.Save(&user).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "DBの更新に失敗しました"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "ユーザー情報変更成功",
		"status":  "success",
	})
}

type ChangePasswordRequest struct {
	Password    string
	NewPassword string
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "不正なデータ形式です"})
		return
	}

	var user User
	if err := db.Where("id = ?", r.Context().Value("user_id")).First(&user).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "存在しないユーザーからのリクエストです"})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "既存のパスワードが違います"})
		return
	}

	if len(req.NewPassword) < 6 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "パスワードは6文字以上必要です"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "パスワードの暗号化に失敗しました"})
		return
	}
	user.PasswordHash = string(hashedPassword)

	if err := db.Save(&user).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "DBの更新に失敗しました"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "パスワード変更成功",
		"status":  "success",
	})
}

type DeleteUserRequest struct {
	Password string
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "不正なデータ形式です"})
		return
	}

	var user User
	if err := db.Where("id = ?", r.Context().Value("user_id")).First(&user).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "存在しないユーザーからのリクエストです"})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "パスワードが違います"})
		return
	}

	if err := db.Delete(&user).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "DBの更新に失敗しました"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "ユーザー削除成功",
		"status":  "success",
	})
}

type CreateServerRequest struct {
	ServerName string
	IconURL    string
}

func createServerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req CreateServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "不正なデータ形式です"})
		return
	}
	var user User
	if err := db.Where("id = ?", r.Context().Value("user_id")).First(&user).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "存在しないユーザーからのリクエストです"})
		return
	}
	if req.ServerName == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "サーバー名は必須です"})
		return
	}

	newServer := Server{
		Name: req.ServerName,
		IconURL: func() string {
			if req.IconURL == "" {
				return "default_icon.png"
			}
			return req.IconURL
		}(),

		Users:    []User{user},
		Channels: []Channel{},
	}
	newServer.Channels = append(newServer.Channels, Channel{
		ServerID: newServer.ID,
		Name:     "一般",
	})
	if err := db.Create(&newServer).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "チャンネル情報をDBに登録できませんでした"})
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "チャンネル作成が完了しました", "status": "success"})
}

type ModifyServerRequest struct {
	ServerID uint
	Name     string
	IconURL  string
}

func modifyServerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req ModifyServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "不正なデータ形式です"})
		return
	}

	var user User
	if err := db.Where("id = ?", r.Context().Value("user_id")).First(&user).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "存在しないユーザーからのリクエストです"})
		return
	}

	var server Server
	if err := db.Preload("Users").Where("id = ?", req.ServerID).First(&server).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "サーバーが存在しません"})
		return
	}

	if !slices.ContainsFunc(server.Users, func(u User) bool {
		return u.ID == user.ID
	}) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "サーバーに参加していないユーザーは操作できません"})
		return
	}
	if server.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "サーバー名は必須です"})
		return
	}
	server.Name = req.Name

	if req.IconURL == "" {
		server.IconURL = "default-icon.png"
	} else {
		server.IconURL = req.IconURL
	}

	if err := db.Save(&server).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "DBの更新に失敗しました"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "サーバー情報変更成功",
		"status":  "success",
	})
}

type DeleteServerRequest struct {
	ServerID uint
	Name     string
}

func deleteServerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req DeleteServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "不正なデータ形式です"})
		return
	}

	var user User
	if err := db.Where("id = ?", r.Context().Value("user_id")).First(&user).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "存在しないユーザーからのリクエストです"})
		return
	}

	var server Server
	if err := db.Preload("Users").Where("id = ?", req.ServerID).First(&server).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "サーバーが存在しません"})
		return
	}

	if !slices.ContainsFunc(server.Users, func(u User) bool {
		return u.ID == user.ID
	}) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "サーバーに参加していないユーザーは操作できません"})
		return
	}

	if server.Name != req.Name {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "サーバー名が間違っています"})
		return
	}

	if err := db.Delete(&server).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "DBの更新に失敗しました"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "サーバー削除成功",
		"status":  "success",
	})
}

type JoinServerRequest struct {
	InviteCode string
}

func joinServerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req JoinServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "不正なデータ形式です"})
		return
	}
	var user User
	if err := db.Where("id = ?", r.Context().Value("user_id")).First(&user).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "存在しないユーザーからのリクエストです"})
		return
	}
	var invite Invite
	if err := db.Where("code = ?", req.InviteCode).First(&invite).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "招待コードが存在しません"})
		return
	}
}

type LeaveServerRequest struct{}

func leaveServerHandler(w http.ResponseWriter, r *http.Request) {}

type ListServerCurrentlyOnRequest struct{}

func listServerCurrentlyOnHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user User
	if err := db.Preload("Servers").Where("id = ?", r.Context().Value("user_id")).First(&user).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "存在しないユーザーからのリクエストです"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string][]Server{"servers": user.Servers})
}

type CreateChannelRequest struct{}

func createChannelHandler(w http.ResponseWriter, r *http.Request) {}

type ModifyChannelRequest struct{}

func modifyChannelHandler(w http.ResponseWriter, r *http.Request) {}

type DeleteChannelRequest struct{}

func deleteChannelHandler(w http.ResponseWriter, r *http.Request) {}

type CreateInviteRequest struct {
	Duration string
	MaxUses  uint
	ServerID uint
}

func createInviteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req CreateInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "不正なデータ形式です"})
		return
	}

	var user User
	if err := db.Where("id = ?", r.Context().Value("user_id")).First(&user).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "存在しないユーザーからのリクエストです"})
		return
	}

	var server Server
	if err := db.Preload("Users").Where("id = ?", req.ServerID).First(&server).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "サーバーが存在しません"})
		return
	}
	if !slices.ContainsFunc(server.Users, func(u User) bool {
		return u.ID == user.ID
	}) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "サーバーに参加していないユーザーは操作できません"})
		return
	}

	now := time.Now()
	var expires time.Time
	if req.Duration != "" {
		duration, err := time.ParseDuration(req.Duration)
		if err != nil {
			duration = 24 * time.Hour
		}
		expires = now.Add(duration)
	} else {
		expires = now.Add(time.Hour)
	}

	code, err := generateInviteCode(inviteCodeLength)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "招待コード生成に失敗しました"})
		return
	}
	newInvite := Invite{
		Code:      code,
		MaxUses:   req.MaxUses,
		ServerID:  req.ServerID,
		CreatorID: user.ID,
		CreatedAt: now,
		ExpiresAt: &expires,
	}
	if err := db.Create(&newInvite).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "DBの更新に失敗しました"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message":    "招待コード生成成功",
		"invitecode": code,
	})
}

type DeleteInviteRequest struct {
	InviteCode string
}

func deleteInviteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req DeleteInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "不正なデータ形式です"})
		return
	}

	var user User
	if err := db.Where("id = ?", r.Context().Value("user_id")).First(&user).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "存在しないユーザーからのリクエストです"})
		return
	}

	var invite Invite
	if err := db.Where("code = ?", req.InviteCode).First(&invite).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "招待コードが存在しません"})
		return
	}

	if invite.CreatorID != user.ID {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "作成者のみが招待コードを削除できます"})
		return
	}

	if err := db.Delete(&invite).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "DBの更新に失敗しました"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "招待コード削除成功",
		"status":  "success",
	})

}

func listMyInviteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var user User
	if err := db.Preload("Invites").Where("id = ?", r.Context().Value("user_id")).First(&user).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "存在しないユーザーからのリクエストです"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string][]Invite{"invites": user.Invites})
}
