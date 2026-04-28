package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var jwtSecretKey = []byte("my_super_super_secret_key_12345")

const inviteCodeLength = 8

var db *gorm.DB

type Settings struct {
	Http HttpSettings `json:"http"`
	Ws   WsSettings   `json:"websocket"`
}

type HttpSettings struct {
	Port uint16 `json:"port"`
}

type WsSettings struct {
}

type User struct {
	// gorm.Model を入れると、ID, CreatedAt(作成日時), UpdatedAt(更新日時)などが自動で付与されます
	gorm.Model
	Username     string `gorm:"unique;not null"` // ユーザー名（重複不可、必須）
	PasswordHash string `gorm:"not null"`        // ハッシュ化されたパスワード

	DisplayName   string `gorm:"not null"`
	IconURL       string `gorm:"default:'default_icon.png'"`
	ThemeColor    string `gorm:"default:'#7289da'"`
	StatusMessage string

	Servers []Server `gorm:"many2many:user_servers;"`
	Invites []Invite `gorm:"foreignKey:CreatorID"`
}

type Server struct {
	gorm.Model
	Name    string `gorm:"not null"`
	IconURL string `gorm:"default:'default_icon.png'"`

	Users    []User `gorm:"many2many:user_servers;"`
	Channels []Channel
	Invites  []Invite
}

type Channel struct {
	gorm.Model
	ServerID uint   `gorm:"not null"`
	Name     string `gorm:"not null"`
}

type Invite struct {
	Code string `gorm:"primaryKey;type:varchar(20)"`

	Uses      uint `gorm:"default=0"`
	MaxUses   uint `gorm:"default=0"`
	ServerID  uint `gorm:"not null"`
	CreatorID uint `gorm:"not null"`

	CreatedAt time.Time
	ExpiresAt *time.Time
}

func main() {
	settings := Settings{
		Http: HttpSettings{
			Port: 25565,
		},
		Ws: WsSettings{},
	}
	f, err := os.Open("config.json")
	if err != nil {
		log.Println("config.jsonが開けませんでした。自動で作成します")
		f, err = os.Create("config.json")
		if err != nil {
			log.Fatal("config.jsonの新規作成が失敗しました")
		}
		e := json.NewEncoder(f)
		if err := e.Encode(settings); err != nil {
			log.Fatal("config.jsonにデフォルト値を書き込めませんでした")
		}
	}
	sDecoder := json.NewDecoder(f)
	if err := sDecoder.Decode(&settings); err != nil {
		log.Fatal("config.jsonを読み込めませんでした")
	}
	log.Println("config.jsonを読み込みました")

	db, err = gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("DBの接続に失敗しました")
	}
	db.AutoMigrate(&User{})
	log.Println("DBに接続しました")

	http.HandleFunc("/api/hello", helloHandler)
	http.HandleFunc("/api/register", registerHandler)
	http.HandleFunc("/api/login", loginHandler)
	http.HandleFunc("/api/modify_user", authMiddle(modifyUserHandler))
	http.HandleFunc("/api/change_password", authMiddle(changePasswordHandler))
	http.HandleFunc("/api/delete_user", authMiddle(deleteUserHandler))
	http.HandleFunc("/api/create_server", authMiddle(createServerHandler))
	http.HandleFunc("/api/modify_server", authMiddle(modifyServerHandler))
	http.HandleFunc("/api/delete_server", authMiddle(deleteServerHandler))
	http.HandleFunc("/api/join_server", authMiddle(joinServerHandler))
	http.HandleFunc("/api/leave_server", authMiddle(leaveServerHandler))
	http.HandleFunc("/api/list_server_current", authMiddle(listServerCurrentlyOnHandler))
	http.HandleFunc("/api/create_channel", authMiddle(createChannelHandler))
	http.HandleFunc("/api/modify_channel", authMiddle(modifyChannelHandler))
	http.HandleFunc("/api/delete_channel", authMiddle(deleteChannelHandler))
	http.HandleFunc("/api/create_invite", authMiddle(createInviteHandler))
	http.HandleFunc("/api/delete_invite", authMiddle(deleteInviteHandler))
	http.HandleFunc("/api/list_invite", authMiddle(listMyInviteHandler))

	log.Printf("Server has started on http://127.0.0.1:%d\n", settings.Http.Port)
	http.ListenAndServe(fmt.Sprintf(":%d", settings.Http.Port), nil)

}
