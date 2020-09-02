package constant

import (
	"time"

	"github.com/gogf/gf/frame/g"
)

// base
const (
	BaseId   = 10000 // 默认id
	BasePage = 1     // 默认页码
	BaseSize = 10    // 默认每页展示数量
)

// 基础配置
var (
	ServerName    = g.Config().GetString("app.ServerName")
	ServerAddress = g.Config().GetString("app.Address")
	ServerVersion = g.Config().GetString("app.Version")
)

//jwt
var (
	JwtSecret   = []byte("NoeC@q^cvE5S-rd@TO7-Z-cs-CcUo630^A")
	Myissuer    = "cs.com"
	ExpiresAt   = 30 * 24 * time.Hour
	SkeyTimeOut = 86400
)
