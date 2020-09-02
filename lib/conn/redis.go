package conn

import (
	"github.com/gogf/gf/database/gredis"
	"github.com/gogf/gf/frame/g"
)

func GetRedis() *gredis.Redis {
	return g.Redis()
}
