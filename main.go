package main

import (
	"dm_auth_srv/constant"
	"dm_auth_srv/handler"
	authSrvPb "dm_auth_srv/proto/auth"

	"github.com/gogf/gf/frame/g"
	"github.com/micro/go-micro/v2"
)

func main() {
	service := micro.NewService(
		micro.Name(constant.ServerName),
		micro.Address(constant.ServerAddress),
		micro.Version(constant.ServerVersion),
	)

	// Initialise service
	service.Init()

	// 注册服务
	authSrvPb.RegisterAuthServiceHandler(service.Server(), new(handler.AuthService))

	// Run service
	if err := service.Run(); err != nil {
		g.Log().Fatal(err)
	}
}
