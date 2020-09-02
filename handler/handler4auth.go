package handler

import (
	"context"
	"dm_auth_srv/constant"
	"dm_auth_srv/lib/conn"
	"dm_auth_srv/lib/ecode"
	"dm_auth_srv/lib/jwt"
	"dm_auth_srv/lib/validation"
	authSrvPb "dm_auth_srv/proto/auth"
	"fmt"

	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/text/gstr"
	"github.com/gogf/gf/util/gconv"
	"github.com/gogf/gf/util/guid"
)

type AuthService struct{}

// 生成token
func (s *AuthService) MakeToken(ctx context.Context, req *authSrvPb.MakeTokenReq, resp *authSrvPb.MakeTokenResp) error {
	g.Log().Debugf("======== AuthService.MakeToken ======== [param:%v]", req)

	// 参数校验
	if req.Token == nil {
		g.Log().Line().Errorf("token 不能为空 [token:%v]", req.Token)
		return ecode.ParamErr
	}

	// 参数校验 uin
	if err := validation.CheckUin(req.Token.Uin); err != nil {
		return err
	}

	// 生成skey
	req.Token.Skey = guid.S()

	// 生成jwt串
	strToken, err := jwt.CreateToken(*req.Token)
	if err != nil {
		g.Log().Line().Errorf("生成token失败 [err:%v]", err.Error())
		return ecode.AuthTokenMakeErr
	} else {
		g.Log().Debugf("生成token成功 [strToken:%v]", strToken)
		conn.GetRedis().Do("SET", s.getRedisKey(*req.Token), req.Token.Skey, "EX", constant.SkeyTimeOut)
	}

	resp.Token = strToken
	return nil
}

// 校验token
func (s *AuthService) CheckToken(ctx context.Context, req *authSrvPb.CheckTokenReq, resp *authSrvPb.CheckTokenResp) error {
	g.Log().Debugf("======== AuthService.CheckToken ======== [param:%v]", req)

	// 参数校验 strToken
	if err := validation.CheckToken(req.Token); err != nil {
		return err
	}

	// strtoken 解析token结构体
	rep, err := jwt.ParseToken(req.Token)
	if err != nil {
		g.Log().Line().Errorf("jwt字符串解析失败 [strtoken:%v] [err:%v]", req.Token, err.Error())
		return ecode.AuthTokenParseErr
	} else {
		resp.Token = &rep.JwtSession
		g.Log().Debugf("jwt字符串解析成功 [token:%v]", resp.Token)
	}

	// 开始校验skey
	r, err := conn.GetRedis().Do("GET", s.getRedisKey(*resp.Token))
	skeyFromRedis := gconv.String(r)
	if gstr.ToLower(skeyFromRedis) == resp.Token.Skey && resp.Token.Skey != "" {
		g.Log().Debugf("skey校验成功 [skeyFromRedis:%v] [token.skey:%v]", skeyFromRedis, resp.Token.Skey)
	} else {
		g.Log().Line().Errorf("skey校验失败 [skeyFromRedis:%v] [token.skey:%v]", skeyFromRedis, resp.Token.Skey)
		return ecode.AuthTokenParseErr
	}

	// 续期
	conn.GetRedis().Do("SET", s.getRedisKey(*resp.Token), resp.Token.Skey, "EX", constant.SkeyTimeOut)
	return nil
}

// 清理token
func (s *AuthService) DelToken(ctx context.Context, req *authSrvPb.DelTokenReq, resp *authSrvPb.BaseRsp) error {
	g.Log().Debugf("======== AuthService.MakeToken ======== [param:%v]", req)

	// 参数校验 strToken
	if err := validation.CheckToken(req.Token); err != nil {
		return err
	}

	// strtoken 解析token结构体
	rep, err := jwt.ParseToken(req.Token)
	if err != nil {
		g.Log().Line().Errorf("jwt字符串解析失败 [strtoken:%v] [err:%v]", req.Token, err.Error())
		return ecode.AuthTokenParseErr
	} else {
		g.Log().Debugf("jwt字符串解析成功 [token:%v]", &rep.JwtSession)
	}

	// 清理skey
	conn.GetRedis().Do("DEL", s.getRedisKey(rep.JwtSession))
	return nil
}

// 生成redisKey
func (s *AuthService) getRedisKey(token authSrvPb.Token) string {
	return gstr.ToLower(fmt.Sprintf("auth:session:%d:%s:%s", token.Uin, token.Source, token.Role))
}
