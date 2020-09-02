// Code generated by protoc-gen-micro. DO NOT EDIT.
// source: proto/auth/auth.proto

package authSrvPb

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

import (
	context "context"
	client "github.com/micro/go-micro/v2/client"
	server "github.com/micro/go-micro/v2/server"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ client.Option
var _ server.Option

// Client API for AuthService service

type AuthService interface {
	// 生成token
	MakeToken(ctx context.Context, in *MakeTokenReq, opts ...client.CallOption) (*MakeTokenResp, error)
	// 校验token
	CheckToken(ctx context.Context, in *CheckTokenReq, opts ...client.CallOption) (*CheckTokenResp, error)
	// 删除token
	DelToken(ctx context.Context, in *DelTokenReq, opts ...client.CallOption) (*BaseRsp, error)
}

type authService struct {
	c    client.Client
	name string
}

func NewAuthService(name string, c client.Client) AuthService {
	return &authService{
		c:    c,
		name: name,
	}
}

func (c *authService) MakeToken(ctx context.Context, in *MakeTokenReq, opts ...client.CallOption) (*MakeTokenResp, error) {
	req := c.c.NewRequest(c.name, "AuthService.MakeToken", in)
	out := new(MakeTokenResp)
	err := c.c.Call(ctx, req, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authService) CheckToken(ctx context.Context, in *CheckTokenReq, opts ...client.CallOption) (*CheckTokenResp, error) {
	req := c.c.NewRequest(c.name, "AuthService.CheckToken", in)
	out := new(CheckTokenResp)
	err := c.c.Call(ctx, req, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authService) DelToken(ctx context.Context, in *DelTokenReq, opts ...client.CallOption) (*BaseRsp, error) {
	req := c.c.NewRequest(c.name, "AuthService.DelToken", in)
	out := new(BaseRsp)
	err := c.c.Call(ctx, req, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for AuthService service

type AuthServiceHandler interface {
	// 生成token
	MakeToken(context.Context, *MakeTokenReq, *MakeTokenResp) error
	// 校验token
	CheckToken(context.Context, *CheckTokenReq, *CheckTokenResp) error
	// 删除token
	DelToken(context.Context, *DelTokenReq, *BaseRsp) error
}

func RegisterAuthServiceHandler(s server.Server, hdlr AuthServiceHandler, opts ...server.HandlerOption) error {
	type authService interface {
		MakeToken(ctx context.Context, in *MakeTokenReq, out *MakeTokenResp) error
		CheckToken(ctx context.Context, in *CheckTokenReq, out *CheckTokenResp) error
		DelToken(ctx context.Context, in *DelTokenReq, out *BaseRsp) error
	}
	type AuthService struct {
		authService
	}
	h := &authServiceHandler{hdlr}
	return s.Handle(s.NewHandler(&AuthService{h}, opts...))
}

type authServiceHandler struct {
	AuthServiceHandler
}

func (h *authServiceHandler) MakeToken(ctx context.Context, in *MakeTokenReq, out *MakeTokenResp) error {
	return h.AuthServiceHandler.MakeToken(ctx, in, out)
}

func (h *authServiceHandler) CheckToken(ctx context.Context, in *CheckTokenReq, out *CheckTokenResp) error {
	return h.AuthServiceHandler.CheckToken(ctx, in, out)
}

func (h *authServiceHandler) DelToken(ctx context.Context, in *DelTokenReq, out *BaseRsp) error {
	return h.AuthServiceHandler.DelToken(ctx, in, out)
}
