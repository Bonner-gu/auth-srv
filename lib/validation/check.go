package validation

import (
	"dm_auth_srv/lib/ecode"

	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/util/gvalid"
)

// 校验token参数
func CheckToken(strToken string) error {
	if err := gvalid.Check(strToken, "required|length:64,512", "key必填|key格式不合法"); err != nil {
		g.Log().Errorf("strToken格式校验失败 [strtoken:%v]", strToken)
		return ecode.ParamErr
	} else {
		return nil
	}
}

// 校验UIN参数
func CheckUin(uin int32) error {
	if err := gvalid.Check(uin, "required|between:10000,99999999", "uin必填|uin格式不合法"); err != nil {
		g.Log().Errorf("uin格式校验失败 [uin:%v]", uin)
		return ecode.ParamErr
	} else {
		return nil
	}
}
