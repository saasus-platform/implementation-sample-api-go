package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/saasus-platform/saasus-sdk-go/generated/authapi"
	"github.com/saasus-platform/saasus-sdk-go/middleware"
	"github.com/saasus-platform/saasus-sdk-go/modules/auth"
	"github.com/saasus-platform/saasus-sdk-go/modules/auth/credential"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

var authClient *authapi.ClientWithResponses

type idTokenGetter struct{}

func (*idTokenGetter) GetIDToken(r *http.Request) string {
	// Authorization: Bearer <id_token>
	strs := strings.Split(r.Header.Get("Authorization"), " ")
	if len(strs) == 2 && strings.ToLower(strs[0]) == "bearer" {
		return strs[1]
	}
	return ""
}

var _ middleware.IDTokenGetter = (*idTokenGetter)(nil)

func run() (err error) {
	authClient, err = auth.AuthWithResponse()
	if err != nil {
		return fmt.Errorf("failed to create auth client: %w", err)
	}
	authMiddleware := middleware.AuthMiddlewareEcho(&idTokenGetter{})

	e := echo.New()
	e.Use(echomiddleware.Logger())
	e.Use(
		echomiddleware.CORSWithConfig(echomiddleware.CORSConfig{
			AllowCredentials: true,
			AllowOrigins: []string{
				"http://localhost:3000",
			},
			AllowMethods: []string{
				http.MethodGet,
				http.MethodPut,
				http.MethodPatch,
				http.MethodPost,
				http.MethodDelete,
			},
			MaxAge: 86400,
		}),
	)
	// 認可コードからIDトークンを取得する
	e.GET("/credentials", func(c echo.Context) error {
		code := c.Request().URL.Query().Get("code")
		res, _ := credential.GetAuthCredentialsWithTempCodeAuth(c.Request().Context(), c.Response().Writer, c.Request(), code)
		return c.JSON(http.StatusOK, res)
	})
	// リフレッシュトークンからIDトークンを取得する
	e.GET("/refresh", func(c echo.Context) error {
		refreshToken := c.Request().URL.Query().Get("refreshtoken")
		println("refreshToken:")
		println(refreshToken)
		res, _ := credential.GetAuthCredentialsWithRefreshTokenAuth(c.Request().Context(), c.Response().Writer, c.Request(), refreshToken)
		return c.JSON(http.StatusOK, res)
	})
	// アクセスしたユーザーの情報を取得する
	// 実行するには、getCredentialsで取得したIDトークンをAuthorizationヘッダーに設定する必要がある
	e.GET("/userinfo", getMe, authMiddleware)
	// SaaSusに登録されているユーザーの一覧を取得する
	// 実行するには、getCredentialsで取得したIDトークンをAuthorizationヘッダーに設定する必要がある
	e.GET("/users", getUsers, authMiddleware)
	return e.Start(":80")
}

func getMe(c echo.Context) error {
	userInfo, ok := c.Get("userInfo").(*authapi.UserInfo)
	if !ok {
		c.Logger().Error("failed to get user info")
		return c.String(http.StatusInternalServerError, "internal server error")
	}
	return c.JSON(http.StatusOK, userInfo)
}

func getUsers(c echo.Context) error {
	userInfo, ok := c.Get("userInfo").(*authapi.UserInfo)
	if !ok {
		c.Logger().Error("failed to get user info")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	res, err := authClient.GetTenantUsersWithResponse(c.Request().Context(), userInfo.Tenants[0].Id)
	if err != nil {
		c.Logger().Error("failed to get saas users: %v", err)
		return c.String(http.StatusInternalServerError, "internal server error")
	}
	if res.JSON200 == nil {
		var msg authapi.Error
		if err := json.Unmarshal(res.Body, &msg); err != nil {
			c.Logger().Error("failed to get saas users: %v", err)
			return c.String(http.StatusInternalServerError, "internal server error")
		}
		c.Logger().Error("failed to get saas users: %v", msg)
		return c.String(http.StatusInternalServerError, "internal server error")
	}
	return c.JSON(http.StatusOK, res.JSON200.Users)
}
