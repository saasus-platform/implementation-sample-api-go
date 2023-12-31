package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/saasus-platform/saasus-sdk-go/generated/authapi"
	"github.com/saasus-platform/saasus-sdk-go/middleware"
	"github.com/saasus-platform/saasus-sdk-go/modules/auth"
	"github.com/saasus-platform/saasus-sdk-go/modules/auth/credential"
	"github.com/saasus-platform/saasus-sdk-go/ctxlib"
	"github.com/joho/godotenv"

)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

var authClient *authapi.ClientWithResponses

// run is a function for start echo server.
func run() error {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	authClient, err = auth.AuthWithResponse()
	if err != nil {
		return fmt.Errorf("failed to create auth client: %w", err)
	}

	// create middleware by authMiddlewareEcho with idTokenGetter{}.
	// By using this middleware, user is authenticated and UserInfo is set in the context.
	idTokenGetter := &middleware.IdTokenGetterFromAuthHeader{}
	authMiddleware := authMiddlewareEcho(idTokenGetter)

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
	// Add extractRefere2rEcho to get referer from request header.
	// This middleware allows you to set the Referer to requests in saasus-sdk.
	e.Use(extractRefererEcho())

	// 一時コードからトークンを取得する
	e.GET("/credentials", getCredentials)
	// リフレッシュトークンからIDトークンを取得する
	e.GET("/refresh", refresh)
	// アクセスしたユーザーの情報を取得する
	// 実行するには、getCredentialsで取得したIDトークンをAuthorizationヘッダーに設定する必要がある
	e.GET("/userinfo", getMe, authMiddleware)
	// SaaSusに登録されているユーザーの一覧を取得する
	// 実行するには、getCredentialsで取得したIDトークンをAuthorizationヘッダーに設定する必要がある
	e.GET("/users", getUsers, authMiddleware)
	return e.Start(":80")
}

// auth is a function for /auth route.
func getCredentials(c echo.Context) error {
	// get token string from query parameter if you set.
	token := c.QueryParam("code")

	credentials, err := credential.GetAuthCredentialsWithTempCodeAuth(c.Request().Context(), token)
	if err != nil {
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	return c.JSON(http.StatusOK, credentials)
}

// refresh is a function for /callback route.
func refresh(c echo.Context) error {
	// get refreshToken string from cookie if you set.
	token, err := c.Cookie("SaaSusRefreshToken")
	if err != nil {
		return c.String(http.StatusInternalServerError, "internal server error")
	}
	c.Logger().Error("SaaSusRefreshToken: %v", token.Value)

	credentials, err := credential.GetAuthCredentialsWithRefreshTokenAuth(context.Background(), token.Value)
	if err != nil {
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	return c.JSON(http.StatusOK, credentials)
}

// authMiddlewareEcho is a middleware for authentication by echo.MiddlewareFunc.
func authMiddlewareEcho(getter middleware.IDTokenGetter) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userInfo, err := middleware.Authenticate(c.Request().Context(), getter.GetIDToken(c.Request()))
			if err != nil {
				http.Error(c.Response().Writer, "Unauthorized "+err.Error(), http.StatusUnauthorized)
				return nil
			}

			c.Set(string(ctxlib.UserInfoKey), userInfo)
			return next(c)
		}
	}
}

// extractRefererEcho extracts referer from request and set it to context.
func extractRefererEcho() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ref := c.Request().Referer()
			if ref != "" {
				ctx := context.WithValue(c.Request().Context(), ctxlib.RefererKey, ref)
				c.SetRequest(c.Request().WithContext(ctx))
			}

			return next(c)
		}
	}
}

// getMe is a function for /me route.
// userInfo Set to context via middleware.AuthMiddlewareEcho
func getMe(c echo.Context) error {
	userInfo, ok := c.Get(string(ctxlib.UserInfoKey)).(*authapi.UserInfo)
	if !ok {
		c.Logger().Error("failed to get user info")
		return c.String(http.StatusInternalServerError, "internal server error")
	}
	return c.JSON(http.StatusOK, userInfo)
}

// getUsers is a function of the /users route.
// users are retrieved from saasus-sdk-go called /v1/auth/users
// authClient.GetSaasUsersWithResponse uses the one generated by opi-gen
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
