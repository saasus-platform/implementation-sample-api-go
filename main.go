package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/saasus-platform/saasus-sdk-go/ctxlib"
	"github.com/saasus-platform/saasus-sdk-go/generated/authapi"
	"github.com/saasus-platform/saasus-sdk-go/generated/pricingapi"
	"github.com/saasus-platform/saasus-sdk-go/middleware"
	"github.com/saasus-platform/saasus-sdk-go/modules/auth"
	"github.com/saasus-platform/saasus-sdk-go/modules/auth/credential"
	"github.com/saasus-platform/saasus-sdk-go/modules/pricing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

var authClient *authapi.ClientWithResponses

var pricingClient *pricingapi.ClientWithResponses

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

	pricingClient, err = pricing.PricingWithResponse()
	if err != nil {
		return fmt.Errorf("failed to create pricing client: %w", err)
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
			AllowHeaders: []string{
				"Authorization",
				"X-Requested-With",
				"Content-Type",
				"x-saasus-referer",
				"X-Access-Token",
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
	// ユーザーが所属するテナント属性を取得する
	// 実行するには、getCredentialsで取得したIDトークンをAuthorizationヘッダーに設定する必要がある
	e.GET("/tenant_attributes", getTenantAttributes, authMiddleware)
	// ユーザー属性を取得する
	// 実行するには、getCredentialsで取得したIDトークンをAuthorizationヘッダーに設定する必要がある
	e.GET("/user_attributes", getUserAttributes, authMiddleware)
	// プラン情報を取得する
	e.GET("/pricing_plan", getPricingPlan, authMiddleware)
	// ユーザー登録を実行する
	e.POST("/user_register", userRegister, authMiddleware)
	// ユーザー削除を実行する
	e.DELETE("/user_delete", userDelete, authMiddleware)
	// ユーザー削除ログを取得する
	e.GET("/delete_user_log", getDeleteUserLogs, authMiddleware)
	// 共通のテナント属性を取得する
	e.GET("/tenant_attributes_list", getTenantAttributesList)
	// セルフサインアップを実行する
	e.POST("/self_sign_up", selfSignup, authMiddleware)
	// ユーザー招待を作成する
	e.POST("/user_invitation", userInvitation, authMiddleware)
	// ユーザー招待を取得する
	e.GET("/invitations", getInvitations, authMiddleware)
	// ログアウトを実行する
	e.POST("/logout", logout, authMiddleware)
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
			ref := c.Request().Header.Get("x-saasus-referer")
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

	if len(userInfo.Tenants) == 0 {
		c.Logger().Error("user does not belong to any tenant")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	tenantId := c.QueryParam("tenant_id") // クエリパラメータを取得
	if tenantId == "" {
		c.Logger().Error("tenant_id query parameter is missing")
		return c.String(http.StatusBadRequest, "tenant_id query parameter is required")
	}

	// ユーザーが所属しているテナントか確認する
	isBelongingTenant := belongingTenant(userInfo.Tenants, tenantId)
	if !isBelongingTenant {
		c.Logger().Errorf("tenant %s does not belong to user", tenantId)
		return c.String(http.StatusForbidden, "Tenant that does not belong")
	}

	res, err := authClient.GetTenantUsersWithResponse(c.Request().Context(), tenantId)
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

// getTenantAttributes is a function for /tenant_attributes route.
func getTenantAttributes(c echo.Context) error {
	userInfo, ok := c.Get(string(ctxlib.UserInfoKey)).(*authapi.UserInfo)
	if !ok {
		c.Logger().Error("failed to get user info")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	if len(userInfo.Tenants) == 0 {
		c.Logger().Error("user does not belong to any tenant")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	tenantId := c.QueryParam("tenant_id") // クエリパラメータを取得
	if tenantId == "" {
		c.Logger().Error("tenant_id query parameter is missing")
		return c.String(http.StatusBadRequest, "tenant_id query parameter is required")
	}

	// ユーザーが所属しているテナントか確認する
	isBelongingTenant := belongingTenant(userInfo.Tenants, tenantId)
	if !isBelongingTenant {
		c.Logger().Errorf("tenant %s does not belong to user", tenantId)
		return c.String(http.StatusForbidden, "Tenant that does not belong")
	}

	// テナント属性の取得
	tenantAttributesResp, err := authClient.GetTenantAttributesWithResponse(context.Background())
	if err != nil {
		c.Logger().Errorf("failed to get tenant attributes: %v", err)
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	// テナント情報の取得
	tenantInfoResp, err := authClient.GetTenantWithResponse(context.Background(), tenantId)
	if err != nil {
		c.Logger().Errorf("failed to get tenant: %v", err)
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	// テナント属性のレスポンスから JSON を取得
	tenantAttributes := tenantAttributesResp.JSON200
	tenantInfo := tenantInfoResp.JSON200

	result := make(map[string]map[string]interface{})

	for _, tenantAttribute := range tenantAttributes.TenantAttributes {
		attributeName := tenantAttribute.AttributeName
		value, ok := tenantInfo.Attributes[attributeName]
		if !ok {
			value = nil
		}

		detail := map[string]interface{}{
			"display_name":   tenantAttribute.DisplayName,
			"attribute_type": tenantAttribute.AttributeType,
			"value":          value,
		}

		result[attributeName] = detail
	}

	return c.JSON(http.StatusOK, result)
}

func belongingTenant(tenants []authapi.UserAvailableTenant, tenantId authapi.Uuid) bool {
	for _, tenant := range tenants {
		if tenant.Id == tenantId {
			return true
		}
	}
	return false
}

// getUserAttributes is a function for /user_attributes route.
func getUserAttributes(c echo.Context) error {
	// ユーザー属性の取得
	userAttributesResp, err := authClient.GetUserAttributesWithResponse(context.Background())
	if err != nil {
		c.Logger().Errorf("failed to get tenant attributes: %v", err)
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	// ユーザー属性のレスポンスから JSON を取得
	userAttributes := userAttributesResp.JSON200

	return c.JSON(http.StatusOK, userAttributes)
}

// getPricingPlan is a function for /pricing_plan route.
func getPricingPlan(c echo.Context) error {
	userInfo, ok := c.Get(string(ctxlib.UserInfoKey)).(*authapi.UserInfo)
	if !ok {
		c.Logger().Error("failed to get user info")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	if len(userInfo.Tenants) == 0 {
		c.Logger().Error("user does not belong to any tenant")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	planId := c.QueryParam("plan_id") // クエリパラメータを取得

	if planId == "" {
		c.Logger().Error("plan_id query parameter is missing")
		return c.String(http.StatusBadRequest, "plan_id query parameter is required")
	}

	// ユーザー属性の取得
	planResp, err := pricingClient.GetPricingPlanWithResponse(context.Background(), planId)
	if err != nil {
		c.Logger().Errorf("failed to get tenant attributes: %v", err)
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	// ユーザー属性のレスポンスから JSON を取得
	plan := planResp.JSON200

	return c.JSON(http.StatusOK, plan)
}

type UserRegisterRequest struct {
	Email               string                 `json:"email"`
	Password            string                 `json:"password"`
	TenantID            string                 `json:"tenantId"`
	UserAttributeValues map[string]interface{} `json:"userAttributeValues"`
}

// userRegister is a function for /user_register route.
func userRegister(c echo.Context) error {
	var request UserRegisterRequest
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid request"})
	}

	email := request.Email
	password := request.Password
	tenantID := request.TenantID
	userAttributeValues := request.UserAttributeValues

	userInfo, ok := c.Get(string(ctxlib.UserInfoKey)).(*authapi.UserInfo)
	if !ok {
		c.Logger().Error("failed to get user info")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	if len(userInfo.Tenants) == 0 {
		c.Logger().Error("user does not belong to any tenant")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	isBelongingTenant := belongingTenant(userInfo.Tenants, tenantID)
	if !isBelongingTenant {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Tenant that does not belong"})
	}

	// ユーザー属性の取得
	userAttributesResp, err := authClient.GetUserAttributesWithResponse(context.Background())
	if err != nil {
		c.Logger().Errorf("failed to get tenant attributes: %v", err)
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	// ユーザー属性のレスポンスから JSON を取得
	userAttributes := userAttributesResp.JSON200
	if userAttributeValues == nil {
		userAttributeValues = make(map[string]interface{})
	}

	if userAttributes != nil {
		for _, attribute := range userAttributes.UserAttributes {
			attributeName := attribute.AttributeName
			attributeType := attribute.AttributeType

			if value, ok := userAttributeValues[attributeName]; ok && attributeType == "number" {
				userAttributeValues[attributeName], err = strconv.Atoi(value.(string))
				if err != nil {
					return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid attribute value"})
				}
			}
		}
	}

	createSaasUserParam := authapi.CreateSaasUserJSONRequestBody{
		Email:    email,
		Password: &password,
	}

	_, err = authClient.CreateSaasUser(context.Background(), createSaasUserParam)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to create SaaS user"})
	}

	createTenantUserParam := authapi.CreateTenantUserParam{
		Email:      email,
		Attributes: userAttributeValues,
	}

	tenantUser, err := authClient.CreateTenantUserWithResponse(context.Background(), tenantID, createTenantUserParam)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to create tenant user"})
	}

	rolesResp, err := authClient.GetRolesWithResponse(context.Background())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to get roles"})
	}

	addRole := "admin"
	for _, role := range rolesResp.JSON200.Roles {
		if role.RoleName == "user" {
			addRole = role.RoleName
			break
		}
	}

	createTenantUserRolesParam := authapi.CreateTenantUserRolesParam{
		RoleNames: []string{addRole},
	}

	_, err = authClient.CreateTenantUserRolesWithResponse(context.Background(), tenantID, tenantUser.JSON201.Id, 3, createTenantUserRolesParam)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to assign roles"})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "User registered successfully"})
}

type UserDeleteRequest struct {
	TenantId string `json:"tenantId" binding:"required"`
	UserId   string `json:"userId" binding:"required"`
}

type DeleteUserLog struct {
	Id       uint      `gorm:"primaryKey" json:"id"`
	TenantId string    `json:"tenant_id"`
	UserId   string    `json:"user_id"`
	Email    string    `json:"email"`
	DeleteAt time.Time `gorm:"column:delete_at"`
}

type DeleteUserLogResponse struct {
	Id       uint   `json:"id"`
	TenantId string `json:"tenant_id"`
	UserId   string `json:"user_id"`
	Email    string `json:"email"`
	DeleteAt string `json:"delete_at"`
}

func getDB() (*gorm.DB, error) {
	dsn := "host=localhost user=postgres password=postgres dbname=postgres port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return db, nil
}

func userDelete(c echo.Context) error {
	// リクエストデータの取得
	req := new(UserDeleteRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"detail": "Invalid request"})
	}

	tenantId := req.TenantId
	userId := req.UserId

	userInfo, ok := c.Get(string(ctxlib.UserInfoKey)).(*authapi.UserInfo)
	if !ok {
		c.Logger().Error("failed to get user info")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	if len(userInfo.Tenants) == 0 {
		c.Logger().Error("user does not belong to any tenant")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	isBelongingTenant := belongingTenant(userInfo.Tenants, tenantId)
	if !isBelongingTenant {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Tenant that does not belong"})
	}

	// ユーザー削除処理
	// SaaSusからユーザー情報を取得
	deleteUser, err := authClient.GetTenantUserWithResponse(context.Background(), tenantId, userId)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"detail": err.Error()})
	}

	// ユーザー削除
	authClient.DeleteTenantUser(context.Background(), tenantId, userId)

	// ユーザー削除ログをデータベースに登録
	deleteUserLog := DeleteUserLog{
		TenantId: tenantId,
		UserId:   userId,
		Email:    deleteUser.JSON200.Email,
		DeleteAt: time.Now(),
	}

	db, err := getDB()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"detail": err.Error()})
	}
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	if err := db.Table("public.delete_user_log").Create(&deleteUserLog).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"detail": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "User deleted successfully"})
}

func getDeleteUserLogs(c echo.Context) error {
	tenantId := c.QueryParam("tenant_id")

	userInfo, ok := c.Get(string(ctxlib.UserInfoKey)).(*authapi.UserInfo)
	if !ok {
		c.Logger().Error("failed to get user info")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	if len(userInfo.Tenants) == 0 {
		c.Logger().Error("user does not belong to any tenant")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	isBelongingTenant := belongingTenant(userInfo.Tenants, tenantId)
	if !isBelongingTenant {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Tenant that does not belong"})
	}

	// データベース接続の取得
	db, err := getDB()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"detail": "Failed to connect to the database"})
	}

	var deleteUserLogs []DeleteUserLog
	if err := db.Table("public.delete_user_log").Where("tenant_id = ?", tenantId).Find(&deleteUserLogs).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"detail": err.Error()})
	}

	// Gormのオブジェクトをレスポンス用の構造体に変換
	responseData := []DeleteUserLogResponse{}
	for _, log := range deleteUserLogs {
		responseData = append(responseData, DeleteUserLogResponse{
			Id:       log.Id,
			TenantId: log.TenantId,
			UserId:   log.UserId,
			Email:    log.Email,
			DeleteAt: log.DeleteAt.Format(time.RFC3339),
		})
	}

	return c.JSON(http.StatusOK, responseData)
}

func getTenantAttributesList(c echo.Context) error {
	tenantAttributesResp, err := authClient.GetTenantAttributesWithResponse(context.Background())
	if err != nil {
		c.Logger().Errorf("Failed to retrieve tenant attributes: %v", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to retrieve tenant attributes"})
	}

	// テナント属性が存在しない場合のハンドリング
	if tenantAttributesResp.JSON200 == nil {
		return c.JSON(http.StatusOK, echo.Map{"message": "No tenant attributes found"})
	}

	return c.JSON(http.StatusOK, tenantAttributesResp.JSON200)
}

type SelfSignupRequest struct {
	TenantName            string                 `json:"tenantName"`
	TenantAttributeValues map[string]interface{} `json:"tenantAttributeValues"`
	UserAttributeValues   map[string]interface{} `json:"userAttributeValues"`
}

func selfSignup(c echo.Context) error {
	var request SelfSignupRequest
	if err := c.Bind(&request); err != nil {
		c.Logger().Errorf("Failed to bind request: %v", err)
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid request"})
	}

	userInfo, ok := c.Get(string(ctxlib.UserInfoKey)).(*authapi.UserInfo)
	if !ok {
		c.Logger().Error("failed to get user info")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	// ユーザーが既にテナントに関連付けられている場合のチェック
	if len(userInfo.Tenants) > 0 {
		c.Logger().Error("User is already associated with a tenant")
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "User is already associated with a tenant"})
	}

	tenantName := request.TenantName
	tenantAttributeValues := request.TenantAttributeValues
	userAttributeValues := request.UserAttributeValues

	// テナント属性を取得する
	tenantAttributesResp, err := authClient.GetTenantAttributesWithResponse(context.Background())
	if err != nil {
		c.Logger().Errorf("Failed to retrieve tenant attributes: %v", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to retrieve tenant attributes"})
	}

	tenantAttributes := tenantAttributesResp.JSON200
	if tenantAttributeValues == nil {
		tenantAttributeValues = make(map[string]interface{})
	}

	if tenantAttributes != nil {
		for _, attribute := range tenantAttributes.TenantAttributes {
			attributeName := attribute.AttributeName
			attributeType := attribute.AttributeType
			if value, ok := tenantAttributeValues[attributeName]; ok && attributeType == "number" {
				tenantAttributeValues[attributeName], err = strconv.Atoi(value.(string))
				if err != nil {
					c.Logger().Errorf("Invalid tenant attribute value: %v", err)
					return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid tenant attribute value"})
				}
			}
		}
	}

	// テナントを作成する
	tenantProps := authapi.CreateTenantParam{
		Name:                 tenantName,
		Attributes:           tenantAttributeValues,
		BackOfficeStaffEmail: userInfo.Email,
	}

	tenantResp, err := authClient.CreateTenantWithResponse(context.Background(), tenantProps)
	if err != nil {
		c.Logger().Errorf("Failed to create tenant: %v", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to create tenant"})
	}

	tenantID := tenantResp.JSON201.Id

	// ユーザー属性を取得する
	userAttributesResp, err := authClient.GetUserAttributesWithResponse(context.Background())
	if err != nil {
		c.Logger().Errorf("Failed to retrieve user attributes: %v", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to retrieve user attributes"})
	}

	userAttributes := userAttributesResp.JSON200
	if userAttributeValues == nil {
		userAttributeValues = make(map[string]interface{})
	}

	if userAttributes != nil {
		for _, attribute := range userAttributes.UserAttributes {
			attributeName := attribute.AttributeName
			attributeType := attribute.AttributeType
			if value, ok := userAttributeValues[attributeName]; ok && attributeType == "number" {
				userAttributeValues[attributeName], err = strconv.Atoi(value.(string))
				if err != nil {
					c.Logger().Errorf("Invalid user attribute value: %v", err)
					return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid user attribute value"})
				}
			}
		}
	}

	// テナントユーザーを登録する
	createTenantUserParam := authapi.CreateTenantUserParam{
		Email:      userInfo.Email,
		Attributes: userAttributeValues,
	}

	tenantUserResp, err := authClient.CreateTenantUserWithResponse(context.Background(), tenantID, createTenantUserParam)
	if err != nil {
		c.Logger().Errorf("Failed to create tenant user: %v", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to create tenant user"})
	}

	// ユーザーにロールを割り当てる
	createTenantUserRolesParam := authapi.CreateTenantUserRolesParam{
		RoleNames: []string{"admin"},
	}

	_, err = authClient.CreateTenantUserRolesWithResponse(context.Background(), tenantID, tenantUserResp.JSON201.Id, 3, createTenantUserRolesParam)
	if err != nil {
		c.Logger().Errorf("Failed to assign roles: %v", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to assign roles"})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "User successfully registered to the tenant"})
}

func logout(c echo.Context) error {
	// クライアントのクッキーを削除
	c.SetCookie(&http.Cookie{
		Name:     "SaaSusRefreshToken",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
	})

	// JSON レスポンスを返す
	return c.JSON(http.StatusOK, map[string]string{
		"message": "Logged out successfully",
	})
}

type UserInvitationRequest struct {
	Email    string `json:"email"`
	TenantID string `json:"tenantId"`
}

// userInvitation is a function for /user_invitation route.
func userInvitation(c echo.Context) error {
	var request UserInvitationRequest
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid request"})
	}

	email := request.Email
	tenantID := request.TenantID

	userInfo, ok := c.Get(string(ctxlib.UserInfoKey)).(*authapi.UserInfo)
	if !ok {
		c.Logger().Error("failed to get user info")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	if len(userInfo.Tenants) == 0 {
		c.Logger().Error("user does not belong to any tenant")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	isBelongingTenant := belongingTenant(userInfo.Tenants, tenantID)
	if !isBelongingTenant {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Tenant that does not belong"})
	}

	// 招待を作成するユーザーのアクセストークンを取得
	accessToken := c.Request().Header.Get("X-Access-Token")

	// アクセストークンがリクエストヘッダーに含まれていなかったらエラー
	if accessToken == "" {
		return c.String(http.StatusBadRequest, "Access token is missing")
	}

	// テナント招待のパラメータを作成
	createTenantInvitationJSONRequestBody := authapi.CreateTenantInvitationJSONRequestBody{
		AccessToken: accessToken,
		Email:       email,
		Envs: []struct {
			Id        uint64   `json:"id"`
			RoleNames []string `json:"role_names"`
		}{
			{
				Id:        3, // 本番環境のID:3を設定
				RoleNames: []string{"admin"},
			},
		},
	}

	// テナントへの招待を作成
	authClient.CreateTenantInvitation(context.Background(), tenantID, createTenantInvitationJSONRequestBody)

	return c.JSON(http.StatusOK, echo.Map{"message": "Create tenant user invitation successfully"})
}

// getInvitations is a function for /invitations route.
func getInvitations(c echo.Context) error {
	userInfo, ok := c.Get("userInfo").(*authapi.UserInfo)
	if !ok {
		c.Logger().Error("failed to get user info")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	if len(userInfo.Tenants) == 0 {
		c.Logger().Error("user does not belong to any tenant")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	tenantId := c.QueryParam("tenant_id") // クエリパラメータを取得
	if tenantId == "" {
		c.Logger().Error("tenant_id query parameter is missing")
		return c.String(http.StatusBadRequest, "tenant_id query parameter is required")
	}

	// ユーザーが所属しているテナントか確認する
	isBelongingTenant := belongingTenant(userInfo.Tenants, tenantId)
	if !isBelongingTenant {
		c.Logger().Errorf("tenant %s does not belong to user", tenantId)
		return c.String(http.StatusForbidden, "Tenant that does not belong")
	}

	// テナントが発行している全招待を取得する
	res, err := authClient.GetTenantInvitationsWithResponse(c.Request().Context(), tenantId)
	if err != nil {
		c.Logger().Error("failed to get tenant invitations: %v", err)
		return c.String(http.StatusInternalServerError, "internal server error")
	}
	if res.JSON200 == nil {
		var msg authapi.Error
		if err := json.Unmarshal(res.Body, &msg); err != nil {
			c.Logger().Error("failed to get tenant invitations: %v", err)
			return c.String(http.StatusInternalServerError, "internal server error")
		}
		c.Logger().Error("failed to get tenant invitations: %v", msg)
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	return c.JSON(http.StatusOK, res.JSON200.Invitations)
}
