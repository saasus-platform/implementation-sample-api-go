package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/saasus-platform/saasus-sdk-go/ctxlib"
	"github.com/saasus-platform/saasus-sdk-go/generated/authapi"
	"github.com/saasus-platform/saasus-sdk-go/generated/pricingapi"
)

// ──────────────────────────────────────────────
// DTO 定義
// ──────────────────────────────────────────────
// 課金ダッシュボード全体
type BillingDashboardResponse struct {
	Summary              DashboardSummary      `json:"summary"`
	MeteringUnitBillings []MeteringUnitBilling `json:"metering_unit_billings"`
	PricingPlanInfo      PricingPlanInfo       `json:"pricing_plan_info"`
	TaxRate              *pricingapi.TaxRate   `json:"tax_rate,omitempty"`
}

// 課金概要（通貨別合計 & 件数）
type DashboardSummary struct {
	TotalByCurrency    []CurrencyTotal `json:"total_by_currency"`
	TotalMeteringUnits int             `json:"total_metering_units"`
}

// 通貨ごとの合計金額
type CurrencyTotal struct {
	Currency    string  `json:"currency"`
	TotalAmount float64 `json:"total_amount"`
}

// 計測単位ごとの課金明細
type MeteringUnitBilling struct {
	MeteringUnitName       string  `json:"metering_unit_name"`
	MeteringUnitType       string  `json:"metering_unit_type"`
	FunctionMenuName       string  `json:"function_menu_name"`
	PeriodCount            float64 `json:"period_count"`
	Currency               string  `json:"currency"`
	PeriodAmount           float64 `json:"period_amount"`
	PricingUnitDisplayName string  `json:"pricing_unit_display_name"`
}

// 料金プラン情報
type PricingPlanInfo struct {
	PlanID      string `json:"plan_id"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}

// プラン適用期間の選択肢情報
type PlanPeriodOption struct {
	Label  string `json:"label"`
	PlanID string `json:"plan_id"`
	Start  int64  `json:"start"`
	End    int64  `json:"end"`
}

// internal 用: ティア料金構造
type tier struct {
	To         int     // up_to
	Inf        bool    // inf
	FlatAmount float64 // flat_amount
	UnitPrice  float64 // unit_amount
}

// ──────────────────────────────────────────────
// /billing/dashboard   課金ダッシュボード
// ──────────────────────────────────────────────
func getBillingDashboard(c echo.Context) error {
	userInfo, ok := c.Get(string(ctxlib.UserInfoKey)).(*authapi.UserInfo)
	if !ok {
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	tenantId := c.QueryParam("tenant_id")
	planId := c.QueryParam("plan_id")
	startStr := c.QueryParam("period_start")
	endStr := c.QueryParam("period_end")

	if tenantId == "" || planId == "" || startStr == "" || endStr == "" {
		return c.String(http.StatusBadRequest, "tenant_id, plan_id, period_start, period_end are required")
	}

	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid period_start")
	}
	end, err := strconv.ParseInt(endStr, 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid period_end")
	}

	// 権限（admin / sadmin）チェック
	if !hasBillingAccess(userInfo, tenantId) {
		return c.String(http.StatusForbidden, "Insufficient permissions")
	}

	ctx := c.Request().Context()

	// プラン情報
	planResp, err := pricingClient.GetPricingPlanWithResponse(ctx, planId)
	if err != nil || planResp.JSON200 == nil {
		return c.String(http.StatusNotFound, "Pricing plan not found for the given plan_id.")
	}
	plan := planResp.JSON200

	// テナント取得
	tenantResp, err := authClient.GetTenantWithResponse(ctx, authapi.Uuid(tenantId))
	if err != nil || tenantResp.JSON200 == nil {
		return c.String(http.StatusNotFound, "Tenant not found for the given tenant_id.")
	}
	tenant := tenantResp.JSON200

	// 該当税率を抽出（プラン履歴）
	var matchedTax *pricingapi.TaxRate
	var appliedAt int64
	var taxRateID authapi.Uuid

	for _, h := range tenant.PlanHistories {
		if string(h.PlanId) == planId && int64(h.PlanAppliedAt) <= start {
			if int64(h.PlanAppliedAt) >= appliedAt && h.TaxRateId != nil {
				appliedAt = int64(h.PlanAppliedAt)
				taxRateID = *h.TaxRateId
			}
		}
	}

	if taxRateID != "" {
		taxResp, _ := pricingClient.GetTaxRatesWithResponse(ctx)
		if taxResp != nil && taxResp.JSON200 != nil {
			for _, tr := range taxResp.JSON200.TaxRates {
				if tr.Id == string(taxRateID) {
					matchedTax = &tr
					break
				}
			}
		}
	}

	// メータ課金計算
	billings, totals, err := calculateMeteringUnitBillings(ctx, tenantId, start, end, plan)
	if err != nil {
		log.Printf("billing calculation failed: %v", err)
		return c.String(http.StatusInternalServerError, "billing calculation failed")
	}

	resp := BillingDashboardResponse{
		Summary: DashboardSummary{
			TotalByCurrency:    totals,
			TotalMeteringUnits: len(billings),
		},
		MeteringUnitBillings: billings,
		PricingPlanInfo: PricingPlanInfo{
			PlanID:      planId,
			DisplayName: plan.DisplayName,
			Description: plan.Description,
		},
		TaxRate: matchedTax,
	}

	return c.JSON(http.StatusOK, resp)
}

// getPlanPeriods handles the `/tenant/plan_periods` endpoint and returns
// available plan periods (billing intervals) for a tenant.
//
//   - Builds boundary points from the tenant’s plan history and the
//     current plan period end timestamp.
//   - Determines whether each segment is billed monthly or annually
//     and splits the intervals accordingly.
//   - Returns JSON sorted from newest to oldest.
func getPlanPeriods(c echo.Context) error {
	tenantId := c.QueryParam("tenant_id")
	if tenantId == "" {
		return c.String(http.StatusBadRequest, "tenant_id required")
	}

	ctx := c.Request().Context()

	// 1) テナント取得
	tResp, err := authClient.GetTenantWithResponse(ctx, authapi.Uuid(tenantId))
	if err != nil || tResp.JSON200 == nil {
		return c.String(http.StatusInternalServerError, "tenant fetch error")
	}
	tenant := tResp.JSON200

	// 2) 境界エッジ作成（PlanAppliedAt 昇順）
	type edge struct {
		PlanID string
		Time   time.Time
	}
	loc, _ := time.LoadLocation("Asia/Tokyo")
	var edges []edge
	for _, h := range tenant.PlanHistories {
		edges = append(edges, edge{
			PlanID: string(h.PlanId),
			Time:   time.Unix(int64(h.PlanAppliedAt), 0).In(loc),
		})
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].Time.Before(edges[j].Time) })

	// 3) 最後の境界（current_plan_period_end があればその 1 秒前、無ければ「今」）
	lastBoundary := time.Now().In(loc)
	if tenant.CurrentPlanPeriodEnd != nil {
		lastBoundary = time.Unix(int64(*tenant.CurrentPlanPeriodEnd)-1, 0).In(loc)
	}

	// 4) 区間を月／年単位で分割
	var results []PlanPeriodOption
	for idx, e := range edges {
		if e.PlanID == "" { // プラン未設定境界はスキップ
			continue
		}

		periodStart := e.Time
		periodEnd := lastBoundary
		if idx+1 < len(edges) {
			periodEnd = edges[idx+1].Time.Add(-time.Second)
		}

		// 年払い判定
		recurring := "month"
		if pResp, _ := pricingClient.GetPricingPlanWithResponse(ctx, e.PlanID); pResp != nil && pResp.JSON200 != nil {
			if hasYearUnit(pResp.JSON200.PricingMenus) {
				recurring = "year"
			}
		}

		step := func(t time.Time) time.Time {
			if recurring == "year" {
				return t.AddDate(1, 0, 0)
			}
			return t.AddDate(0, 1, 0)
		}

		for cur := periodStart; !cur.After(periodEnd); {
			next := step(cur)
			end := next.Add(-time.Second)
			if end.After(periodEnd) {
				end = periodEnd
			}
			if !end.After(cur) { // 0 秒区間なら抜ける
				break
			}

			label := fmt.Sprintf(
				"%04d年%02d月%02d日 %02d:%02d:%02d ～ %04d年%02d月%02d日 %02d:%02d:%02d",
				cur.Year(), cur.Month(), cur.Day(), cur.Hour(), cur.Minute(), cur.Second(),
				end.Year(), end.Month(), end.Day(), end.Hour(), end.Minute(), end.Second(),
			)

			results = append(results, PlanPeriodOption{
				Label:  label,
				PlanID: e.PlanID,
				Start:  cur.Unix(),
				End:    end.Unix(),
			})

			if end.Equal(periodEnd) {
				break
			}
			cur = end.Add(time.Second)
		}
	}

	// 5) 新しい順に並べ替え
	sort.Slice(results, func(i, j int) bool { return results[i].Start > results[j].Start })

	return c.JSON(http.StatusOK, results)
}

// ──────────────────────────────────────────────
// /metering/:tenantId/:unit/:ts   メータ更新
// ──────────────────────────────────────────────
func updateCountOfSpecifiedTS(c echo.Context) error {
	tenantId := c.Param("tenantId")
	unitName := c.Param("unit")
	tsStr := c.Param("ts")

	userInfo, _ := c.Get(string(ctxlib.UserInfoKey)).(*authapi.UserInfo)
	if !hasBillingAccess(userInfo, tenantId) {
		return c.String(http.StatusForbidden, "Insufficient permissions")
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "ts must be 10-digit unix seconds")
	}

	var body struct {
		Method string `json:"method"` // add | sub | direct
		Count  int    `json:"count"`
	}
	if err := c.Bind(&body); err != nil {
		return c.String(http.StatusBadRequest, "invalid JSON body")
	}
	if body.Count < 0 {
		return c.String(http.StatusBadRequest, "count must be >= 0")
	}

	method := pricingapi.UpdateMeteringUnitTimestampCountMethod(body.Method)
	switch method {
	case pricingapi.Add, pricingapi.Sub, pricingapi.Direct:
		// ok
	default:
		return c.String(http.StatusBadRequest, "method must be add, sub, or direct")
	}

	param := pricingapi.UpdateMeteringUnitTimestampCountParam{
		Method: method,
		Count:  body.Count,
	}

	resp, err := pricingClient.UpdateMeteringUnitTimestampCountWithResponse(
		c.Request().Context(), tenantId, unitName, int(ts), param,
	)
	if err != nil {
		log.Printf("pricing API error: %v", err)
		return c.String(http.StatusInternalServerError, "pricing API error")
	}
	if resp.JSON200 == nil {
		return c.String(resp.StatusCode(), string(resp.Body))
	}

	return c.JSON(http.StatusOK, resp.JSON200)
}

// ──────────────────────────────────────────────
// /metering/:tenantId/:unit   メータ更新
// ──────────────────────────────────────────────
func updateCountOfNow(c echo.Context) error {
	tenantId := c.Param("tenantId")
	unitName := c.Param("unit")

	userInfo, _ := c.Get(string(ctxlib.UserInfoKey)).(*authapi.UserInfo)
	if !hasBillingAccess(userInfo, tenantId) {
		return c.String(http.StatusForbidden, "Insufficient permissions")
	}

	var body struct {
		Method string `json:"method"` // add | sub | direct
		Count  int    `json:"count"`
	}
	if err := c.Bind(&body); err != nil {
		return c.String(http.StatusBadRequest, "invalid JSON body")
	}
	if body.Count < 0 {
		return c.String(http.StatusBadRequest, "count must be >= 0")
	}

	method := pricingapi.UpdateMeteringUnitTimestampCountMethod(body.Method)
	switch method {
	case pricingapi.Add, pricingapi.Sub, pricingapi.Direct:
		// ok
	default:
		return c.String(http.StatusBadRequest, "method must be add, sub, or direct")
	}

	param := pricingapi.UpdateMeteringUnitTimestampCountNowParam{
		Method: method,
		Count:  body.Count,
	}

	resp, err := pricingClient.UpdateMeteringUnitTimestampCountNowWithResponse(
		c.Request().Context(), tenantId, unitName, param,
	)
	if err != nil {
		log.Printf("pricing API error: %v", err)
		return c.String(http.StatusInternalServerError, "pricing API error")
	}
	if resp.JSON200 == nil {
		return c.String(resp.StatusCode(), string(resp.Body))
	}

	return c.JSON(http.StatusOK, resp.JSON200)
}

// ──────────────────────────────────────────────
// 権限制御ユーティリティ
// ──────────────────────────────────────────────
func hasBillingAccess(userInfo *authapi.UserInfo, tenantId string) bool {
	if !belongingTenant(userInfo.Tenants, authapi.Uuid(tenantId)) {
		return false
	}
	for _, t := range userInfo.Tenants {
		if string(t.Id) != tenantId {
			continue
		}
		for _, env := range t.Envs {
			for _, r := range env.Roles {
				if r.RoleName == "admin" || r.RoleName == "sadmin" {
					return true
				}
			}
		}
	}
	return false
}

// ──────────────────────────────────────────────
// 課金計算
// ──────────────────────────────────────────────
func calculateMeteringUnitBillings(ctx context.Context, tenantId string, start, end int64, plan *pricingapi.PricingPlan) ([]MeteringUnitBilling, []CurrencyTotal, error) {
	var billings []MeteringUnitBilling
	currencySum := map[string]float64{}
	usageCache := map[string]float64{}

	for _, menu := range plan.PricingMenus {
		menuName := menu.DisplayName
		for _, unit := range menu.Units {

			// 型変換のため一旦 JSON ↔ map
			raw, _ := json.Marshal(unit)
			var u map[string]interface{}
			_ = json.Unmarshal(raw, &u)

			unitType, ok := u["type"].(string)
			if !ok || unitType == "" {
				unitType = "usage"
			}

			unitName, ok := u["metering_unit_name"].(string)
			if !ok {
				unitName = ""
			}

			dispName, ok := u["display_name"].(string)
			if !ok {
				dispName = ""
			}

			curr, ok := u["currency"].(string)
			if !ok || curr == "" {
				curr = "JPY"
			}

			aggUsage, ok := u["aggregate_usage"].(string)
			if !ok || aggUsage == "" {
				aggUsage = "sum"
			}

			// 使用量取得
			count := usageCache[unitName]
			if unitType != "fixed" && count == 0 {
				st := int(start)
				ed := int(end)
				resp, err := pricingClient.GetMeteringUnitDateCountByTenantIdAndUnitNameAndDatePeriodWithResponse(
					ctx, tenantId, unitName,
					&pricingapi.GetMeteringUnitDateCountByTenantIdAndUnitNameAndDatePeriodParams{
						StartTimestamp: (*pricingapi.StartTimestamp)(&st),
						EndTimestamp:   (*pricingapi.EndTimestamp)(&ed),
					})
				if err == nil && resp.JSON200 != nil {
					if aggUsage == "max" {
						for _, c := range resp.JSON200.Counts {
							if float64(c.Count) > count {
								count = float64(c.Count)
							}
						}
					} else {
						for _, c := range resp.JSON200.Counts {
							count += float64(c.Count)
						}
					}
				}
				usageCache[unitName] = count
			}

			amount := calculateAmountByUnitType(count, u)
			billings = append(billings, MeteringUnitBilling{
				MeteringUnitName:       unitName,
				MeteringUnitType:       unitType,
				FunctionMenuName:       menuName,
				PeriodCount:            count,
				Currency:               curr,
				PeriodAmount:           amount,
				PricingUnitDisplayName: dispName,
			})
			currencySum[curr] += amount
		}
	}

	// 通貨別集計配列化
	var totals []CurrencyTotal
	for k, v := range currencySum {
		totals = append(totals, CurrencyTotal{Currency: k, TotalAmount: v})
	}
	sort.Slice(totals, func(i, j int) bool { return totals[i].Currency < totals[j].Currency })
	return billings, totals, nil
}

// ──────────────────────────────────────────────
// 金額計算 (unit type)
// ──────────────────────────────────────────────
func calculateAmountByUnitType(count float64, u map[string]interface{}) float64 {
	unitType, _ := u["type"].(string)
	price, _ := u["unit_amount"].(float64)

	switch unitType {
	case "fixed":
		return price
	case "usage":
		return count * price
	case "tiered":
		return calcTiered(count, u)
	case "tiered_usage":
		return calcTieredUsage(count, u)
	default:
		return count * price
	}
}

// tiered: 指定 count が属する段の flat + count*unit
func calcTiered(count float64, u map[string]interface{}) float64 {
	tiers := extractTiers(u)
	var last tier
	for _, t := range tiers {
		last = t
		if t.Inf || count <= float64(t.To) {
			return t.FlatAmount + count*t.UnitPrice
		}
	}
	return last.FlatAmount + count*last.UnitPrice
}

// tiered_usage: 累積計算
func calcTieredUsage(count float64, u map[string]interface{}) float64 {
	tiers := extractTiers(u)
	var total float64
	var prev float64
	for _, t := range tiers {
		if count <= prev {
			break
		}
		var usage float64
		if t.Inf {
			usage = count - prev
		} else {
			usage = math.Min(count, float64(t.To)) - prev
		}
		total += t.FlatAmount + usage*t.UnitPrice
		prev = float64(t.To)
	}
	return total
}

func extractTiers(u map[string]interface{}) []tier {
	var res []tier
	if raw, ok := u["tiers"].([]interface{}); ok {
		for _, r := range raw {
			if m, ok := r.(map[string]interface{}); ok {
				t := tier{}
				if v, ok := m["up_to"].(float64); ok {
					t.To = int(v)
				}
				if v, ok := m["inf"].(bool); ok {
					t.Inf = v
				}
				if v, ok := m["flat_amount"].(float64); ok {
					t.FlatAmount = v
				}
				if v, ok := m["unit_amount"].(float64); ok {
					t.UnitPrice = v
				}
				res = append(res, t)
			}
		}
	}
	return res
}

// 対象プランに recurring_interval == "year" の unit が 1 つでもあるか
func hasYearUnit(menus []pricingapi.PricingMenu) bool {
	for _, menu := range menus {
		for _, u := range menu.Units {
			raw, _ := json.Marshal(u)
			var m map[string]interface{}
			_ = json.Unmarshal(raw, &m)
			if m["recurring_interval"] == "year" {
				return true
			}
		}
	}
	return false
}

// ──────────────────────────────────────────────
// プラン管理機能
// ──────────────────────────────────────────────

// getPricingPlans is a function for /pricing_plans route.
func getPricingPlans(c echo.Context) error {
	userInfo, ok := c.Get(string(ctxlib.UserInfoKey)).(*authapi.UserInfo)
	if !ok {
		c.Logger().Error("failed to get user info")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	if len(userInfo.Tenants) == 0 {
		c.Logger().Error("user does not belong to any tenant")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	// 料金プラン一覧を取得
	plansResp, err := pricingClient.GetPricingPlansWithResponse(c.Request().Context())
	if err != nil {
		c.Logger().Errorf("failed to get pricing plans: %v", err)
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	if plansResp.JSON200 == nil {
		var msg pricingapi.Error
		if err := json.Unmarshal(plansResp.Body, &msg); err != nil {
			c.Logger().Errorf("failed to get pricing plans: %v", err)
			return c.String(http.StatusInternalServerError, "internal server error")
		}
		c.Logger().Errorf("failed to get pricing plans: %v", msg)
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	return c.JSON(http.StatusOK, plansResp.JSON200.PricingPlans)
}

// getTaxRates is a function for /tax_rates route.
func getTaxRates(c echo.Context) error {
	userInfo, ok := c.Get(string(ctxlib.UserInfoKey)).(*authapi.UserInfo)
	if !ok {
		c.Logger().Error("failed to get user info")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	if len(userInfo.Tenants) == 0 {
		c.Logger().Error("user does not belong to any tenant")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	// 税率一覧を取得
	taxRatesResp, err := pricingClient.GetTaxRatesWithResponse(c.Request().Context())
	if err != nil {
		c.Logger().Errorf("failed to get tax rates: %v", err)
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	if taxRatesResp.JSON200 == nil {
		var msg pricingapi.Error
		if err := json.Unmarshal(taxRatesResp.Body, &msg); err != nil {
			c.Logger().Errorf("failed to get tax rates: %v", err)
			return c.String(http.StatusInternalServerError, "internal server error")
		}
		c.Logger().Errorf("failed to get tax rates: %v", msg)
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	return c.JSON(http.StatusOK, taxRatesResp.JSON200.TaxRates)
}

type UpdateTenantPlanRequest struct {
	NextPlanId        string  `json:"next_plan_id"`
	TaxRateId         *string `json:"tax_rate_id,omitempty"`
	UsingNextPlanFrom *int64  `json:"using_next_plan_from,omitempty"`
}

// updateTenantPlan is a function for /tenants/:tenant_id/plan route (PUT).
func updateTenantPlan(c echo.Context) error {
	tenantId := c.Param("tenant_id")
	if tenantId == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "tenant_id is required"})
	}

	var request UpdateTenantPlanRequest
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid request"})
	}
	nextPlanId := request.NextPlanId
	taxRateId := request.TaxRateId
	usingNextPlanFrom := request.UsingNextPlanFrom

	userInfo, ok := c.Get(string(ctxlib.UserInfoKey)).(*authapi.UserInfo)
	if !ok {
		c.Logger().Error("failed to get user info")
		return c.String(http.StatusInternalServerError, "internal server error")
	}

	// 管理者権限チェック（hasBillingAccess関数を再利用）
	if !hasBillingAccess(userInfo, tenantId) {
		return c.String(http.StatusForbidden, "Insufficient permissions")
	}

	// テナントプランを更新
	updateTenantPlanParam := authapi.UpdateTenantPlanParam{
		NextPlanId: (*authapi.Uuid)(&nextPlanId),
	}

	// 税率IDが指定されている場合のみ設定
	if taxRateId != nil && *taxRateId != "" {
		updateTenantPlanParam.NextPlanTaxRateId = (*authapi.Uuid)(taxRateId)
	}

	// using_next_plan_fromが指定されている場合のみ設定
	if usingNextPlanFrom != nil && *usingNextPlanFrom > 0 {
		usingNextPlanFromInt := int(*usingNextPlanFrom)
		updateTenantPlanParam.UsingNextPlanFrom = &usingNextPlanFromInt
	}

	resp, err := authClient.UpdateTenantPlanWithResponse(c.Request().Context(), tenantId, updateTenantPlanParam)
	if err != nil {
		c.Logger().Errorf("failed to update tenant plan: %v", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to update tenant plan"})
	}

	// レスポンスのステータスコードをチェック
	if resp.StatusCode() != http.StatusOK {
		c.Logger().Errorf("tenant plan update failed with status %d: %s", resp.StatusCode(), string(resp.Body))

		// エラーレスポンスからmessageを抽出
		var errorResponse map[string]interface{}
		if err := json.Unmarshal(resp.Body, &errorResponse); err == nil {
			if message, ok := errorResponse["message"].(string); ok {
				return c.JSON(resp.StatusCode(), echo.Map{"error": message})
			}
		}

		return c.JSON(resp.StatusCode(), echo.Map{"error": "Failed to update tenant plan"})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "Tenant plan updated successfully"})
}

// getTenantPlanInfo is a function for /tenants/:tenant_id route (GET).
// Returns tenant information with plan details and reservations formatted for frontend.
func getTenantPlanInfo(c echo.Context) error {
	tenantId := c.Param("tenant_id")
	if tenantId == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "tenant_id is required"})
	}

	userInfo, ok := c.Get(string(ctxlib.UserInfoKey)).(*authapi.UserInfo)
	if !ok {
		c.Logger().Error("failed to get user info")
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Internal server error"})
	}

	// 管理者権限チェック
	if !hasBillingAccess(userInfo, tenantId) {
		return c.JSON(http.StatusForbidden, echo.Map{"error": "Insufficient permissions"})
	}

	// テナント詳細情報を取得
	tenantDetailResp, err := authClient.GetTenantWithResponse(c.Request().Context(), authapi.TenantId(tenantId))
	if err != nil {
		c.Logger().Errorf("Failed to retrieve tenant detail: %v", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to retrieve tenant detail"})
	}

	if tenantDetailResp.StatusCode() != http.StatusOK {
		c.Logger().Errorf("Failed to retrieve tenant detail: status %d", tenantDetailResp.StatusCode())
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to retrieve tenant detail"})
	}

	if tenantDetailResp.JSON200 == nil {
		return c.JSON(http.StatusNotFound, echo.Map{"error": "Tenant not found"})
	}

	// 現在のプランの税率情報を取得（プラン履歴の最新エントリから）
	var currentTaxRateId *string
	if len(tenantDetailResp.JSON200.PlanHistories) > 0 {
		latestPlanHistory := tenantDetailResp.JSON200.PlanHistories[len(tenantDetailResp.JSON200.PlanHistories)-1]
		if latestPlanHistory.TaxRateId != nil {
			taxRateIdStr := string(*latestPlanHistory.TaxRateId)
			currentTaxRateId = &taxRateIdStr
		}
	}

	// レスポンスを構築
	response := echo.Map{
		"id":               tenantDetailResp.JSON200.Id,
		"name":             tenantDetailResp.JSON200.Name,
		"plan_id":          tenantDetailResp.JSON200.PlanId,
		"tax_rate_id":      currentTaxRateId,
		"plan_reservation": nil,
	}

	// 予約情報がある場合は追加
	if tenantDetailResp.JSON200.NextPlanId != nil {
		planReservation := echo.Map{
			"next_plan_id":          *tenantDetailResp.JSON200.NextPlanId,
			"using_next_plan_from":  tenantDetailResp.JSON200.UsingNextPlanFrom,
			"next_plan_tax_rate_id": tenantDetailResp.JSON200.NextPlanTaxRateId,
		}
		response["plan_reservation"] = planReservation
	}

	return c.JSON(http.StatusOK, response)
}
