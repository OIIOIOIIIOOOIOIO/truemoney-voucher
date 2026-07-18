package twapi

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	utls "github.com/refraction-networking/utls"
)

var client = newHTTPClient()

const campaignPrefix = "https://gift.truemoney.com/campaign/?v="

// Firefox TLS fingerprint – known stable with Cloudflare + uTLS.
var browserFingerprint = utls.HelloFirefox_120

// firefoxSpec is the Firefox 120 ClientHelloSpec cached once (includes h2 ALPN).
var (
	firefoxSpec     *utls.ClientHelloSpec
	firefoxSpecOnce sync.Once
)

func getFirefoxSpec() *utls.ClientHelloSpec {
	firefoxSpecOnce.Do(func() {
		spec, err := utls.UTLSIdToSpec(browserFingerprint)
		if err != nil {
			panic("utls: failed to build Firefox 120 spec: " + err.Error())
		}
		firefoxSpec = &spec
	})
	return firefoxSpec
}

// firefoxHeaderOrder is the exact header order Firefox sends.
var firefoxHeaderOrder = []string{
	"Host",
	"User-Agent",
	"Accept",
	"Accept-Language",
	"Accept-Encoding",
	"Content-Type",
	"Referer",
	"Sec-Fetch-Dest",
	"Sec-Fetch-Mode",
	"Sec-Fetch-Site",
	"Priority",
}

func newHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:     jar,
		Timeout: 15 * time.Second,
		Transport: &browserTransport{
			dialer: &net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			},
		},
	}
}

// browserTransport is an http.RoundTripper that mimics Chrome at the wire level.
//
// It combines three anti-detection measures:
//  1. uTLS with Firefox 120 ClientHello – defeats JA3/JA4 TLS fingerprinting.
//  2. HTTP/2 with Chrome-matching SETTINGS, HPACK, and header order.
//  3. Header ordering – Chrome sends headers in a fixed, predictable order;
//     Go's http.Header is a map with random iteration.  We encode HPACK
//     manually to guarantee Chrome-order on the wire.
type browserTransport struct {
	dialer *net.Dialer
}

// RoundTrip executes a single HTTP request/response over HTTP/2.
//
// For HTTPS targets it opens a fresh h2 connection (TCP + uTLS + HTTP/2
// handshake), sends the request with Chrome-ordered headers, and reads
// the response.  Plain HTTP requests (e.g. tests) fall back to Go's
// default transport unchanged.
func (t *browserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return http.DefaultTransport.RoundTrip(req)
	}

	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	host := net.JoinHostPort(req.URL.Hostname(), port)

	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	h2, err := dialH2(ctx, host, t.dialer, getFirefoxSpec())
	if err != nil {
		return nil, err
	}
	defer h2.Close()

	return h2.do(req, firefoxHeaderOrder)
}

// Redeem redeems a TrueWallet voucher for the given phone number.
// Supports both voucher codes and full gift.truemoney.com URLs.
func Redeem(voucher, phoneNumber string) (json.RawMessage, error) {
	code, err := VoucherCode(voucher)
	if err != nil {
		return nil, err
	}
	phoneNumber, err = MobileNumber(phoneNumber)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://gift.truemoney.com/campaign/vouchers/%s/redeem", code)
	body, err := json.Marshal(map[string]string{"mobile": phoneNumber})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	setBrowserHeaders(req, "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://gift.truemoney.com/campaign/card")

	return doJSON(req)
}

// Verify reads voucher details without redeeming it.
// Supports both voucher codes and full gift.truemoney.com URLs.
func Verify(voucher, phoneNumber string) (json.RawMessage, error) {
	code, err := VoucherCode(voucher)
	if err != nil {
		return nil, err
	}
	if phoneNumber != "" {
		phoneNumber, err = MobileNumber(phoneNumber)
		if err != nil {
			return nil, err
		}
	}
	endpoint := fmt.Sprintf("https://gift.truemoney.com/campaign/vouchers/%s/verify?mobile=%s", code, url.QueryEscape(phoneNumber))
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	setBrowserHeaders(req, "*/*")
	req.Header.Set("Referer", campaignPrefix+code)

	return doJSON(req)
}

func doJSON(req *http.Request) (json.RawMessage, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body := io.Reader(resp.Body)

	// TrueMoney / Cloudflare often gzip responses even when HTTP/2 clients don't
	// auto-decompress.  Handle the common encodings manually.
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		gr, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			return nil, fmt.Errorf("gzip reader: %w", gzErr)
		}
		defer gr.Close()
		body = gr
	case "deflate":
		body = flate.NewReader(resp.Body)
	case "br":
		body = brotli.NewReader(resp.Body)
	}

	data, err := io.ReadAll(io.LimitReader(body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// TrueMoney sometimes returns 200 with an empty body (e.g. voucher already redeemed).
	// Treat empty 2xx as valid.
	if len(data) == 0 {
		if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
			return json.RawMessage(`{}`), nil
		}
		return nil, fmt.Errorf("TrueMoney returned HTTP %d with an empty body", resp.StatusCode)
	}

	if !json.Valid(data) {
		// Log a preview so we can debug unexpected responses (Cloudflare challenges, HTML, etc.)
		preview := string(data)
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		return nil, fmt.Errorf("TrueMoney returned HTTP %d with a non-JSON response: %s", resp.StatusCode, preview)
	}

	return json.RawMessage(data), nil
}

type DebugExchange struct {
	Request  string `json:"request"`
	Response string `json:"response,omitempty"`
	Error    string `json:"error,omitempty"`
}

type DebugReport struct {
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
	Exchanges []DebugExchange `json:"exchanges"`
}

type traceTransport struct {
	base      http.RoundTripper
	mu        sync.Mutex
	exchanges []DebugExchange
}

func (t *traceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	exchange := DebugExchange{}
	requestDump, dumpErr := httputil.DumpRequestOut(req, true)
	if dumpErr != nil {
		exchange.Error = "dump request: " + dumpErr.Error()
	} else {
		exchange.Request = string(requestDump)
	}

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		if exchange.Error != "" {
			exchange.Error += "; "
		}
		exchange.Error += err.Error()
		t.append(exchange)
		return nil, err
	}

	responseDump, dumpErr := httputil.DumpResponse(resp, true)
	if dumpErr != nil {
		if exchange.Error != "" {
			exchange.Error += "; "
		}
		exchange.Error += "dump response: " + dumpErr.Error()
	} else {
		exchange.Response = string(responseDump)
	}
	t.append(exchange)
	return resp, nil
}

func (t *traceTransport) append(exchange DebugExchange) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.exchanges = append(t.exchanges, exchange)
}

func (t *traceTransport) snapshot() []DebugExchange {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]DebugExchange, len(t.exchanges))
	copy(result, t.exchanges)
	return result
}

// DebugRedeem runs a direct redeem request while recording the complete
// outbound HTTP exchange. Callers must protect this function.
func DebugRedeem(voucher, phoneNumber string) DebugReport {
	report := DebugReport{Exchanges: []DebugExchange{}}

	code, err := VoucherCode(voucher)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	phoneNumber, err = MobileNumber(phoneNumber)
	if err != nil {
		report.Error = err.Error()
		return report
	}

	tracer := &traceTransport{base: &browserTransport{
		dialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}}
	jar, _ := cookiejar.New(nil)
	debugClient := &http.Client{
		Jar:       jar,
		Transport: tracer,
		Timeout:   30 * time.Second,
	}
	defer debugClient.CloseIdleConnections()

	redeemEndpoint := fmt.Sprintf("https://gift.truemoney.com/campaign/vouchers/%s/redeem", code)
	body, err := json.Marshal(map[string]string{"mobile": phoneNumber})
	if err != nil {
		report.Error = err.Error()
		report.Exchanges = tracer.snapshot()
		return report
	}
	redeemReq, err := http.NewRequest(http.MethodPost, redeemEndpoint, bytes.NewReader(body))
	if err != nil {
		report.Error = err.Error()
		report.Exchanges = tracer.snapshot()
		return report
	}
	setBrowserHeaders(redeemReq, "application/json")
	redeemReq.Header.Set("Content-Type", "application/json")
	redeemReq.Header.Set("Referer", "https://gift.truemoney.com/campaign/card")

	redeemResp, err := debugClient.Do(redeemReq)
	if err != nil {
		report.Error = err.Error()
		report.Exchanges = tracer.snapshot()
		return report
	}
	redeemData, readErr := io.ReadAll(redeemResp.Body)
	redeemResp.Body.Close()
	if readErr != nil {
		report.Error = readErr.Error()
		report.Exchanges = tracer.snapshot()
		return report
	}
	if !json.Valid(redeemData) {
		report.Error = fmt.Sprintf("TrueMoney redeem returned HTTP %d with a non-JSON response", redeemResp.StatusCode)
		report.Exchanges = tracer.snapshot()
		return report
	}

	report.Result = json.RawMessage(redeemData)
	report.Exchanges = tracer.snapshot()
	return report
}

func VoucherCode(voucher string) (string, error) {
	voucher = strings.TrimSpace(voucher)
	if voucher == "" {
		return "", errors.New("voucher code is required")
	}

	if strings.Contains(voucher, "://") {
		parsed, err := url.Parse(voucher)
		if err != nil {
			return "", errors.New("invalid voucher URL")
		}
		if parsed.Scheme != "https" || !strings.EqualFold(parsed.Hostname(), "gift.truemoney.com") ||
			parsed.Path != "/campaign/" {
			return "", errors.New("invalid voucher URL")
		}
		voucher = parsed.Query().Get("v")
	}

	if len(voucher) > 128 {
		return "", errors.New("invalid voucher code")
	}

	if voucher == "" {
		return "", errors.New("voucher code is required")
	}

	for _, char := range voucher {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && char != '-' && char != '_' {
			return "", errors.New("invalid voucher code")
		}
	}

	return voucher, nil
}

func MobileNumber(phoneNumber string) (string, error) {
	phoneNumber = strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(phoneNumber))
	if len(phoneNumber) != 10 || phoneNumber[0] != '0' {
		return "", errors.New("mobile number must contain 10 digits and start with 0")
	}
	for _, char := range phoneNumber {
		if char < '0' || char > '9' {
			return "", errors.New("mobile number must contain 10 digits and start with 0")
		}
	}
	return phoneNumber, nil
}

func setBrowserHeaders(req *http.Request, accept string) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept", accept)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Priority", "u=4")
}
