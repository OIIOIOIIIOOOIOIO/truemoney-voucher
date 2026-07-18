package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"tw/internal/twapi"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	publicDir := filepath.Join(".", "public")
	fileServer := http.FileServer(http.Dir(publicDir))

	mux := http.NewServeMux()
	mux.Handle("POST /api/{code}/{mobile}", redeemAccessLogMiddleware(http.HandlerFunc(handleRedeem)))
	mux.Handle("POST /api/{code}/{mobile}/debug", redeemAccessLogMiddleware(http.HandlerFunc(handleRedeemDebug)))
	mux.Handle("GET /api/{code}/verify", http.HandlerFunc(handleVerify))
	mux.Handle("POST /api/verify", http.HandlerFunc(handleVerifyBody))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSON(w, http.StatusNotFound, map[string]any{"code": 404, "message": "Not Found"})
			return
		}
		fileServer.ServeHTTP(w, r)
	}))

	addr := ":" + port
	log.Printf("Server is running on http://localhost:%s", port)
	if err := http.ListenAndServe(addr, corsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

func handleRedeem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	code := r.PathValue("code")
	mobile := r.PathValue("mobile")
	if code == "" || mobile == "" {
		writeJSON(w, http.StatusOK, map[string]any{"code": 400, "message": "Bad Request"})
		return
	}

	result, err := twapi.Redeem(code, mobile)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"code":    500,
			"message": "Internal Server Error",
			"error":   err.Error(),
		})
		return
	}

	w.Write(result)
}

func handleRedeemDebug(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !validDebugToken(r.Header.Get("X-Debug-Token")) {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 404, "message": "Not Found"})
		return
	}

	code := r.PathValue("code")
	mobile := r.PathValue("mobile")
	report := twapi.DebugRedeem(code, mobile)
	for index, exchange := range report.Exchanges {
		log.Printf(
			"event=truemoney_debug_exchange step=%d\n--- REQUEST ---\n%s\n--- RESPONSE ---\n%s\n--- ERROR ---\n%s",
			index+1,
			exchange.Request,
			exchange.Response,
			exchange.Error,
		)
	}
	if report.Error != "" {
		log.Printf("event=truemoney_debug_result error=%q", report.Error)
	}
	writeJSON(w, http.StatusOK, report)
}

func validDebugToken(provided string) bool {
	expected := os.Getenv("TW_DEBUG_TOKEN")
	if expected == "" || len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	code := r.PathValue("code")
	mobile := r.URL.Query().Get("mobile")
	if code == "" {
		writeJSON(w, http.StatusOK, map[string]any{"code": 400, "message": "Bad Request"})
		return
	}

	result, err := twapi.Verify(code, mobile)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"code":    500,
			"message": "Internal Server Error",
			"error":   err.Error(),
		})
		return
	}

	w.Write(result)
}

func handleVerifyBody(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var payload struct {
		Code   string `json:"code"`
		URL    string `json:"url"`
		Mobile string `json:"mobile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"code": 400, "message": "Bad Request"})
		return
	}

	voucher := payload.Code
	if voucher == "" {
		voucher = payload.URL
	}
	if voucher == "" {
		writeJSON(w, http.StatusOK, map[string]any{"code": 400, "message": "Bad Request"})
		return
	}

	result, err := twapi.Verify(voucher, payload.Mobile)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"code":    500,
			"message": "Internal Server Error",
			"error":   err.Error(),
		})
		return
	}

	w.Write(result)
}

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (w *responseRecorder) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseRecorder) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}

func redeemAccessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &responseRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		if recorder.status == 0 {
			recorder.status = http.StatusOK
		}
		log.Printf("event=redeem_request ip=%s method=%s status=%d duration=%s",
			remoteIP(r.RemoteAddr), r.Method, recorder.status, time.Since(started).Round(time.Millisecond))
	})
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Debug-Token")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
