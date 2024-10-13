package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/syumai/workers"
)

func main() {
	workers.Serve(registerRouter())
}

//go:embed web/*
var StaticFiles embed.FS

func registerRouter() *http.ServeMux {
	mux := http.NewServeMux()
	tmpl := template.Must(template.ParseFS(StaticFiles, "web/index.html"))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		err := tmpl.Execute(w, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	web, _ := fs.Sub(StaticFiles, "web")
	mux.Handle("/avatar.png", http.FileServer(http.FS(web)))
	mux.Handle("/icon.png", http.FileServer(http.FS(web)))

	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "pong"}`))
	})

	mux.HandleFunc("/v1/chat/completions", Authorization(duckduckgo))
	return mux
}

type ChatCompletionChunk struct {
	ID      string    `json:"id"`
	Object  string    `json:"object"`
	Created int64     `json:"created"`
	Model   string    `json:"model"`
	Choices []Choices `json:"choices"`
}

func (chunk *ChatCompletionChunk) String() string {
	resp, _ := json.Marshal(chunk)
	return string(resp)
}

type Choices struct {
	Delta        Delta       `json:"delta"`
	Index        int         `json:"index"`
	FinishReason interface{} `json:"finish_reason"`
}

type Delta struct {
	Content string `json:"content,omitempty"`
	Role    string `json:"role,omitempty"`
}

func NewChatCompletionChunk(text string) ChatCompletionChunk {
	return ChatCompletionChunk{
		ID:      "chatcmpl-QXlha2FBbmROaXhpZUFyZUF3ZXNvbWUK",
		Object:  "chat.completion.chunk",
		Created: 0,
		Model:   "gpt-4o-mini",
		Choices: []Choices{
			{
				Index: 0,
				Delta: Delta{
					Content: text,
				},
				FinishReason: nil,
			},
		},
	}
}

func NewChatCompletionChunkWithModel(text string, model string) ChatCompletionChunk {
	return ChatCompletionChunk{
		ID:      "chatcmpl-QXlha2FBbmROaXhpZUFyZUF3ZXNvbWUK",
		Object:  "chat.completion.chunk",
		Created: 0,
		Model:   model,
		Choices: []Choices{
			{
				Index: 0,
				Delta: Delta{
					Content: text,
				},
				FinishReason: nil,
			},
		},
	}
}

func StopChunkWithModel(reason string, model string) ChatCompletionChunk {
	return ChatCompletionChunk{
		ID:      "chatcmpl-QXlha2FBbmROaXhpZUFyZUF3ZXNvbWUK",
		Object:  "chat.completion.chunk",
		Created: 0,
		Model:   model,
		Choices: []Choices{
			{
				Index:        0,
				FinishReason: reason,
			},
		},
	}
}

func StopChunk(reason string) ChatCompletionChunk {
	return ChatCompletionChunk{
		ID:      "chatcmpl-QXlha2FBbmROaXhpZUFyZUF3ZXNvbWUK",
		Object:  "chat.completion.chunk",
		Created: 0,
		Model:   "gpt-4o-mini",
		Choices: []Choices{
			{
				Index:        0,
				FinishReason: reason,
			},
		},
	}
}

type ChatCompletion struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Usage   usage    `json:"usage"`
	Choices []Choice `json:"choices"`
}
type Msg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type Choice struct {
	Index        int         `json:"index"`
	Message      Msg         `json:"message"`
	FinishReason interface{} `json:"finish_reason"`
}
type usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

func NewChatCompletionWithModel(text string, model string) ChatCompletion {
	return ChatCompletion{
		ID:      "chatcmpl-QXlha2FBbmROaXhpZUFyZUF3ZXNvbWUK",
		Object:  "chat.completion",
		Created: int64(0),
		Model:   model,
		Usage: usage{
			PromptTokens:     0,
			CompletionTokens: 0,
			TotalTokens:      0,
		},
		Choices: []Choice{
			{
				Message: Msg{
					Content: text,
					Role:    "assistant",
				},
				Index: 0,
			},
		},
	}
}

func NewChatCompletion(full_test string, input_tokens, output_tokens int) ChatCompletion {
	return ChatCompletion{
		ID:      "chatcmpl-QXlha2FBbmROaXhpZUFyZUF3ZXNvbWUK",
		Object:  "chat.completion",
		Created: int64(0),
		Model:   "gpt-4o-mini",
		Usage: usage{
			PromptTokens:     input_tokens,
			CompletionTokens: output_tokens,
			TotalTokens:      input_tokens + output_tokens,
		},
		Choices: []Choice{
			{
				Message: Msg{
					Content: full_test,
					Role:    "assistant",
				},
				Index: 0,
			},
		},
	}
}

type APIRequest struct {
	Messages  []api_message `json:"messages"`
	Stream    bool          `json:"stream"`
	Model     string        `json:"model"`
	PluginIDs []string      `json:"plugin_ids"`
}

type api_message struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

type OpenAISessionToken struct {
	SessionToken string `json:"session_token"`
}

type OpenAIRefreshToken struct {
	RefreshToken string `json:"refresh_token"`
}

func Authorization(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		customerKey := os.Getenv("Authorization")
		if customerKey != "" {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
				return
			}
			tokenParts := strings.Split(strings.Replace(authHeader, "Bearer ", "", 1), " ")
			customAccessToken := tokenParts[0]
			if customerKey != customAccessToken {
				http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
				return
			}
			if len(tokenParts) > 1 {
				openaiAccessToken := tokenParts[1]
				r.Header.Set("Authorization", "Bearer "+openaiAccessToken)
			}
		}
		next(w, r)
	}
}

type ChatClient struct {
	Client    *http.Client
	ReqBefore handler
}

type handler func(r *http.Request) error

func NewStdClient() *ChatClient {
	client := &http.Client{
		Timeout: 600 * time.Second,
	}

	stdClient := &ChatClient{Client: client}
	return stdClient
}

func (t *ChatClient) handleHeaders(req *http.Request, headers map[string]string) {
	if headers == nil {
		return
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

func (t *ChatClient) handleCookies(req *http.Request, cookies []*http.Cookie) {
	if cookies == nil {
		return
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
}

func (t *ChatClient) Request(method HttpMethod, url string, headers AuroraHeaders, cookies []*http.Cookie, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(string(method), url, body)
	if err != nil {
		return nil, err
	}
	t.handleHeaders(req, headers)
	t.handleCookies(req, cookies)
	if t.ReqBefore != nil {
		if err := t.ReqBefore(req); err != nil {
			return nil, err
		}
	}
	return t.Client.Do(req)
}

func ConvertAPIRequest(api_request APIRequest) ApiRequest {
	inputModel := api_request.Model
	duckgo_request := NewApiRequest(inputModel)
	realModel := inputModel

	// 如果模型未进行映射，则直接使用输入模型，方便后续用户使用 duckduckgo 添加的新模型。
	modelLower := strings.ToLower(inputModel)
	switch {
	case strings.HasPrefix(modelLower, "gpt-3.5"):
		realModel = "gpt-4o-mini"
	case strings.HasPrefix(modelLower, "claude-3-haiku"):
		realModel = "claude-3-haiku-20240307"
	case strings.HasPrefix(modelLower, "llama-3.1-70b"):
		realModel = "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo"
	case strings.HasPrefix(modelLower, "mixtral-8x7b"):
		realModel = "mistralai/Mixtral-8x7B-Instruct-v0.1"
	}

	duckgo_request.Model = realModel
	content := buildContent(&api_request)
	duckgo_request.AddMessage("user", content)

	return duckgo_request
}

func buildContent(api_request *APIRequest) string {
	var content strings.Builder
	for _, apiMessage := range api_request.Messages {
		role := apiMessage.Role
		if role == "user" || role == "system" || role == "assistant" {
			if role == "system" {
				role = "user"
			}
			contentStr := ""
			// 判断 apiMessage.Content 是否为数组
			if arrayContent, ok := apiMessage.Content.([]interface{}); ok {
				// 如果是数组，遍历数组，查找第一个 type 为 "text" 的元素
				for _, element := range arrayContent {
					if elementMap, ok := element.(map[string]interface{}); ok {
						if elementMap["type"] == "text" {
							contentStr = elementMap["text"].(string)
							break
						}
					}
				}
			} else {
				contentStr, _ = apiMessage.Content.(string)
			}
			content.WriteString(role + ":" + contentStr + ";\r\n")
		}
	}
	return content.String()
}

type ApiResponse struct {
	Message string `json:"message"`
	Created int    `json:"created"`
	Id      string `json:"id"`
	Action  string `json:"action"`
	Model   string `json:"model"`
}

var (
	Token *XqdgToken
	UA    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

type XqdgToken struct {
	Token    string     `json:"token"`
	M        sync.Mutex `json:"-"`
	ExpireAt time.Time  `json:"expire"`
}

type ApiRequest struct {
	Model    string     `json:"model"`
	Messages []messages `json:"messages"`
}
type messages struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func (a *ApiRequest) AddMessage(role string, content string) {
	a.Messages = append(a.Messages, messages{
		Role:    role,
		Content: content,
	})
}

func NewApiRequest(model string) ApiRequest {
	return ApiRequest{
		Model: model,
	}
}

func InitXVQD(client AuroraHttpClient) (string, error) {
	if Token == nil {
		Token = &XqdgToken{
			Token: "",
			M:     sync.Mutex{},
		}
	}
	Token.M.Lock()
	defer Token.M.Unlock()
	if Token.Token == "" || Token.ExpireAt.Before(time.Now()) {
		status, err := postStatus(client)
		if err != nil {
			return "", err
		}
		defer status.Body.Close()
		token := status.Header.Get("x-vqd-4")
		if token == "" {
			return "", errors.New("no x-vqd-4 token")
		}
		Token.Token = token
		Token.ExpireAt = time.Now().Add(time.Minute * 3)
	}

	return Token.Token, nil
}

func postStatus(client AuroraHttpClient) (*http.Response, error) {
	header := createHeader()
	header.Set("accept", "*/*")
	header.Set("x-vqd-accept", "1")
	response, err := client.Request(GET, "https://duckduckgo.com/duckchat/v1/status", header, nil, nil)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func POSTconversation(client AuroraHttpClient, request ApiRequest, token string) (*http.Response, error) {
	body_json, err := json.Marshal(request)
	if err != nil {
		return &http.Response{}, err
	}
	header := createHeader()
	header.Set("accept", "text/event-stream")
	header.Set("x-vqd-4", token)
	response, err := client.Request(POST, "https://duckduckgo.com/duckchat/v1/chat", header, nil, bytes.NewBuffer(body_json))
	if err != nil {
		return nil, err
	}
	return response, nil
}

func Handle_request_error(w http.ResponseWriter, response *http.Response) bool {
	if response.StatusCode != http.StatusOK {
		var errorResponse map[string]interface{}
		err := json.NewDecoder(response.Body).Decode(&errorResponse)
		if err != nil {
			body, _ := io.ReadAll(response.Body)
			http.Error(w, string(body), response.StatusCode)
			return true
		}
		http.Error(w, errorResponse["detail"].(string), response.StatusCode)
		return true
	}
	return false
}

func createHeader() AuroraHeaders {
	header := make(AuroraHeaders)
	header.Set("accept-language", "zh-CN,zh;q=0.9")
	header.Set("content-type", "application/json")
	header.Set("origin", "https://duckduckgo.com")
	header.Set("referer", "https://duckduckgo.com/")
	header.Set("sec-ch-ua", `"Chromium";v="120", "Google Chrome";v="120", "Not-A.Brand";v="99"`)
	header.Set("sec-ch-ua-mobile", "?0")
	header.Set("sec-ch-ua-platform", `"Windows"`)
	header.Set("sec-fetch-dest", "empty")
	header.Set("sec-fetch-mode", "cors")
	header.Set("sec-fetch-site", "same-origin")
	header.Set("user-agent", UA)
	return header
}

func Handler(w http.ResponseWriter, response *http.Response, oldRequest ApiRequest, stream bool) string {
	reader := bufio.NewReader(response.Body)
	if stream {
		w.Header().Set("Content-Type", "text/event-stream")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}

	var previousText strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return ""
		}
		if len(line) < 6 {
			continue
		}
		line = line[6:]
		if !strings.HasPrefix(line, "[DONE]") {
			var originalResponse ApiResponse
			err = json.Unmarshal([]byte(line), &originalResponse)
			if err != nil {
				continue
			}
			if originalResponse.Action != "success" {
				http.Error(w, "Error", http.StatusInternalServerError)
				return ""
			}
			responseString := ""
			if originalResponse.Message != "" {
				previousText.WriteString(originalResponse.Message)
				translatedResponse := NewChatCompletionChunkWithModel(originalResponse.Message, originalResponse.Model)
				responseString = "data: " + translatedResponse.String() + "\n\n"
			}

			if responseString == "" {
				continue
			}

			if stream {
				_, err = w.Write([]byte(responseString))
				if err != nil {
					return ""
				}
				w.(http.Flusher).Flush()
			}
		} else {
			if stream {
				finalLine := StopChunkWithModel("stop", oldRequest.Model)
				w.Write([]byte("data: " + finalLine.String() + "\n\n"))
			}
		}
	}
	return previousText.String()
}

type AuroraHttpClient interface {
	Request(method HttpMethod, url string, headers AuroraHeaders, cookies []*http.Cookie, body io.Reader) (*http.Response, error)
}

type HttpMethod string

const (
	GET     HttpMethod = "GET"
	POST    HttpMethod = "POST"
	PUT     HttpMethod = "PUT"
	HEAD    HttpMethod = "HEAD"
	DELETE  HttpMethod = "DELETE"
	OPTIONS HttpMethod = "OPTIONS"
)

type AuroraHeaders map[string]string

func (a AuroraHeaders) Set(key, value string) {
	a[key] = value
}

func duckduckgo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var originalRequest APIRequest
	err := json.NewDecoder(r.Body).Decode(&originalRequest)
	if err != nil {
		http.Error(w, `{"error": {"message": "Request must be proper JSON", "type": "invalid_request_error", "param": null, "code": "`+err.Error()+`"}}`, http.StatusBadRequest)
		return
	}
	client := NewStdClient()
	token, err := InitXVQD(client)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	translatedRequest := ConvertAPIRequest(originalRequest)
	response, err := POSTconversation(client, translatedRequest, token)
	if err != nil {
		http.Error(w, `{"error": "request conversion error"}`, http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()

	if Handle_request_error(w, response) {
		return
	}
	var responsePart string = Handler(w, response, translatedRequest, originalRequest.Stream)
	if w.Header().Get("Content-Type") != "" {
		return
	}

	if !originalRequest.Stream {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(NewChatCompletionWithModel(responsePart, translatedRequest.Model))
	} else {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: [DONE]\n\n"))
	}
}
