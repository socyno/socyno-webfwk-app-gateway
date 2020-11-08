package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"net/url"
	"strings"

	"net/http"
	"regexp"
	"sort"

	"github.com/gin-gonic/gin"
)

type AuthorityScope int8
type AuthorityParser func(path string, queries map[string][]string, headers map[string][]string, body string) (int64, error)

var URL_BACKENDS map[string][]string
var URL_PATHREGEXPS []regexp.Regexp
var URL_DEFINITIONS map[string]AuthorityDefinition

const (
	AuthorityScope_GUEST     AuthorityScope = 1 // 访客授权，即任何人均可访问
	AuthorityScope_SYSTEM    AuthorityScope = 2 // 系统授权，只要系统中配置即可
	AuthorityScope_SUBSYSTEM AuthorityScope = 4 // 根据不同业务进行授权，因此需要在校验授权时，通过定义的授权标的解析器解析出涉及的业务系统信息
)

type AuthorityDefinition struct {
	key          string          // 授权具体操作
	scope        AuthorityScope  // 授权的范围
	parser       AuthorityParser // 授权标的解析器，仅当 AuthorityScope_SUBSYSTEM 时需要定义
	bodyRequired bool            // 配合授权标的解析器使用，表示是否需要读取请求体的内容，以便在解析时使用
}

var (
	LogInfo  *log.Logger
	LogWarn  *log.Logger
	LogError *log.Logger
)

func init() {
	LogInfo = log.New(os.Stdout, "[INFO]", log.Ldate|log.Ltime|log.Lshortfile)
	LogWarn = log.New(os.Stderr, "[WARN]", log.Ldate|log.Ltime|log.Lshortfile)
	LogError = log.New(os.Stderr, "[ERROR]", log.Ldate|log.Ltime|log.Lshortfile)
}

func registerGuestUrl(pathRegexp string) {
	initUrlPathDefinitions()
	URL_DEFINITIONS[pathRegexp] = AuthorityDefinition{
		key:          "",
		scope:        AuthorityScope_GUEST,
		parser:       nil,
		bodyRequired: false,
	}
}

func registerSystemUrl(pathRegexp string, authKey string) {
	initUrlPathDefinitions()
	URL_DEFINITIONS[pathRegexp] = AuthorityDefinition{
		key:          authKey,
		scope:        AuthorityScope_SYSTEM,
		parser:       nil,
		bodyRequired: false,
	}
}

func registerSubSystemUrl(pathRegexp string, authKey string, parser AuthorityParser, bodyRequired bool) {
	initUrlPathDefinitions()
	URL_DEFINITIONS[pathRegexp] = AuthorityDefinition{
		key:          authKey,
		scope:        AuthorityScope_SUBSYSTEM,
		parser:       parser,
		bodyRequired: bodyRequired,
	}
}

func registerBackend(backendBaseUrl string, pathRegexp []string) {
	if URL_BACKENDS == nil {
		URL_BACKENDS = make(map[string][]string)
	}
	URL_BACKENDS[backendBaseUrl] = pathRegexp
}

func initUrlPathDefinitions() {
	if URL_DEFINITIONS == nil {
		URL_DEFINITIONS = make(map[string]AuthorityDefinition)
	}
}

func initUrlPathRegexps() {
	if URL_PATHREGEXPS != nil {
		return
	}
	i := 0
	keys := make([]string, len(URL_DEFINITIONS))
	for k := range URL_DEFINITIONS {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	URL_PATHREGEXPS = make([]regexp.Regexp, len(keys))
	for p := 0; p < len(keys); p++ {
		sexpr := keys[p]
		rexpr, err := regexp.Compile(sexpr)
		if err != nil {
			panic(fmt.Sprintf("注册的URL路径正则表达式解析失败:%v -- %v", sexpr, err.Error()))
		}
		URL_PATHREGEXPS[p] = *rexpr
	}
}

// 根据请求地址，匹配最合适的授权配置定义
func findAuthrityDefintion(path string) (AuthorityDefinition, bool) {
	initUrlPathRegexps()
	for r := len(URL_PATHREGEXPS) - 1; r >= 0; r-- {
		rexpr := URL_PATHREGEXPS[r]
		if rexpr.MatchString(path) {
			auth, ok := URL_DEFINITIONS[rexpr.String()]
			return auth, ok
		}
	}
	return AuthorityDefinition{}, false
}

// 校验当前用户是否对请求具有授权
// 首先，必须确保请求的地址能匹配到预配置的授权定义
// 其次，验证当前用户在配置的授权范围内用户配置的授权操作
func checkAuthorityDefintion(c *gin.Context) bool {
	urlPath := c.Request.URL.Path
	LogInfo.Printf("Checking access : %v\n", urlPath)
	auth, has := findAuthrityDefintion(urlPath)
	if !has {
		LogError.Printf("-- No authority definition for request path %v\n", urlPath)
		return false
	}
	if auth.scope != AuthorityScope_GUEST && auth.scope != AuthorityScope_SYSTEM &&
		auth.scope != AuthorityScope_SUBSYSTEM {
		LogError.Printf("-- Unknown authority scope value form path %v\n", urlPath)
		return false
	}
	targetScopeId := int64(-1)
	if auth.scope == AuthorityScope_SUBSYSTEM {
		if auth.parser == nil {
			LogError.Println("-- Missing subsytem parser defined for authority checking...")
			return false
		}
		path := c.Request.URL.Path
		queries := c.Request.URL.Query()
		headers := c.Request.Header
		bodyLen := 0
		bodyData := make([]byte, 0)
		if auth.bodyRequired {
			bodyLimit := 10
			bodyData = make([]byte, bodyLimit)
			bodyLen, err := c.Request.Body.Read(bodyData)
			if err != nil && err != io.EOF {
				LogError.Printf("-- Error occurs when reading request body stream: %v\n", err.Error())
				return false
			}
			if bodyLen >= bodyLimit {
				bodyNextData := make([]byte, 1)
				bodyNextLen, err := c.Request.Body.Read(bodyNextData)
				if !(err == io.EOF && bodyNextLen <= 0) {
					LogError.Println("-- Body too large, can not be used for authority checking...")
					return false
				}
			}
			c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyData[:bodyLen]))
		}
		targetScopeId, err := auth.parser(path, queries, headers, string(bodyData[:bodyLen]))
		if err != nil {
			LogError.Printf("-- Error occurs when checking authority: %v\n", err.Error())
			return false
		}
		if targetScopeId <= 0 {
			LogError.Printf("-- Parsed target scope identifier is invalid: %v\n", targetScopeId)
			return false
		}
	}
	// check authority for parsed target scope id
	return checkAuthorityAccess(auth.key, auth.scope, targetScopeId)
}

// 校验当前用户在指定的授权范围（authScope/targetScopeId）内，是否拥有给定的授权操作（authKey）
// 根据授权配置的定义：
//       针对访客（GUEST）表示可直接访问，无需授权认证；
//       系统（SYSTEM）/业务（SUBSYSTEM）授权必须确保当前用户所在的角色中有包含指定授权操（authKey）作的即可；
// TODO: 此处还需要补充实际的校验逻辑
func checkAuthorityAccess(authKey string, authScope AuthorityScope, targetScopeId int64) bool {
	if authScope == AuthorityScope_GUEST {
		return true
	}
	return true
}

func main() {
	/**
	 * 注册允许访问的Url地址及其授权解析器
	 */
	// TODO: GUST 和
	registerGuestUrl("^/guest/.+")
	registerSubSystemUrl("^/subsystem/\\d+(/.*)*", "", func(path string, queries map[string][]string, headers map[string][]string, body string) (int64, error) {
		return 1, nil
	}, false)
	registerSubSystemUrl("^/subsystem/\\d+/body/.*", "", func(path string, queries map[string][]string, headers map[string][]string, body string) (int64, error) {
		return 1, nil
	}, true)

	/**
	 * 注册转发至后端服务的映射关系
	 */
	// TODO: 将后端转发的映射配置转移至数据库与的存储，并定时加载即可
	registerBackend("http://socyno.org/backend/", []string{"/backend/"})

	/**
	 * 解析注册的URL授权表达式清单
	 */
	initUrlPathRegexps()
	router := gin.Default()
	router.Any("/*path", func(c *gin.Context) {
		// 匹配请求地址并验证其授权
		if !checkAuthorityDefintion(c) {
			c.JSON(http.StatusForbidden, gin.H{
				"message": "Access Denied",
				"status":  403,
			})
			return
		}
		// 请求原样转发至后端服务
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}}
		httpBackendUrl := fmt.Sprintf(
			"https://baidu.com/s?wd=%v,%v",
			url.QueryEscape(c.Request.URL.Path),
			c.Request.URL.RawQuery,
		)
		// log.Printf("backend url : %v", httpBackendUrl)
		httpBackendReq, err := http.NewRequest(
			c.Request.Method,
			httpBackendUrl,
			c.Request.Body,
		)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"message": err.Error(),
				"status":  500,
			})
			return
		}
		httpBackendReq.Header = c.Request.Header
		httpBackendRes, err := httpClient.Do(httpBackendReq)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"message": err.Error(),
				"status":  500,
			})
			return
		}
		// 响应原样转投给调用端
		for name, values := range httpBackendRes.Header {
			if strings.Compare("transfer-encoding", strings.ToLower(name)) == 0 {
				continue
			}
			for i := 0; i < len(values); i++ {
				c.Header(name, values[i])
			}
		}
		io.Copy(c.Writer, httpBackendRes.Body)
	})
	// 启动HTTP服务，默认在0.0.0.0:8080启动服务
	router.Run()
}
