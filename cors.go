package cors

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	macaron "gopkg.in/macaron.v1"
)

const _VERSION = "0.1.0"

func Version() string {
	return _VERSION
}

// Options represents a struct for specifying configuration options for the CORS middleware.
type Options struct {
	Section        string
	Scheme         string
	AllowDomain    string
	AllowSubdomain bool
}

func prepareOptions(options []Options) Options {
	var opt Options
	if len(options) > 0 {
		opt = options[0]
	}

	if len(opt.Section) == 0 {
		opt.Section = "cors"
	}
	sec := macaron.Config().Section(opt.Section)

	if len(opt.Scheme) == 0 {
		opt.Scheme = sec.Key("SCHEME").MustString("http")
	}
	if len(opt.AllowDomain) == 0 {
		opt.AllowDomain = sec.Key("ALLOW_DOMAIN").MustString("*")
	}
	if !opt.AllowSubdomain {
		opt.AllowSubdomain = sec.Key("ALLOW_SUBDOMAIN").MustBool(false)
	}

	return opt
}

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
// https://fetch.spec.whatwg.org/#cors-protocol-and-credentials
// For requests without credentials, the server may specify "*" as a wildcard, thereby allowing any origin to access the resource.
func CORS(options ...Options) macaron.Handler {
	opt := prepareOptions(options)
	return func(ctx *macaron.Context, log *log.Logger) {
		reqOptions := ctx.Req.Method == http.MethodOptions

		headers := map[string]string{
			"access-control-allow-methods": "POST,GET,OPTIONS,PUT,PATCH,DELETE",
			"access-control-allow-headers": ctx.Req.Header.Get("access-control-request-headers"),
		}
		if reqOptions {
			// cache options response for 24h
			// ref: https://www.fastly.com/blog/caching-cors
			headers["cache-control"] = "max-age=86400"
		}
		if opt.AllowDomain == "*" {
			headers["access-control-allow-origin"] = "*"
		} else if opt.AllowDomain != "" {
			origin := ctx.Req.Header.Get("Origin")
			if reqOptions && origin == "" {
				respErrorf(ctx, log, http.StatusBadRequest, "missing origin header in CORS request")
				return
			}

			u, err := url.Parse(origin)
			if err != nil {
				respErrorf(ctx, log, http.StatusBadRequest, "Failed to parse CORS origin header. Reason: %v", err)
				return
			}

			ok := u.Hostname() == opt.AllowDomain ||
				(opt.AllowSubdomain && strings.HasSuffix(u.Hostname(), "."+opt.AllowDomain))
			if ok {
				u.Scheme = opt.Scheme
				headers["access-control-allow-origin"] = u.String()
				headers["access-control-allow-credentials"] = "true"
				headers["vary"] = "Origin"
			}
			if reqOptions && !ok {
				respErrorf(ctx, log, http.StatusBadRequest, "CORS request from prohibited domain %v", origin)
				return
			}
		}
		ctx.Resp.Before(func(w macaron.ResponseWriter) {
			for k, v := range headers {
				w.Header().Set(k, v)
			}
		})
		if reqOptions {
			ctx.Status(200) // return response
		}
	}
}

func respErrorf(ctx *macaron.Context, log *log.Logger, statusCode int, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Println(msg)
	ctx.WriteHeader(statusCode)
	_, err := ctx.Write([]byte(msg))
	if err != nil {
		panic(err)
	}
	return
}
