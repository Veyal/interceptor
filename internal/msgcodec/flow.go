package msgcodec

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"go.starlark.net/starlark"
)

func flowValue(f Flow) starlark.Value { return &flowVal{f: f} }

type flowVal struct{ f Flow }

func (v *flowVal) String() string {
	return fmt.Sprintf("flow(%s %s%s)", v.f.Method, v.f.Host, v.f.Path)
}
func (v *flowVal) Type() string          { return "flow" }
func (v *flowVal) Freeze()               {}
func (v *flowVal) Truth() starlark.Bool  { return starlark.True }
func (v *flowVal) Hash() (uint32, error) { return 0, fmt.Errorf("flow is unhashable") }

func (v *flowVal) AttrNames() []string {
	return []string{
		"method", "scheme", "host", "port", "path", "status", "mime",
		"req_body", "res_body", "req_headers", "res_headers",
		"req_header", "res_header", "req_header_all", "res_header_all", "query_param",
	}
}

func (v *flowVal) Attr(name string) (starlark.Value, error) {
	switch name {
	case "method":
		return starlark.String(v.f.Method), nil
	case "scheme":
		return starlark.String(v.f.Scheme), nil
	case "host":
		return starlark.String(v.f.Host), nil
	case "port":
		return starlark.MakeInt(v.f.Port), nil
	case "path":
		return starlark.String(v.f.Path), nil
	case "status":
		return starlark.MakeInt(v.f.Status), nil
	case "mime":
		return starlark.String(v.f.Mime), nil
	case "req_body":
		return starlark.String(v.f.ReqBody), nil
	case "res_body":
		return starlark.String(v.f.ResBody), nil
	case "req_headers":
		return headersDict(v.f.ReqHeaders), nil
	case "res_headers":
		return headersDict(v.f.ResHeaders), nil
	case "req_header":
		return headerGetter("req_header", v.f.ReqHeaders), nil
	case "res_header":
		return headerGetter("res_header", v.f.ResHeaders), nil
	case "req_header_all":
		return headerAllGetter("req_header_all", v.f.ReqHeaders), nil
	case "res_header_all":
		return headerAllGetter("res_header_all", v.f.ResHeaders), nil
	case "query_param":
		return queryParamGetter(v.f.Path), nil
	}
	return nil, nil
}

func headersDict(h map[string][]string) starlark.Value {
	d := starlark.NewDict(len(h))
	for k, vals := range h {
		first := ""
		if len(vals) > 0 {
			first = vals[0]
		}
		_ = d.SetKey(starlark.String(http.CanonicalHeaderKey(k)), starlark.String(first))
	}
	d.Freeze()
	return d
}

func headerGetter(name string, h map[string][]string) *starlark.Builtin {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var key string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &key); err != nil {
			return nil, err
		}
		for k, vals := range h {
			if strings.EqualFold(k, key) && len(vals) > 0 {
				return starlark.String(vals[0]), nil
			}
		}
		return starlark.String(""), nil
	})
}

func headerAllGetter(name string, h map[string][]string) *starlark.Builtin {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var key string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &key); err != nil {
			return nil, err
		}
		for k, vals := range h {
			if strings.EqualFold(k, key) {
				out := make([]starlark.Value, len(vals))
				for i, v := range vals {
					out[i] = starlark.String(v)
				}
				return starlark.NewList(out), nil
			}
		}
		return starlark.NewList(nil), nil
	})
}

func queryParamGetter(path string) *starlark.Builtin {
	return starlark.NewBuiltin("query_param", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name); err != nil {
			return nil, err
		}
		if i := strings.IndexByte(path, '?'); i >= 0 {
			if vals, err := url.ParseQuery(path[i+1:]); err == nil {
				return starlark.String(vals.Get(name)), nil
			}
		}
		return starlark.String(""), nil
	})
}

var _ starlark.HasAttrs = (*flowVal)(nil)
