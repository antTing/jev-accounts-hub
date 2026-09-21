package adminui

import _ "embed"

// IndexHTML 单页管理台。Admin token 只存在浏览器 localStorage。
//
//go:embed index.html
var IndexHTML string
