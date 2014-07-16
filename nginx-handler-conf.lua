
local conf = {}

conf['cookie'] = ngx.var.cookie_lemonldap
conf['fqdn'] = ngx.var.host
conf['request'] = ngx.var.request_uri
conf['scheme'] = ngx.var.scheme
conf['server_port'] = ngx.var.server_port

conf['lemon_portal'] = "http://auth.example.com"
conf['lemon_conf'] = conf['lemon_portal'].."/index.pl/config"
conf['lemon_session'] = conf['lemon_portal'].."/index.pl/sessions"

conf['lemon_namespace'] = "urn:Lemonldap::NG::Common::CGI::SOAPService"
conf['lemon_session_method'] = "getAttributes"
conf['lemon_conf_method'] = "getConfig"

conf['lemonSharedConf'] = ngx.shared.lemonSharedConf
conf['lemonSharedConfExpires'] = 10 -- time in minute before expiration
conf['lemonSharedSession'] = ngx.shared.lemonSharedSession
conf['lemonSharedSessionExpires'] = 10 -- time in minute before expiration


return conf
