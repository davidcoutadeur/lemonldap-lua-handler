-- LUA SSO handler module for LemonLDAP::NG

-- Some variable declarations.
local handlerConf = require('nginx-handler-conf')

-------------------
-- base64 functions
-------------------


-- encoding
function enc(data)
    local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    return ((data:gsub('.', function(x) 
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end


--------------------------
-- parse session functions
--------------------------

function get_soap_session (cookie)
  local client = require "soap.client"
  client.https = require"ssl.https"
  local result = {} -- result returned

  local ns, meth, ent = client.call {
	url = handlerConf['lemon_session'],
	namespace = handlerConf['lemon_namespace'],
	soapaction = handlerConf['lemon_namespace'].."#"..handlerConf['lemon_session_method'],
	method = handlerConf['lemon_session_method'],
	entries = {
			{
			 tag = "c-gensym3",
			 attr = { "xsi:type", ["xsi:type"] = "xsd:string", },
			 cookie,
			},
	}
  }
  for i, elem in ipairs (ent[1]) do
    if elem.tag == "error" then -- do not include return code in the data result
      if elem[1] ~= "0" then -- there was an error in the session retrieval
        -- here, more can be done to identify the problem (session id not present in soap database ?)
        ngx.log(ngx.INFO,"Soap session unavailable")
	return nil
      end
    else
      for j, res in ipairs (elem) do
        result[res.tag] = res[1]
      end
    end
  end
  ngx.log(ngx.INFO,"Soap session loaded")
  return result
end


--------------------------------
-- parse configuration functions
--------------------------------

function parse_locationRules (res)
  local rules = {}
  local nb = 1
  for i, elem in ipairs (res) do
    if elem.tag ~= "item" then
      if res.tag == handlerConf['fqdn'] then
        rules[nb] = { elem.tag, elem[1] }
        nb = nb + 1
      end
    else
      for k, val in ipairs (elem) do
        if res.tag == handlerConf['fqdn'] then
          if val.tag == "key" then
            rules[nb] = { elem[k][1], elem[(k+1)][1] }
            nb = nb + 1
          end
        end
      end
    end
  end
  return rules
end

function parse_exportedHeaders (res)
  local headers = {}
  local found = false
  for i, elem in ipairs (res) do
    if res.tag == handlerConf['fqdn'] then
      headers[elem.tag] = elem[1]
      found=true
    end
  end
  if found == true then
    return headers
  else
    return nil
  end
end

function parse_vhostOptions (res)
  local options = {}
  local found = false
  for i, elem in ipairs (res) do
    if res.tag == handlerConf['fqdn'] then
      options[elem.tag] = elem[1]
      found = true
    end
  end
  if found == true then
    return options
  else
    return nil
  end
end


function get_soap_configuration ()
  local conf = {}
  local client = require "soap.client"
  local res = nil
  client.https = require"ssl.https"

  local ns, meth, ent = client.call {
	url = handlerConf['lemon_conf'], 
	namespace = handlerConf['lemon_namespace'],
	soapaction = handlerConf['lemon_namespace'].."#"..handlerConf['lemon_conf_method'],
	method = handlerConf['lemon_conf_method'],
	entries = {
	}
  }
  for i, elem in ipairs (ent[1]) do
    for j, res in ipairs (elem) do
      if elem.tag == "exportedHeaders" then
        res = parse_exportedHeaders(res)
        if res ~= nil then -- if parsing the current vhost
          conf["exportedHeaders"] = res
        end
      elseif  elem.tag == "locationRules" then
        res = parse_locationRules(res)
        if #res ~= 0 then -- if parsing the current vhost
          conf["locationRules"] = res
        end
      elseif  elem.tag == "vhostOptions" then
        res = parse_vhostOptions(res)
        if res ~= nil then -- if parsing the current vhost
          conf["vhostOptions"] = res
        end
      end
    end
  end
  ngx.log(ngx.INFO,"Soap configuration loaded")
  return conf
end



-----------------
-- access control
-----------------

function compute_rule(conf, session, rule)
  local finalrule = rule -- final rule will be evaluated with variable substitution
  local access = 403 -- by default, access is *not* granted

  if string.lower(finalrule) == "accept" then
    if session ~= nil then
      ngx.log(ngx.INFO,"rule \"accept\" is applied")
      set_headers (conf, session)
      access = 200
    else
      ngx.log(ngx.INFO,"rule \"accept\" applied, but user not found")
      access = 302 -- no lemonldap session, redirecting to portal
    end

  elseif string.lower(finalrule) == "deny" then
    ngx.log(ngx.INFO,"rule \"deny\" is applied")
    access = 403

  elseif string.lower(finalrule) == "skip" then
    ngx.log(ngx.INFO,"rule \"skip\" is applied")
    set_headers (conf, nil) -- force not to export headers
    access = 200

  elseif string.lower(finalrule) == "unprotect" then
    ngx.log(ngx.INFO,"rule \"unprotect\" is applied")
    set_headers (conf, session)
    access = 200

  else -- consider finalrule as perl expression
    -- converting basic operations
    finalrule = string.gsub(finalrule, ' eq ', ' == ')
    finalrule = string.gsub(finalrule, ' ne ', ' ~= ')
    finalrule = string.gsub(finalrule, ' gt ', ' > ')
    finalrule = string.gsub(finalrule, ' lt ', ' < ')
    finalrule = string.gsub(finalrule, ' ge ', ' >= ')
    finalrule = string.gsub(finalrule, ' le ', ' <= ')
    for key,value in pairs(session) do
      finalrule = string.gsub(finalrule, '%$'..key, '"'..value..'"')
    end
    local perlexpression = loadstring('return '..finalrule)
    if perlexpression == nil then -- fail to compile rule
      ngx.log(ngx.INFO,"failed to compile rule: "..finalrule)
      access = 403
    elseif perlexpression () then
      ngx.log(ngx.INFO,"acces granted for evaluated rule: "..finalrule)
      access = 200
    else -- evaluation failed, access is denied
      ngx.log(ngx.INFO,"acces denied for evaluated rule: "..finalrule)
      access = 403
    end
  end

  return access
end

function compute_access(conf, session)
  local access = 403 -- by default, access is *not* granted
  local matching = false -- by default, no matching rule has applied
  local expression = "" -- the rule to match against the request url
  local default = "" -- the default matching rule is not filled yet

  -- parse locationRules
  for i, elem in ipairs (conf["locationRules"]) do
    expression = elem[1]
    expression = string.gsub(expression, '%(%?%#[^)]*%)', "") -- delete starting comment
    expression = string.gsub(expression, '\\', "%%") -- change \ escape character to %
    ngx.log(ngx.INFO,"processing rule: "..expression.." with request: "..handlerConf['fqdn']..handlerConf['request'])
    if string.match(handlerConf['request'], expression) then
      ngx.log(ngx.INFO,"rule: "..expression.." is applied")
      access = compute_rule(conf, session, elem[2])
      matching = true
      break
    end
    if string.lower(expression) == "default" then
      default = elem[2] -- save default rule for later evaluation
    end
  end

  -- if no matching rule applied, then apply default
  if matching == false and default ~= "" then
    ngx.log(ngx.INFO,"default rule is applied")
    access = compute_rule(conf, session, default)
  elseif matching == false and default == "" then
    ngx.log(ngx.INFO,"No rule has applied (even default one)... Access denied")
  end

  return access
end

----------
-- headers
----------

function set_headers (conf, session)
  local finalkey = ""
  local finalvalue = ""

  if session ~= nil then -- no need to compute headers if no session available
    for key,value in pairs(conf["exportedHeaders"]) do
      finalkey = key
      finalvalue = value
      for k,val in pairs(session) do
        finalvalue = string.gsub(finalvalue, '%$'..k, val)
      end
      finalkey = string.gsub(finalkey, '%"', "")
      finalvalue = string.gsub(finalvalue, '%"', "")
      ngx.log(ngx.INFO,"sending header: "..finalkey.." / "..finalvalue)
      ngx.req.set_header(finalkey, finalvalue)
    end
  end
end


----------
-- options
----------

function compute_vhost_option(conf)
  for key,value in pairs(conf["vhostOptions"]) do
    if key == "vhostMaintenance" then -- default: 0
      if value == "1" then -- set maintenance
        ngx.log(ngx.INFO,"maintenance mode")
        return "maintenance"
      end
    elseif key == "vhostHttps" then -- default: -1
      if value == "-1" then -- default, do nothing
        
      elseif value == "0" then -- http scheme
        ngx.log(ngx.INFO,"force http scheme")
        handlerConf['scheme'] = "http"
      elseif value == "1" then -- https scheme
        ngx.log(ngx.INFO,"force https scheme")
        handlerConf['scheme'] = "https"
      end
    elseif key == "vhostPort" then -- default: -1
      if value ~= "-1" then -- set port
        ngx.log(ngx.INFO,"set port from configuration database: "..value)
        handlerConf['server_port'] = value
      end
    end
  end
  return nil
end


--------------
-- entry point
--------------


local code = 403 -- by default, access is forbidden

local conf = get_soap_configuration()
if handlerConf['cookie'] ~= nil then
  ngx.log(ngx.INFO,"cookie: "..handlerConf['cookie'])
  session = get_soap_session(handlerConf['cookie'])
end

if compute_vhost_option(conf) ~= "maintenance" then
  code = compute_access(conf, session)
else
  ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE) -- service unavailable = 503
end

if code == 200 then
  return 
elseif code == 302 then
  ngx.redirect(handlerConf['lemon_portal'].."?url="..
        enc(handlerConf['scheme']..'://'..handlerConf['fqdn']..':'..handlerConf['server_port']..handlerConf['request']))
elseif code == 403 then
  ngx.exit(ngx.HTTP_FORBIDDEN)
end


