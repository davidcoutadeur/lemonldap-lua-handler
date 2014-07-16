-- LUA SSO handler module for LemonLDAP::NG

-- Some variable declarations.

local json = require "json"

--local handlerConf = require('nginx-handler-conf')
local path = string.sub( debug.getinfo(1).short_src,
                         1,
                         string.len(debug.getinfo(1).short_src)-24 )
local confFile = path..'nginx-handler-conf.lua'
ngx.log(ngx.INFO,"loading configuration file "..confFile)
local handlerConf = dofile( confFile )

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

function parse_locationRules (lconf)
  local rules = {}
  local nb = 1


  for a, node in ipairs (lconf) do
    for b, res in ipairs (node) do
      if node.tag == "locationRules" then
        rules[res.tag] = {} -- initialize vhost rules table
        nb = 1
        for i, elem in ipairs (res) do
          if elem.tag ~= "item" then -- only 1 rule
            nb = 1
            rules[res.tag][nb] = { elem.tag, elem[1] } 
                                    -- rules[vhost][numRule] = { ruleName, ruleValue}
          else -- multiple rules to parse
            for k, val in ipairs (elem) do
              if val.tag == "key" then
                rules[res.tag][nb] = { elem[k][1], elem[(k+1)][1] }
                                    -- rules[vhost][numRule] = { ruleName, ruleValue}
                nb = nb + 1
              end
            end
          end
        end
      end
    end
  end
  return rules
end

function parse_exportedHeaders (lconf)
  local headers = {}

  for i, elem in ipairs (lconf) do
    for j, res in ipairs (elem) do
      if elem.tag == "exportedHeaders" then
        headers[res.tag] = {} -- initialize vhost headers table
        for i, elem in ipairs (res) do
          headers[res.tag][elem.tag] = elem[1] -- options[vhost][optName] = optVal
        end
      end
    end
  end
  return headers
end

function parse_vhostOptions (lconf)
  local options = {}

  for i, elem in ipairs (lconf) do
    for j, res in ipairs (elem) do
      if elem.tag == "vhostOptions" then
        options[res.tag] = {} -- initialize vhost options table
        for i, elem in ipairs (res) do
          options[res.tag][elem.tag] = elem[1] -- options[vhost][optName] = optVal
        end
      end
    end
  end
  return options
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

  conf["locationRules"] = parse_locationRules(ent[1])
  conf["exportedHeaders"] = parse_exportedHeaders(ent[1])
  conf["vhostOptions"] = parse_vhostOptions(ent[1])

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
  local config = conf["locationRules"][handlerConf['fqdn']]
  local access = 403 -- by default, access is *not* granted
  local matching = false -- by default, no matching rule has applied
  local expression = "" -- the rule to match against the request url
  local default = "" -- the default matching rule is not filled yet

  -- parse locationRules
  for i, elem in ipairs (config) do
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
  local config = conf["exportedHeaders"][handlerConf['fqdn']]
  local finalkey = ""
  local finalvalue = ""

  if session ~= nil then -- no need to compute headers if no session available
    for key,value in pairs(config) do
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
  local config = conf["vhostOptions"][handlerConf['fqdn']]
  for key,value in pairs(config) do
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


--
-- Get configuration from cache or lemon soap portal
--
local lemonSharedConf = handlerConf['lemonSharedConf']
local confValue = lemonSharedConf:get('lemonSharedConf')
                                          -- get configuration from local cache
local conf = nil -- final configuration
if confValue == nil or
   os.time() > json.decode( confValue )['expires'] then
                       -- conf not in cache or cache expired
  conf = get_soap_configuration() -- get configuration from lemon portal
  conf['expires'] = os.time() + 60*handlerConf['lemonSharedConfExpires']
  local succ, err, forcible =
                      lemonSharedConf:set("lemonSharedConf", json.encode(conf))
                                                  -- set configuration in cache
  if succ ~= true then
    ngx.log(ngx.ERR,"storing configuration into local cache: "..err)
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end
else
  ngx.log(ngx.INFO,"Configuration loading from cache")
  conf = json.decode( confValue ) -- get configuration from cache
end


--
-- Get session from cache or lemon soap portal
--
if handlerConf['cookie'] ~= nil then -- if lemonCookie is present
  ngx.log(ngx.INFO,"cookie: "..handlerConf['cookie'])

  local lemonSharedSession = handlerConf['lemonSharedSession']
  local sessionValue = lemonSharedSession:get(handlerConf['cookie'])
                                                -- get session from local cache
  if sessionValue == nil or
     os.time() > json.decode( sessionValue )['expires'] then
                                      -- session not in cache or cache expired
    session = get_soap_session(handlerConf['cookie'])
                                               -- get session from lemon portal
    session['expires'] = os.time() + 60*handlerConf['lemonSharedSessionExpires']
    
    if next(session) ~= nil then -- session has been found
      local succ, err, forcible =
            lemonSharedSession:set(handlerConf['cookie'], json.encode(session))
                                                  -- set session in cache
      if succ ~= true then
        ngx.log(ngx.ERR,"storing session into local cache: "..err)
        ngx.exit(ngx.HTTP_FORBIDDEN)
      end
    end
  else -- session already in cache
    ngx.log(ngx.INFO,"Session loading from cache")
    session = json.decode( sessionValue ) -- get session from cache
  end
end


-- checking if the vhost is declared in LemonLDAP::NG and if maintenance mode
if conf["vhostOptions"][handlerConf['fqdn']] ~= nil
     and compute_vhost_option(conf) ~= "maintenance" then
  code = compute_access(conf, session)
else
  ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE) -- service unavailable = 503
end

if code == 200 then
  return 
elseif code == 302 then
  ngx.redirect(handlerConf['lemon_portal'].."?url="..
        enc(handlerConf['scheme']..'://'..handlerConf['fqdn']..':'..
            handlerConf['server_port']..handlerConf['request']))
elseif code == 403 then
  ngx.exit(ngx.HTTP_FORBIDDEN)
end





