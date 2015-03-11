lemonldap-lua-handler
=====================

A basic handler with cache feature for LemonLDAP::NG websso

Howto install
-------------

* install nginx
tested on debian: nginx-extras 1.4.1
apt-get install nginx-extras

* install lua, luarocks (for dependancies and for installing luasoap), lua-sec, lua-json, and libexpat1-dev
apt-get install luarocks lua-sec lua-json libexpat1-dev

* install luasoap thanks to luarocks
luasoap debian version is buggy on debian wheezy 27/11/2013
luarocks install luasoap

* copy every files from the archive to /opt/sso

* configure nginx to use the handler:

in /etc/nginx/nginx.conf, add this line into the http{ } directive:
lua_package_path "/opt/sso/?.lua;;"; # inform nginx where to find lua standard libraries


in /etc/nginx/sites-enabled/default, in http section (outside of server section), add:
lua_shared_dict lemonSharedConf 1m;
lua_shared_dict lemonSharedSession 100m;

So 1Mb will be used for configuration, and 100Mb for sessions

in /etc/nginx/sites-enabled/default, configure the desired location like this one (reverse proxy):
        location / {
                access_by_lua_file /opt/sso/nginx-handler-access.lua;
                #try_files $uri $uri/ /index.html;
                proxy_pass http://backend_host:80/;
        }

Optional step:
Additionally, you can put this directive in the location scope:
lua_code_cache off;
So the code will be loaded each time a request is done.
Warning: this will impact performances badly
(the bad cookie recuperation due to cookie caching is solved with the
directive dofile for loading the configuration file)


* fill the configuration file:
/opt/sso/nginx-handler-conf.lua
in most case, the conf['lemon_portal'] variable should be sufficient

* configure lemonldap to hold SOAP configuration backend AND SOAP session backend
http://lemonldap-ng.org/documentation/latest/soapconfbackend
http://lemonldap-ng.org/documentation/latest/soapsessionbackend

* add a virtual host corresponding to your nginx site with an adapted port



features available
------------------
* read configuration and session from lemonldap-ng portal in SOAP (and SOAP only)
* location rules (but no regexp is allowed into the rule) However, expressions such as $uid eq 'somebody' is working
* vhost options (but no alias for now)
* exported headers

drawbacks / improvements
------------------------
(ordered by priority: from the most urgent / grave to the less urgent / grave)
* limited support for regexp. For example:
   - locations like ^/*.(css|js) is not working (and can never be unless missing regex features are coded)
   - no regexp at all for rules. $uid =~ /somebody/ does not work
* the code could be distributed into a few modules (4 or 5)
* aliases are not taken into consideration (can be improved, but not easily)
  (notice: serveralias apache directives are available in nginx as server_name directives)
* it is quite sure that some other features from apache handler are still missing

