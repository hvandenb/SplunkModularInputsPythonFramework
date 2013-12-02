[yammer://<name>]

* Yammer REST API Endpoint Base URL
yammer_api_endpoint_base_url= <value>

* Yammer Access Authentication Token
yammer_access_token= <value>

* Yammer Client Id
yammer_client_id= <value>

* Yammer Client Secret
yammer_client_secret= <value>

* Yammer REST API Endpoint Path
yammer_api_endpoint_path= <value>

* prop=value, prop2=value2
http_header_propertys= <value>

* arg=value, arg2=value2
url_args= <value>

* true | false
streaming_request= <value>

* ie: (http://10.10.1.10:3128 or http://user:pass@10.10.1.10:3128 or https://10.10.1.10:1080 etc...)
http_proxy= <value>
https_proxy= <value>

*in seconds
request_timeout= <value>

* time to wait for reconnect after timeout or error
backoff_time = <value>

*in seconds
polling_interval= <value>

* whether or not to index http error response codes
index_error_response_codes= <value>

*Python classname of custom response handler
response_handler= <value>

*Response Handler arguments string ,  key=value,key2=value2
response_handler_args= <value>

*Python Regex pattern, if present , the response will be scanned for this match pattern, and indexed if a match is present
response_filter_pattern = <value>

*Delimiter to use for any multi "key=value" field inputs
delimiter= <value>





