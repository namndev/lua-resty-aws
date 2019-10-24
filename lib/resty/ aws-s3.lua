-- generate amazon v4 authorization signature
-- https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
-- Author: namnd.bka@gmail.com

local json = require "json"
local ltn12 = require "ltn12"
local https = require "ssl.https"
local resty_sha256 = require 'resty.sha256'
local resty_hmac   = require 'resty.hmac'
local str  = require 'resty.string'
local xml2lua = require "xml2lua"
local handler = require "xmlhandler.tree"

-- variable in config
local aws_key, aws_secret, aws_region, aws_scheme, user_agent 
-- intern variable
local iso_date, iso_tz, aws_host

local _M = {
  _VERSION = '0.1'
}

local mt = { __index = _M }

local aws_service = "s3"

local ALGORITHM = "AWS4-HMAC-SHA256"

https.TIMEOUT = 5

-- init new aws auth
function _M.new(self, config)

  config = config or {}
  if type(config) ~= 'table' then
      ngx.log(ngx.ERROR, 'InvalidArgument', string.format(
        'invalid config: %s, is not a table, is type: %s',
        tostring(config), type(config)))
      return nil
  end
  aws_key     = config.aws_key
  aws_secret  = config.aws_secret
  aws_region  = config.aws_region
  user_agent  = config.user_agent
  aws_scheme  = config.aws_scheme or 'https'
  -- set default time
  aws_host = string.format( "s3.%s.amazonaws.com", aws_region)
  local timestamp = tonumber(ngx.time())
  self:set_iso_date(timestamp)
  return setmetatable(_M, mt)
end

-- generate sha256 from the given string
function _M.get_sha256_digest(self, s)
  local h = resty_sha256:new()
  h:update(s or '')
  return str.to_hex(h:final())
end


function _M.hmac(self, secret, message)
  local hmac_sha256 = resty_hmac:new(secret, resty_hmac.ALGOS.SHA256)
  hmac_sha256:update(message)
  return hmac_sha256:final()
end

function isempty(s)
  return s == nil or s == ''
end

-- required for testing
function _M.set_iso_date(self, timestamp)
  iso_date = os.date('!%Y%m%d', timestamp)
  iso_tz   = os.date('!%Y%m%dT%H%M%SZ', timestamp)
end

function _M.get_signed_headers(self)
  return 'host;x-amz-content-sha256;x-amz-date'
end

-- create canonical headers
-- header must be sorted asc
function _M.get_canonical_header(self, bucket_name, req_body)
  local content_hash = self:get_signed_request_body(req_body or '')
  local host = aws_host
  if not isempty(bucket_name) then 
    host = string.format( "%s.%s", bucket_name, aws_host )
  end
  local h = {
    'host:' .. host,
    'x-amz-content-sha256:' .. content_hash,
    'x-amz-date:' .. iso_tz,
  }
  return table.concat(h, '\n')
end

function _M.get_signed_request_body(self, req_body)
  local digest = self:get_sha256_digest(req_body or '')
  return string.lower(digest) -- hash must be in lowercase hex string
end

-- get canonical request
-- https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
function _M.get_canonical_request(self, opts)
  local signed_header = self:get_signed_headers()
  local canonical_header = self:get_canonical_header(opts.bucket_name, opts.req_body)
  local signed_body = self:get_signed_request_body(opts.req_body)
  local param  = {
    opts.req_method or 'GET',
    opts.req_path or '/', -- req_path
    opts.req_querystr or '', -- canonical querystr ''
    canonical_header,
    '',   -- required
    signed_header,
    signed_body
  }
  local canonical_request = table.concat(param, '\n')
  ngx.log(ngx.INFO, 'canonical_request:\n', canonical_request)
  return self:get_sha256_digest(canonical_request)
end

-- get signing key
-- https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
function _M.get_signing_key(self)
  local  k_date    = self:hmac('AWS4' .. aws_secret, iso_date)
  local  k_region  = self:hmac(k_date, aws_region)
  local  k_service = self:hmac(k_region, aws_service)
  local  k_signing = self:hmac(k_service, 'aws4_request')
  return k_signing
end

-- get string
function _M.get_string_to_sign(self, opts)
  local param = { iso_date, aws_region, aws_service, 'aws4_request' }
  local cred  = table.concat(param, '/')
  local req   = self:get_canonical_request(opts)
  return table.concat({ ALGORITHM, iso_tz, cred, req}, '\n')
end

-- generate signature
function _M.get_signature(self, opts)
  local  signing_key = self:get_signing_key()
  local  string_to_sign = self:get_string_to_sign(opts)
  ngx.log(ngx.INFO, 'StringToSign:\n', string_to_sign)
  return str.to_hex(self:hmac(signing_key, string_to_sign))
end

-- get authorization string
-- x-amz-content-sha256 required by s3
function _M.get_authorization_header(self, opts)
  local  param = { aws_key, iso_date, aws_region, aws_service, 'aws4_request' }
  local header = {
    ALGORITHM .. ' Credential=' .. table.concat(param, '/'),
    'SignedHeaders='.. self:get_signed_headers(),
    'Signature=' .. self:get_signature(opts)
  }
  return table.concat(header, ', ')
end

-- @see https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html
-- return ListAllMyBucketsResult, msg if success
-- Returns a list of all buckets owned by the authenticated sender of the request.
function _M.list_buckets(self)
  local response = {}
  local req_method = "GET"
  local req_body=""
  local url = string.format( "%s://%s", aws_scheme, aws_host)
  local opts = {
    req_method     = req_method,
    req_body       = req_body
  }
  local authorization = self:get_authorization_header(opts)
  ngx.log(ngx.DEBUG, "Authorization: ", authorization)
  local res, code, headers, status = https.request{
      url = url,
      method = req_method,
      headers = {
          ["X-Amz-Content-SHA256"] = self:get_signed_request_body(req_body),
          ["Authorization"] = authorization,
          ["X-Amz-Date"] = iso_tz,
          ["User-Agent"] = user_agent
      },
      source = ltn12.source.string(req_body),
      sink = ltn12.sink.table(response)
  }
  if code == 200 then
      response = table.concat(response)
      local parser = xml2lua.parser(handler)
      parser:parse(response) 
      return handler.root.ListAllMyBucketsResult, status
  else
    ngx.log(ngx.DEBUG, status)
    ngx.log(ngx.DEBUG, json.encode(headers))
    return nil, status
  end
end

-- @see https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
-- return ListBucketResult, msg if success
-- Returns some or all (up to 1,000) of the objects in a bucket
function _M.list_objects(self, bucket_name, query_opts)
  if isempty(bucket_name) then
    ngx.log(ngx.ERROR, 'ParamError:', 'Bucket name is not empty')
    return nil, "ParamError: Bucket name is not empty"
  end
  local response = {}
  local req_method = "GET"
  local req_body=""
  query_opts = query_opts or {}
  if type(query_opts) ~= 'table' then
    return nil, 'InvalidArgument', string.format(
      'invalid query_opts: %s, is not a table, is type: %s',
      tostring(query_opts), type(query_opts))
  end
  local req_querystr = string.format( "delimiter=%s&encoding-type=%s&list-type=2&prefix=%s", ngx.escape_uri(query_opts.delimiter or '/'), query_opts.encoding or 'url', query_opts.prefix or '')
  local url = string.format( "%s://%s.%s/?%s", aws_scheme, bucket_name, aws_host, req_querystr)
  local opts = {
    bucket_name    = bucket_name,
    req_method     = req_method,
    req_body       = req_body,
    req_querystr   = req_querystr
  }
  local authorization = self:get_authorization_header(opts)
  ngx.log(ngx.DEBUG, "Authorization: ", authorization)
  local res, code, headers, status = https.request{
      url = url,
      method = req_method,
      headers = {
          ["X-Amz-Content-SHA256"] = self:get_signed_request_body(req_body),
          ["Authorization"] = authorization,
          ["X-Amz-Date"] = iso_tz,
          ["User-Agent"] = user_agent
      },
      source = ltn12.source.string(req_body),
      sink = ltn12.sink.table(response)
  }
  if code == 200 then
      response = table.concat(response)
      local parser = xml2lua.parser(handler)
      parser:parse(response) 
      return handler.root.ListBucketResult, status
  else
    ngx.log(ngx.DEBUG, status)
    ngx.log(ngx.DEBUG, json.encode(headers))
    return nil, status
  end
end

-- @see https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html
-- Creates a new bucket
function _M.create_bucket(self, bucket_name)
  if isempty(bucket_name) then
    ngx.log(ngx.ERROR, 'ParamError:', 'Bucket name is not empty')
    return nil, "ParamError: Bucket name is not empty"
  end
  local response = {}
  local req_method = "PUT"
  local req_body = string.format("<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>%s</LocationConstraint></CreateBucketConfiguration>", aws_region)
  local url =  string.format( "%s://%s.%s", aws_scheme, bucket_name, aws_host)
  local opts = {
    bucket_name    = bucket_name,
    req_method     = req_method,
    req_body       = req_body
  }
  local authorization = self:get_authorization_header(opts)
  ngx.log(ngx.DEBUG, "Authorization: ", authorization)
  local res, code, headers, status = https.request{
      url = url,
      method = req_method,
      headers = {
          ["X-Amz-Content-SHA256"] = self:get_signed_request_body(req_body),
          ["Content-Length"] = req_body:len(),
          ["Authorization"] = authorization,
          ["X-Amz-Date"] = iso_tz,
          ["User-Agent"] = user_agent
      },
      source = ltn12.source.string(req_body),
      sink = ltn12.sink.table(response)
  }
  if code == 200 then
      return table.concat(response), status
  else
    ngx.log(ngx.DEBUG, status)
    ngx.log(ngx.DEBUG, json.encode(headers))
    return nil, status
  end
end

-- @see https://docs.aws.amazon.com/cli/latest/reference/s3/cp.html
-- file_out: default /opt/tmp/{file_key}
-- return File if success
function _M.download_file(self, bucket_name, file_key, file_out)
  if isempty(bucket_name) or isempty(file_key) then
    ngx.log(ngx.ERROR, 'ParamError:', 'Bucket name and key are not empty')
    return nil, "ParamError: Bucket name and key are not empty"
  end
  file_key = ngx.escape_uri(file_key)
  local response = {}
  local req_method = "HEAD"
  local req_body = ""
  local get_file_url =  string.format( "%s://%s.%s/%s", aws_scheme, bucket_name, aws_host, file_key)
  local opts = {
    bucket_name    = bucket_name,
    req_method     = req_method,
    req_path       = "/"..file_key,
    req_body       = req_body
  }
  local authorization = self:get_authorization_header(opts)
  ngx.log(ngx.INFO, "Authorization: ", authorization)
  local file = ltn12.sink.file(io.open(file_out or '/opt/tmp/'..file_key, 'w'))
  local res, code, headers, status = https.request{
      url = get_file_url,
      method = req_method,
      headers = {
          ["X-Amz-Content-SHA256"] = self:get_signed_request_body(req_body),
          ["Content-Length"] = req_body:len(),
          ["Authorization"] = authorization,
          ["X-Amz-Date"] = iso_tz,
          ["User-Agent"] = user_agent
      },
      source = ltn12.source.string(req_body),
      sink = file
  }
  if code == 200 then
      return file, status
  else
    ngx.log(ngx.INFO, status)
    ngx.log(ngx.INFO, json.encode(headers))
    return nil, status
  end
end


return _M