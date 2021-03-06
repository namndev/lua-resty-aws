-- generate amazon v4 authorization signature
-- https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
-- Author: namnd.bka@gmail.com

local json = require "json"
local ltn12 = require "ltn12"
local https = require "ssl.https"
local resty_sha256 = require 'resty.sha256'
local resty_hmac   = require 'resty.hmac'
local str  = require 'resty.string'

-- config variable
local aws_key, aws_secret, aws_region, aws_scheme, user_agent
-- intern variable
local iso_date, iso_tz, cont_type, req_body, aws_host 

local _M = {
  _VERSION = '0.1'
}

local mt = { __index = _M }

local aws_service = "acm"

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
  aws_scheme  = config.aws_scheme or 'https'
  cont_type   = config.content_type  or "application/x-amz-json-1.1"
  user_agent  = config.user_agent
  -- set default time
  aws_host = string.format( "%s.%s.amazonaws.com", aws_service, aws_region)
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

-- required for testing
function _M.set_iso_date(self, timestamp)
  iso_date = os.date('!%Y%m%d', timestamp)
  iso_tz   = os.date('!%Y%m%dT%H%M%SZ', timestamp)
end

function _M.get_signed_headers(self)
  return 'content-type;host;x-amz-date;x-amz-target'
end

-- create canonical headers
-- header must be sorted asc
function _M.get_canonical_header(self, amz_target)
  local h = {
    'content-type:' .. cont_type,
    'host:' .. aws_host,
    'x-amz-date:' .. iso_tz,
    'x-amz-target:' .. amz_target
  }
  return table.concat(h, '\n')
end

function _M.get_signed_request_body(self, req_body)
  local digest = self:get_sha256_digest(req_body or '')
  return string.lower(digest) -- hash must be in lowercase hex string
end

-- get canonical request
-- https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
function _M.get_canonical_request(self, amz_target, opts)
  local signed_header = self:get_signed_headers()
  local canonical_header = self:get_canonical_header(amz_target)
  local signed_body = self:get_signed_request_body(opts.req_body)
  local param  = {
    opts.req_method or 'POST',
    opts.req_path or '/', -- req_path
    opts.req_querystr or '', -- canonical querystr
    canonical_header,
    '',   -- required
    signed_header,
    signed_body
  }
  local canonical_request = table.concat(param, '\n')
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
function _M.get_string_to_sign(self, amz_target, opts)
  local param = { iso_date, aws_region, aws_service, 'aws4_request' }
  local cred  = table.concat(param, '/')
  local req   = self:get_canonical_request(amz_target, opts)
  return table.concat({ ALGORITHM, iso_tz, cred, req}, '\n')
end

-- generate signature
function _M.get_signature(self, amz_target, opts)
  local  signing_key = self:get_signing_key()
  local  string_to_sign = self:get_string_to_sign(amz_target, opts)
  return str.to_hex(self:hmac(signing_key, string_to_sign))
end


-- get authorization string
-- x-amz-content-sha256 required by s3
function _M.get_authorization_header(self, amz_target, opts)
  local  param = { aws_key, iso_date, aws_region, aws_service, 'aws4_request' }
  local header = {
    ALGORITHM .. ' Credential=' .. table.concat(param, '/'),
    'SignedHeaders='.. self:get_signed_headers(),
    'Signature=' .. self:get_signature(amz_target, opts)
  }
  return table.concat(header, ', ')
end

-- @see https://docs.aws.amazon.com/acm/latest/APIReference/API_ListCertificates.html
-- Retrieves a list of certificate ARNs and domain names.
function _M.list_certificates(self)
  local response = {}
  local get_list_url = string.format( "%s://%s",aws_scheme, aws_host)
  local req_method = "POST"
  local amz_target = "CertificateManager.ListCertificates"
  local req_body="{}"
  local opts =  {
    req_method = req_method,
    req_body = req_body
  }
  local authorization = self:get_authorization_header(amz_target, opts)
  ngx.log(ngx.DEBUG, "Authorization: ", authorization)
  local res, code, headers, status = https.request{
      url = get_list_url,
      method = req_method,
      headers = {
          ["Content-Length"] = req_body:len(),
          ["X-Amz-Target"] = amz_target,
          ["X-Amz-Date"] = iso_tz,
          ["Content-Type"] = cont_type,
          ["Authorization"] = authorization
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

-- @see https://docs.aws.amazon.com/acm/latest/APIReference/API_GetCertificate.html
-- Retrieves a certificate specified by an ARN and its certificate chain
function _M.get_certificate(self, certificate_arn)
    local response = {}
    local get_cert_url = string.format( "%s://%s",aws_scheme, aws_host)
    local amz_target = "CertificateManager.GetCertificate"
    local req_method = "POST"
    local req_body = string.format( "{\"CertificateArn\": \"%s\"}", certificate_arn)
    local opts =  {
      req_method = req_method,
      req_body = req_body
    }
    local authorization = self:get_authorization_header(amz_target, opts)
    ngx.log(ngx.DEBUG, "Authorization: ", authorization)
    local res, code, headers, status = https.request{
        url = get_cert_url,
        method = req_method,
        headers = {
            ["Content-Length"] = req_body:len(),
            ["X-Amz-Target"] = amz_target,
            ["X-Amz-Date"] = iso_tz,
            ["Content-Type"] = cont_type,
            ["Authorization"] = authorization
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

-- @see https://docs.aws.amazon.com/acm/latest/APIReference/API_DescribeCertificate.html
-- Returns detailed metadata about the specified ACM certificate.
function _M.describe_certificate( self, certificate_arn )
  local response = {}
  local get_des_url = string.format( "%s://%s",aws_scheme, aws_host)
  local amz_target = "CertificateManager.DescribeCertificate"
  local req_method = "POST"
  local req_body = string.format( "{\"CertificateArn\": \"%s\"}", certificate_arn)
  local opts =  {
    req_method = req_method,
    req_body = req_body
  }
  local authorization = self:get_authorization_header(amz_target, opts)
  ngx.log(ngx.DEBUG, "Authorization: ", authorization)
  local res, code, headers, status = https.request{
      url = get_des_url,
      method = req_method,
      headers = {
          ["Content-Length"] = req_body:len(),
          ["X-Amz-Target"] = amz_target,
          ["X-Amz-Date"] = iso_tz,
          ["Content-Type"] = cont_type,
          ["Authorization"] = authorization
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

-- get the current timestamp in iso8601 basic format
function _M.get_date_header()
  return iso_tz
end

return _M