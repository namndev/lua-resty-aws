# lua-resty-aws
AWS ACM and S3 for OpenResty + Lua

## Overview
This library implements request signing using the AWS Signature Version 4 specification. This signature scheme is used by nearly all AWS services.

## Installation

```bash
git clone https://github.com/namndbka/lua-resty-aws.git
cp -R lua-resty-aws/lib/resty <your_lua_lib_path>
```

## Example

Currently, this library support some method of `aws acm` and `aws s3`.

### `acm`

```lua
local json = require "json"
local aws_acm = require "resty.aws-acm"

local config = {
    aws_key        = "<AWS_KEY>",
    aws_secret     = "<AWS_SECRET_KEY>",
    aws_region     = "<AWS_REGION>",
    user_agent     = "<YOUR_AGENT>"
  }

function demo_cert()
  local acm = aws_acm:new(config)
  local list_cert, status = acm:list_certificates()
  ngx.log(ngx.INFO, 'status: ', status)
  local list_o = json.decode(list_cert)
  local listArrs = list_o["CertificateSummaryList"]
  local cert_arn = nil
  for i = 1, table.getn(listArrs) do 
    if(listArrs[i]["DomainName"] == "*.example.com") then
      cert_arn = listArrs[i]["CertificateArn"]
      break
    end
  end
  if (cert_arn ~= nil) then
    ngx.say("==== GET CERTIFICATE ====")
    local get_cert, status1 = acm:get_certificate(cert_arn)
    ngx.say(get_cert)
    ngx.say("==== DESCRIBE CERTIFICATE ====")
    local des_cert, status2 = acm:describe_certificate(cert_arn)
    ngx.say(des_cert)
  end
end

local ac = demo_cert()
```

### `s3`

```lua
local json = require "json"
local aws_s3 = require "resty.aws-s3"

local config = {
    aws_key        = "<AWS_KEY>",
    aws_secret     = "<AWS_SECRET_KEY>",
    aws_region     = "<AWS_REGION>",
    user_agent     = "<YOUR_AGENT>"
}
local s3 = aws_s3:new(config)
local buckets, status = s3:list_buckets()
ngx.log(ngx.INFO, "list_buckets status: ", status)
if(buckets ~= nil) then
    for k, p in pairs(buckets.Buckets) do
        for i = 1, table.getn(p) do
            ngx.say(json.encode(p[i]))
        end
    end
end

 -- get all objects in bucket `bucket_name`
local objects, status = s3:list_objects('bucket_name')
ngx.log(ngx.INFO, "list_objects status: ", status)
if(objects ~= nil) then
    for i, p in pairs(objects.Contents) do
        ngx.say(json.encode(p))
    end
end
local cres, status = s3:create_bucket('bucket_name')
ngx.log(ngx.INFO, "create_bucket status: ", status)
ngx.say(cres)

local file, status = s3:download_file('bucket_name', 'key')
ngx.log(ngx.INFO, "download_file status: ", status)
```