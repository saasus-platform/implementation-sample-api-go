# implementation-sample-api-go

This is a SaaS implementation sample using the SaaSus SDK

See the documentation [API implementation using SaaS Platform](https://docs.saasus.io/docs/implementing-authentication-using-saasus-platform-apiserver)

## Run Go API

```
git clone git@github.com:saasus-platform/implementation-sample-api-go.git
cd ./implementation-sample-api-go

# Set Env for SaaSus Platform API
# Get it in the SaaSus Admin Console
export SAASUS_SAAS_ID="xxxxxxxxxx"
export SAASUS_API_KEY="xxxxxxxxxx"
export SAASUS_SECRET_KEY="xxxxxxxxxx"

go run main.go
```
