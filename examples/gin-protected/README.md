# Protected Gin service

This example demonstrates exact-audience verification, dynamic resource derivation, strict revocation, trusted stateless environment context, and atomic limited-use consumption.

```sh
export UPSILON_ISSUER=https://auth.internal
export UPSILON_CONSUMPTION_TOKEN=secret-manager-value
export APP_ENVIRONMENT=prod
go run ./examples/gin-protected
```

It intentionally refuses plaintext metadata/control-plane URLs. For a local-only experiment, adapt the constructor with `AllowInsecureHTTP: true` and pass `true` to `client.NewConsumer`; do not carry those values into production.
