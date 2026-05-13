#include <libsecret/secret.h>

// Crystal-compatible wrapper to avoid variadic FFI issues on ARM64.
// Creates a SecretSchema with 2 attributes.
SecretSchema *crystal_secret_schema_create(const char *name,
                                            const char *attr0_name, SecretSchemaAttributeType attr0_type,
                                            const char *attr1_name, SecretSchemaAttributeType attr1_type) {
  return secret_schema_new(name, SECRET_SCHEMA_NONE,
                           attr0_name, attr0_type,
                           attr1_name, attr1_type,
                           NULL);
}
