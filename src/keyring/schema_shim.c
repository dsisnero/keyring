#include <libsecret/secret.h>
#include <string.h>
#include <stdlib.h>

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

// Format: "service\0username\0password\0\0" — double-null terminated.
// Caller must free the returned buffer with free().
// Returns NULL if no credentials found.
char *crystal_list_passwords(SecretSchema *schema) {
  GError *error = NULL;
  SecretService *svc = secret_service_get_sync(SECRET_SERVICE_NONE, NULL, &error);
  if (!svc) { if (error) g_error_free(error); return NULL; }

  GList *items = secret_service_search_sync(svc, schema, NULL,
      SECRET_SEARCH_ALL, NULL, &error);
  if (!items) {
    if (error) g_error_free(error);
    else g_object_unref(svc);
    return NULL;
  }

  // First pass: compute total size needed
  size_t total = 0;
  for (GList *cur = items; cur; cur = cur->next) {
    SecretItem *item = cur->data;
    if (!item) continue;

    const char *label = secret_item_get_label(item);
    if (!label) continue;

    // Parse label "service (username)"
    const char *paren = strrchr(label, '(');
    if (!paren || paren == label) continue; // no opening paren or at start
    const char *close = strrchr(paren, ')');
    if (!close) continue;
    size_t svc_len = paren - label;
    while (svc_len > 0 && label[svc_len-1] == ' ') svc_len--; // trim trailing space

    // Load secret
    gboolean loaded = secret_item_load_secret_sync(item, NULL, &error);
    if (!loaded) { if (error) g_error_free(error); error = NULL; continue; }

    SecretValue *val = secret_item_get_secret(item);
    if (!val) continue;

    const char *pw = secret_value_get_text(val);
    if (!pw) { secret_value_unref(val); continue; }

    total += svc_len + 1;                              // service + \0
    total += (size_t)(paren - label - svc_len - 2) + 1; // username + \0 (between ' ' and '(')
    total += strlen(pw) + 1;                           // password + \0
    secret_value_unref(val);
  }
  if (total == 0) {
    g_list_free_full(items, g_object_unref);
    g_object_unref(svc);
    return NULL;
  }
  total += 1; // final \0 terminator

  // Allocate buffer
  char *result = malloc(total);
  if (!result) {
    g_list_free_full(items, g_object_unref);
    g_object_unref(svc);
    return NULL;
  }

  // Second pass: fill buffer
  char *pos = result;
  for (GList *cur = items; cur; cur = cur->next) {
    SecretItem *item = cur->data;
    if (!item) continue;

    const char *label = secret_item_get_label(item);
    if (!label) continue;
    const char *paren = strrchr(label, '(');
    if (!paren || paren == label) continue;
    const char *close = strrchr(paren, ')');
    if (!close) continue;

    size_t svc_len = paren - label;
    while (svc_len > 0 && label[svc_len-1] == ' ') svc_len--;

    size_t user_len = close - paren - 1;

    gboolean loaded = secret_item_load_secret_sync(item, NULL, &error);
    if (!loaded) { if (error) g_error_free(error); error = NULL; continue; }

    SecretValue *val = secret_item_get_secret(item);
    if (!val) continue;
    const char *pw = secret_value_get_text(val);
    if (!pw) { secret_value_unref(val); continue; }

    size_t pw_len = strlen(pw);

    memcpy(pos, label, svc_len); pos += svc_len; *pos++ = '\0';
    memcpy(pos, paren + 1, user_len); pos += user_len; *pos++ = '\0';
    memcpy(pos, pw, pw_len); pos += pw_len; *pos++ = '\0';
    secret_value_unref(val);
  }
  *pos = '\0'; // double-null terminator

  g_list_free_full(items, g_object_unref);
  g_object_unref(svc);
  return result;
}
