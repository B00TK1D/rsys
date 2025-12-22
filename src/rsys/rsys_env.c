#include "src/rsys/rsys_internal.h"

#include <stdlib.h>
#include <string.h>

int fetch_remote_env(int sock, uint8_t **out_blob, uint32_t *out_len) {
  struct rsys_resp resp;
  uint8_t *data = NULL;
  uint32_t data_len = 0;
  if (rsys_call(sock, RSYS_REQ_GETENV, NULL, 0, &resp, &data, &data_len) < 0) return -1;
  int64_t rr = rsys_resp_raw_ret(&resp);
  int32_t eno = rsys_resp_err_no(&resp);
  if (rr == -1) {
    free(data);
    errno = (eno != 0) ? eno : EIO;
    return -1;
  }
  *out_blob = data;
  *out_len = data_len;
  return 0;
}

char **envp_from_nul_blob(uint8_t *blob, uint32_t len) {
  if (!blob || len == 0) {
    char **envp = (char **)calloc(1, sizeof(char *));
    return envp;
  }
  if (blob[len - 1] != '\0') {
    // Ensure termination.
    uint8_t *nb = (uint8_t *)realloc(blob, (size_t)len + 1);
    if (!nb) return NULL;
    nb[len] = '\0';
    blob = nb;
    len++;
  }
  size_t n = 0;
  for (uint32_t i = 0; i < len; i++) {
    if (blob[i] == '\0') n++;
  }
  char **envp = (char **)calloc(n + 1, sizeof(char *));
  if (!envp) return NULL;
  size_t idx = 0;
  char *p = (char *)blob;
  char *end = (char *)blob + len;
  while (p < end) {
    size_t sl = strlen(p);
    if (sl == 0) break;
    envp[idx++] = p;
    p += sl + 1;
  }
  envp[idx] = NULL;
  return envp;
}

const char *envp_get_value(char **envp, const char *key) {
  if (!envp || !key) return NULL;
  size_t klen = strlen(key);
  for (size_t i = 0; envp[i]; i++) {
    const char *s = envp[i];
    if (strncmp(s, key, klen) == 0 && s[klen] == '=') return s + klen + 1;
  }
  return NULL;
}
