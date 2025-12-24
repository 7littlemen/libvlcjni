/*****************************************************************************
 * resource.c: HTTP resource common code
 *****************************************************************************
 * Copyright (C) 2015 Rémi Denis-Courmont
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ctype.h>

#include <vlc_common.h>
#include <vlc_url.h>
#include <vlc_strings.h>
#include "message.h"
#include "connmgr.h"
#include "resource.h"

static bool vlc_http_header_name_is_forbidden(const char *name)
{
    static const char *const forbidden[] = {
        "Host",
        "Range",
        "Connection",
        "Accept-Encoding",
        "Content-Length",
        "Transfer-Encoding",
        "Cookie",
    };

    for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++)
        if (!vlc_ascii_strcasecmp(name, forbidden[i]))
            return true;
    return false;
}

static bool vlc_http_header_name_is_valid(const char *name)
{
    if (name == NULL || *name == '\0')
        return false;

    for (const unsigned char *p = (const unsigned char *)name; *p != '\0'; p++)
    {
        if (isalnum(*p) || *p == '-' || *p == '_')
            continue;
        return false;
    }
    return true;
}

static char *vlc_http_strdup_trim(const char *start, size_t len)
{
    while (len > 0 && isspace((unsigned char)start[0]))
    {
        start++;
        len--;
    }
    while (len > 0 && isspace((unsigned char)start[len - 1]))
        len--;

    char *out = malloc(len + 1);
    if (out == NULL)
        return NULL;
    memcpy(out, start, len);
    out[len] = '\0';
    return out;
}

static char *vlc_http_strdup_trim_value(const char *start, size_t len)
{
    while (len > 0 && (start[0] == ' ' || start[0] == '\t'))
    {
        start++;
        len--;
    }
    while (len > 0 && (start[len - 1] == ' ' || start[len - 1] == '\t'
                    || start[len - 1] == '\r'))
        len--;

    char *out = malloc(len + 1);
    if (out == NULL)
        return NULL;
    memcpy(out, start, len);
    out[len] = '\0';
    return out;
}

static void vlc_http_custom_headers_clear(struct vlc_http_resource *res)
{
    for (size_t i = 0; i < res->custom_headers_count; i++)
    {
        free(res->custom_headers[i].name);
        free(res->custom_headers[i].value);
    }
    free(res->custom_headers);
    res->custom_headers = NULL;
    res->custom_headers_count = 0;
}

static bool vlc_http_custom_headers_add(struct vlc_http_resource *res,
                                        const char *name, const char *value)
{
    struct vlc_http_custom_header *headers =
        realloc(res->custom_headers,
                (res->custom_headers_count + 1) * sizeof(*headers));
    if (headers == NULL)
        return false;

    res->custom_headers = headers;
    char *name_copy = strdup(name);
    char *value_copy = strdup(value);

    if (name_copy == NULL || value_copy == NULL)
    {
        free(name_copy);
        free(value_copy);
        return false;
    }

    res->custom_headers[res->custom_headers_count].name = name_copy;
    res->custom_headers[res->custom_headers_count].value = value_copy;
    res->custom_headers_count++;
    return true;
}

static void vlc_http_custom_headers_parse(struct vlc_http_resource *res,
                                         const char *custom_headers)
{
    if (custom_headers == NULL || *custom_headers == '\0')
        return;

    const char *p = custom_headers;
    while (*p != '\0')
    {
        const char *line = p;
        const char *nl = strchr(p, '\n');
        size_t line_len = (nl != NULL) ? (size_t)(nl - line) : strlen(line);
        p = (nl != NULL) ? (nl + 1) : (line + line_len);

        while (line_len > 0 && (line[line_len - 1] == '\r' || line[line_len - 1] == '\n'))
            line_len--;

        const char *s = line;
        size_t s_len = line_len;
        while (s_len > 0 && isspace((unsigned char)s[0]))
        {
            s++;
            s_len--;
        }
        if (s_len == 0)
            continue;

        const char *colon = memchr(s, ':', s_len);
        if (colon == NULL)
        {
            if (res->logger)
                msg_Dbg(res->logger, "HTTP custom header skipped (invalid): %.*s",
                        (int)s_len, s);
            continue;
        }

        char *name = vlc_http_strdup_trim(s, (size_t)(colon - s));
        char *value = vlc_http_strdup_trim_value(colon + 1,
                                                 s_len - (size_t)((colon + 1) - s));
        if (name == NULL || value == NULL)
        {
            free(name);
            free(value);
            if (res->logger)
                msg_Dbg(res->logger, "HTTP custom header skipped (oom)");
            continue;
        }

        if (!vlc_http_header_name_is_valid(name))
        {
            if (res->logger)
                msg_Dbg(res->logger, "HTTP custom header skipped (invalid name): %s", name);
            free(name);
            free(value);
            continue;
        }

        if (vlc_http_header_name_is_forbidden(name))
        {
            if (res->logger)
                msg_Dbg(res->logger, "HTTP custom header filtered: %s", name);
            free(name);
            free(value);
            continue;
        }

        if (vlc_http_custom_headers_add(res, name, value) && res->logger)
            msg_Dbg(res->logger, "HTTP custom header added: %s: %s", name, value);

        free(name);
        free(value);
    }
}

static struct vlc_http_msg *
vlc_http_res_req(const struct vlc_http_resource *res, void *opaque)
{
    struct vlc_http_msg *req;

    req = vlc_http_req_create("GET", res->secure ? "https" : "http",
                              res->authority, res->path);
    if (unlikely(req == NULL))
        return NULL;

    /* Content negotiation */
    vlc_http_msg_add_header(req, "Accept", "*/*");

    if (res->negotiate)
    {
        const char *lang = vlc_gettext("C");
        if (!strcmp(lang, "C"))
            lang = "en_US";
        vlc_http_msg_add_header(req, "Accept-Language", "%s", lang);
    }

    /* Authentication */
    if (res->username != NULL && res->password != NULL)
        vlc_http_msg_add_creds_basic(req, false, res->username, res->password);

    /* Request context */
    if (res->agent != NULL)
        vlc_http_msg_add_agent(req, res->agent);

    if (res->referrer != NULL) /* TODO: validate URL */
        vlc_http_msg_add_header(req, "Referer", "%s", res->referrer);

    vlc_http_msg_add_cookies(req, vlc_http_mgr_get_jar(res->manager));

    /* TODO: vlc_http_msg_add_header(req, "TE", "gzip, deflate"); */

    if (res->cbs->request_format(res, req, opaque))
    {
        vlc_http_msg_destroy(req);
        return NULL;
    }

    for (size_t i = 0; i < res->custom_headers_count; i++)
    {
        vlc_http_msg_add_header(req, res->custom_headers[i].name, "%s",
                                res->custom_headers[i].value);
        if (res->logger)
            msg_Dbg(res->logger, "HTTP request custom header: %s: %s",
                    res->custom_headers[i].name, res->custom_headers[i].value);
    }

    return req;
}

struct vlc_http_msg *vlc_http_res_open(struct vlc_http_resource *res,
                                       void *opaque)
{
    struct vlc_http_msg *req;
retry:
    req = vlc_http_res_req(res, opaque);
    if (unlikely(req == NULL))
        return NULL;

    struct vlc_http_msg *resp = vlc_http_mgr_request(res->manager, res->secure,
                                       res->host, res->port, req, true, false);
    vlc_http_msg_destroy(req);

    resp = vlc_http_msg_get_final(resp);
    if (resp == NULL)
        return NULL;

    vlc_http_msg_get_cookies(resp, vlc_http_mgr_get_jar(res->manager),
                             res->host, res->path);

    int status = vlc_http_msg_get_status(resp);
    if (status < 200 || status >= 599)
        goto fail;

    if (status == 406 && res->negotiate)
    {   /* Not Acceptable: Content negotiation failed. Normally it means
         * one (or more) Accept or Accept-* header line does not match any
         * representation of the entity. So we set a flag to remove those
         * header lines (unless they accept everything), and retry.
         * In principles, it could be any header line, and the server can
         * pass Vary to clarify. It cannot be caused by If-*, Range, TE or the
         * other transfer- rather than representation-affecting header lines.
         */
        vlc_http_msg_destroy(resp);
        res->negotiate = false;
        goto retry;
    }

    if (res->cbs->response_validate(res, resp, opaque))
        goto fail;

    return resp;
fail:
    vlc_http_msg_destroy(resp);
    return NULL;
}

int vlc_http_res_get_status(struct vlc_http_resource *res)
{
    if (res->response == NULL)
    {
        if (res->failure)
            return -1;

        res->response = vlc_http_res_open(res, res + 1);
        if (res->response == NULL)
        {
            res->failure = true;
            return -1;
        }
    }
    return vlc_http_msg_get_status(res->response);
}

static void vlc_http_res_deinit(struct vlc_http_resource *res)
{
    vlc_http_custom_headers_clear(res);
    free(res->referrer);
    free(res->agent);
    free(res->password);
    free(res->username);
    free(res->path);
    free(res->authority);
    free(res->host);

    if (res->response != NULL)
        vlc_http_msg_destroy(res->response);
}

void vlc_http_res_destroy(struct vlc_http_resource *res)
{
    vlc_http_res_deinit(res);
    free(res);
}

int vlc_http_res_init(struct vlc_http_resource *restrict res,
                      const struct vlc_http_resource_cbs *cbs,
                      struct vlc_http_mgr *mgr,
                      const char *uri, const char *ua, const char *ref,
                      const char *custom_headers, vlc_object_t *logger)
{
    vlc_url_t url;
    bool secure;

    if (vlc_UrlParse(&url, uri))
        goto error;
    if (url.psz_protocol == NULL || url.psz_host == NULL)
    {
        errno = EINVAL;
        goto error;
    }

    if (!vlc_ascii_strcasecmp(url.psz_protocol, "https"))
        secure = true;
    else if (!vlc_ascii_strcasecmp(url.psz_protocol, "http"))
        secure = false;
    else
    {
        errno = ENOTSUP;
        goto error;
    }

    res->cbs = cbs;
    res->response = NULL;
    res->secure = secure;
    res->negotiate = true;
    res->failure = false;
    res->logger = logger;
    res->custom_headers = NULL;
    res->custom_headers_count = 0;
    res->host = strdup(url.psz_host);
    res->port = url.i_port;
    res->authority = vlc_http_authority(url.psz_host, url.i_port);
    res->username = (url.psz_username != NULL) ? strdup(url.psz_username)
                                               : NULL;
    res->password = (url.psz_password != NULL) ? strdup(url.psz_password)
                                               : NULL;
    res->agent = (ua != NULL) ? strdup(ua) : NULL;
    res->referrer = (ref != NULL) ? strdup(ref) : NULL;

    vlc_http_custom_headers_parse(res, custom_headers);

    const char *path = url.psz_path;
    if (path == NULL)
        path = "/";

    if (url.psz_option != NULL)
    {
        if (asprintf(&res->path, "%s?%s", path, url.psz_option) == -1)
            res->path = NULL;
    }
    else
        res->path = strdup(path);

    vlc_UrlClean(&url);
    res->manager = mgr;

    if (unlikely(res->host == NULL || res->authority == NULL
              || res->path == NULL))
    {
        vlc_http_res_deinit(res);
        return -1;
    }
    return 0;
error:
    vlc_UrlClean(&url);
    return -1;
}

char *vlc_http_res_get_redirect(struct vlc_http_resource *restrict res)
{
    int status = vlc_http_res_get_status(res);
    if (status < 0)
        return NULL;

    if ((status / 100) == 2 && !res->secure)
    {
        char *url;

        /* HACK: Seems like an MMS server. Redirect to MMSH scheme. */
        const char *pragma = vlc_http_msg_get_header(res->response, "Pragma");
        if (pragma != NULL && !vlc_ascii_strcasecmp(pragma, "features")
         && asprintf(&url, "mmsh://%s%s", res->authority, res->path) >= 0)
            return url;

        /* HACK: Seems like an ICY server. Redirect to ICYX scheme. */
        if ((vlc_http_msg_get_header(res->response, "Icy-Name") != NULL
          || vlc_http_msg_get_header(res->response, "Icy-Genre") != NULL)
         && asprintf(&url, "icyx://%s%s", res->authority, res->path) >= 0)
            return url;
    }

    /* TODO: if (status == 426 Upgrade Required) */

    /* Location header is only meaningful for 201 and 3xx */
    if (status != 201 && (status / 100) != 3)
        return NULL;
    if (status == 304 /* Not Modified */
     || status == 305 /* Use Proxy (deprecated) */
     || status == 306 /* Switch Proxy (former) */)
        return NULL;

    const char *location = vlc_http_msg_get_header(res->response, "Location");
    if (location == NULL)
        return NULL;

    /* TODO: if status is 3xx, check for Retry-After and wait */

    char *base;

    if (unlikely(asprintf(&base, "http%s://%s%s", res->secure ? "s" : "",
                          res->authority, res->path) == -1))
        return NULL;

    char *fixed = vlc_uri_fixup(location);
    if (fixed != NULL)
        location = fixed;

    char *abs = vlc_uri_resolve(base, location);

    free(fixed);
    free(base);

    if (likely(abs != NULL))
    {
        /* NOTE: The anchor is discarded if it is present as VLC does not support
         * HTML anchors so far. */
        size_t len = strcspn(abs, "#");
        abs[len] = '\0';
    }
    return abs;
}

char *vlc_http_res_get_type(struct vlc_http_resource *res)
{
    int status = vlc_http_res_get_status(res);
    if (status < 200 || status >= 300)
        return NULL;

    const char *type = vlc_http_msg_get_header(res->response, "Content-Type");
    return (type != NULL) ? strdup(type) : NULL;
}

block_t *vlc_http_res_read(struct vlc_http_resource *res)
{
    int status = vlc_http_res_get_status(res);
    if (status < 200 || status >= 300)
        return NULL; /* do not "read" redirect or error message */

    return vlc_http_msg_read(res->response);
}

int vlc_http_res_set_login(struct vlc_http_resource *res,
                           const char *username, const char *password)
{
    char *user = NULL;
    char *pass = NULL;

    if (username != NULL)
    {
        user = strdup(username);
        if (unlikely(user == NULL))
            return -1;

        pass = strdup((password != NULL) ? password : "");
        if (unlikely(pass == NULL))
        {
            free(user);
            return -1;
        }
    }

    free(res->password);
    free(res->username);
    res->username = user;
    res->password = pass;

    if (res->response != NULL && vlc_http_msg_get_status(res->response) == 401)
    {
        vlc_http_msg_destroy(res->response);
        res->response = NULL;
    }

    return 0;
}

char *vlc_http_res_get_basic_realm(struct vlc_http_resource *res)
{
    int status = vlc_http_res_get_status(res);
    if (status != 401)
        return NULL;
    return vlc_http_msg_get_basic_realm(res->response);
}
