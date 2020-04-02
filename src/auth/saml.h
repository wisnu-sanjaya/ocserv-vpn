/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#ifndef SAML_H
#define SAML_H

#ifdef HAVE_SAML

#include <config.h>
#include <sec-mod-auth.h>
#include <lasso/lasso.h>
#include "common-config.h"
#include <lasso/xml/saml-2.0/samlp2_authn_request.h>

struct saml_vhost_ctx {
    saml_cfg_st *config;
    LassoServer *server;
};

struct saml_ctx_st {
    char username[MAX_USERNAME_SIZE*2];
    struct saml_vhost_ctx *vctx;
    LassoLogin *login;
    LassoSamlp2AuthnRequest *request;
    char *saml_response;
};

extern const struct auth_mod_st saml_auth_funcs;

#endif
#endif