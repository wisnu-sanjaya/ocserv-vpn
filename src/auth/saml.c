/*
 * Copyright (C) 2020 
 *
 * Author: Morgan MacKechnie
 *
 * This file is part of ocserv.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif
#include "inih/ini.h"

#ifdef HAVE_SAML
#include "saml.h"
#include <lasso/lasso.h>
#include <lasso/xml/saml-2.0/samlp2_response.h>
#include "auth/lasso_compat.h"
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <apr-1.0/apr_time.h>

static int cfg_ini_handler(void *_config, const char *section, const char *name,
			   const char *_value)
{
	saml_cfg_st *config = _config;
	size_t len;

	len = strlen(_value);
	if (strcmp(name, "sp-metadata-file") == 0) {
		config->spmeta = strndup(_value, len);
	} else if (strcmp(name, "sp-keyfile") == 0) {
		config->spkey = strndup(_value, len);
	} else if (strcmp(name, "sp-cert") == 0) {
		config->spcert = strndup(_value, len);
	} else if (strcmp(name, "idp-metadata-file") == 0) {
		config->idpmeta = strndup(_value, len);
	} else if (strcmp(name, "idp-cert") == 0) {
		config->idpcert = strndup(_value, len);
	}
	return (1);
}

// Parse the saml subconfig and construct a Lasso server object.
static void saml_vhost_init(void **_vctx, void *pool, void *additional)
{
	saml_cfg_st *config = additional;
	struct saml_vhost_ctx *vctx;
	lasso_error_t ret;

	ini_parse(config->config, cfg_ini_handler, config);

	vctx = talloc_zero(pool, struct saml_vhost_ctx);

	lasso_init();
	vctx->server =
	    lasso_server_new(config->spmeta, config->spkey, NULL,
			     config->spcert);
	if (vctx->server == NULL) {
		fprintf(stderr,
			"Error initialasing Lasso SAML server object. Check configuration. It's almost always the metadata.\n");
		exit(1);
	}
	ret =
	    lasso_server_add_provider(vctx->server, LASSO_PROVIDER_ROLE_IDP,
				      config->idpmeta, NULL, NULL);
	if (ret != 0) {
		fprintf(stderr,
			"Error loading identity provider. Check configuration.\n");
		exit(1);
	}
	GList *idp_list;
	idp_list = g_hash_table_get_keys(vctx->server->providers);
	config->idpname = idp_list->data;
	config->idp_sso_dest_url =
	    lasso_server_get_endpoint_url_by_id(vctx->server, config->idpname,
						"SingleSignOnService HTTP-Redirect");
	config->acs_url =
	    lasso_provider_get_assertion_consumer_service_url((void *)vctx->
							      server, NULL);
	vctx->config = config;
	*_vctx = (void *)vctx;

	/* We need saml sp metadata in a predictable location for worker processes to serve upon request
	 * only the secure module seems to have any notion of where it lies, so lets drop a copy in /tmp */
	char *tmpSpMetaFile = "/tmp/spmeta.xml";
	FILE *fptrSrc, *fptrDest;
	char c;

	fptrSrc = fopen(config->spmeta, "r");
	fptrDest = fopen(tmpSpMetaFile, "w");

	c = fgetc(fptrSrc);
	while (c != EOF) {
		fputc(c, fptrDest);
		c = fgetc(fptrSrc);
	}

	fclose(fptrSrc);
	fclose(fptrDest);
}

// Initialise a login object
static int saml_auth_init(void **_ctx, void *pool, void *_vctx,
			  const common_auth_init_st * info)
{
	struct saml_ctx_st *ctx;
	struct saml_vhost_ctx *vctx = _vctx;
	int ret;

	ctx = talloc_zero(pool, struct saml_ctx_st);

	ctx->login = lasso_login_new(vctx->server);
	ret =
	    lasso_login_init_authn_request(ctx->login, vctx->config->idpname,
					   LASSO_HTTP_METHOD_REDIRECT);
	if (ret != 0) {
		fprintf(stderr, "Lasso error: [%i] %s\n", ret,
			lasso_strerror(ret));
		exit(1);
	}

	ctx->request =
	    LASSO_SAMLP2_AUTHN_REQUEST(LASSO_PROFILE(ctx->login)->request);
	if (ctx->request->NameIDPolicy == NULL) {
		fprintf(stderr, "Error creating login request\n");
		exit(1);
	}

	ctx->request->ForceAuthn = FALSE;
	ctx->request->IsPassive = FALSE;
	ctx->request->NameIDPolicy->AllowCreate = TRUE;

	if (LASSO_SAMLP2_REQUEST_ABSTRACT(ctx->request)->Destination == NULL) {
		lasso_assign_string(LASSO_SAMLP2_REQUEST_ABSTRACT
				    (ctx->request)->Destination,
				    vctx->config->idp_sso_dest_url);
	}
//  lasso_assign_string(ctx->request->AssertionConsumerServiceURL, vctx->config->acs_url);

	LASSO_SAMLP2_REQUEST_ABSTRACT(ctx->request)->Consent
	    = g_strdup(LASSO_SAML2_CONSENT_IMPLICIT);

	ret = lasso_login_build_authn_request_msg(ctx->login);
	if (ret != 0) {
		fprintf(stderr, "aww crap failed building authn request");
	}

	ctx->vctx = vctx;	//save this for later, we'll need it in later functions where the sec module doesn't pass it to us

	*_ctx = (void *)ctx;

	return (ERR_AUTH_CONTINUE);
}

static int saml_auth_msg(void *_ctx, void *pool, passwd_msg_st * pst)
{
	struct saml_ctx_st *ctx = _ctx;
	char *redirect_url;

	redirect_url = LASSO_PROFILE(ctx->login)->msg_url;

	pst->msg_str = talloc_strdup(pool, (char *)redirect_url);

	pst->counter = 0;

	return 0;
}

static int saml_unhex_digit(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'a' && c <= 'f') {
		return c - 'a' + 0xa;
	} else if (c >= 'A' && c <= 'F') {
		return c - 'A' + 0xa;
	} else {
		return -1;
	}
}

int saml_urldecode(char *data)
{
	char *ip;
	char *op;
	int c1, c2;

	if (data == NULL) {
		return -1;
	}

	ip = data;
	op = data;
	while (*ip) {
		switch (*ip) {
		case '+':
			*op = ' ';
			ip++;
			op++;
			break;
		case '%':
			/* Decode the hex digits. Note that we need to check the
			 * result of the first conversion before attempting the
			 * second conversion -- otherwise we may read past the end
			 * of the string.
			 */
			c1 = saml_unhex_digit(ip[1]);
			if (c1 < 0) {
				return -1;
			}
			c2 = saml_unhex_digit(ip[2]);
			if (c2 < 0) {
				return -1;
			}

			*op = (c1 << 4) | c2;
			if (*op == '\0') {
				/* null-byte. */
				return -1;
			}
			ip += 3;
			op++;
			break;
		default:
			*op = *ip;
			ip++;
			op++;
		}
	}
	*op = '\0';

	return 0;
}

static apr_time_t saml_parse_timestamp(const char *timestamp)
{
	size_t len;
	int i;
	char c;
	const char *expected;
	apr_time_exp_t time_exp;
	apr_time_t res;
	apr_status_t rc;

	len = strlen(timestamp);

	/* Verify length of timestamp. */
	if (len < 20) {
		fprintf(stderr, "Invalid length of timestamp: \"%s\".",
			timestamp);
	}

	/* Verify components of timestamp. */
	for (i = 0; i < len - 1; i++) {
		c = timestamp[i];

		expected = NULL;

		switch (i) {

		case 4:
		case 7:
			/* Matches "    -  -            " */
			if (c != '-') {
				expected = "'-'";
			}
			break;

		case 10:
			/* Matches "          T         " */
			if (c != 'T') {
				expected = "'T'";
			}
			break;

		case 13:
		case 16:
			/* Matches "             :  :   " */
			if (c != ':') {
				expected = "':'";
			}
			break;

		case 19:
			/* Matches "                   ." */
			if (c != '.') {
				expected = "'.'";
			}
			break;

		default:
			/* Matches "YYYY MM DD hh mm ss uuuuuu" */
			if (c < '0' || c > '9') {
				expected = "a digit";
			}
			break;
		}

		if (expected != NULL) {
			fprintf(stderr,
				"Invalid character in timestamp at position %i.\nExpected %s, got '%c'. Full timestamp: \"%s\"",
				i, expected, c, timestamp);
			return 0;
		}
	}

	if (timestamp[len - 1] != 'Z') {
		fprintf(stderr,
			"Timestamp wasn't in UTC (did not end with 'Z').\n Full timestamp: \"%s\"",
			timestamp);
		return 0;
	}

	time_exp.tm_usec = 0;
	if (len > 20) {
		/* Subsecond precision. */
		if (len > 27) {
			/* Timestamp has more than microsecond precision. Just clip it to
			 * microseconds.
			 */
			len = 27;
		}
		len -= 1;	/* Drop the 'Z' off the end. */
		for (i = 20; i < len; i++) {
			time_exp.tm_usec =
			    time_exp.tm_usec * 10 + timestamp[i] - '0';
		}
		for (i = len; i < 26; i++) {
			time_exp.tm_usec *= 10;
		}
	}

	time_exp.tm_sec = (timestamp[17] - '0') * 10 + (timestamp[18] - '0');
	time_exp.tm_min = (timestamp[14] - '0') * 10 + (timestamp[15] - '0');
	time_exp.tm_hour = (timestamp[11] - '0') * 10 + (timestamp[12] - '0');
	time_exp.tm_mday = (timestamp[8] - '0') * 10 + (timestamp[9] - '0');
	time_exp.tm_mon = (timestamp[5] - '0') * 10 + (timestamp[6] - '0') - 1;
	time_exp.tm_year = (timestamp[0] - '0') * 1000 +
	    (timestamp[1] - '0') * 100 + (timestamp[2] - '0') * 10 +
	    (timestamp[3] - '0') - 1900;

	time_exp.tm_wday = 0;	/* Unknown. */
	time_exp.tm_yday = 0;	/* Unknown. */

	time_exp.tm_isdst = 0;	/* UTC, no daylight savings time. */
	time_exp.tm_gmtoff = 0;	/* UTC, no offset from UTC. */

	rc = apr_time_exp_gmt_get(&res, &time_exp);
	if (rc != APR_SUCCESS) {
		fprintf(stderr, "Error converting timestamp \"%s\".",
			timestamp);
		return 0;
	}

	return res;
}

static int saml_validate_subject(LassoSaml2Assertion * assertion,
				 const char *url)
{
	apr_time_t now;
	apr_time_t t;
	LassoSaml2SubjectConfirmation *sc;
	LassoSaml2SubjectConfirmationData *scd;

	if (assertion->Subject == NULL) {
		/* No Subject to validate. */
		return 0;
	} else if (!LASSO_IS_SAML2_SUBJECT(assertion->Subject)) {
		fprintf(stderr, "Wrong type of Subject node.\n");
		return -1;
	}

	if (assertion->Subject->SubjectConfirmation == NULL) {
		/* No SubjectConfirmation. */
		return 0;
	} else
	    if (!LASSO_IS_SAML2_SUBJECT_CONFIRMATION
		(assertion->Subject->SubjectConfirmation)) {
		fprintf(stderr, "Wrong type of SubjectConfirmation node.\n");
		return -1;
	}

	sc = assertion->Subject->SubjectConfirmation;
	if (sc->Method == NULL ||
	    strcmp(sc->Method, "urn:oasis:names:tc:SAML:2.0:cm:bearer")) {
		fprintf(stderr, "Invalid Method in SubjectConfirmation.\n");
		return -1;
	}

	scd = sc->SubjectConfirmationData;
	if (scd == NULL) {
		/* Nothing to verify. */
		return 0;
	} else if (!LASSO_IS_SAML2_SUBJECT_CONFIRMATION_DATA(scd)) {
		fprintf(stderr,
			"Wrong type of SubjectConfirmationData node.\n");
		return -1;
	}

	now = apr_time_now();

	if (scd->NotBefore) {
		t = saml_parse_timestamp(scd->NotBefore);
		if (t == 0) {
			fprintf(stderr,
				"Invalid timestamp in NotBefore in SubjectConfirmationData.\n");
			return -1;
		}
		if (t - 60000000 > now) {
			fprintf(stderr,
				"NotBefore in SubjectConfirmationData was in the future.\n");
			return -1;
		}
	}

	if (scd->NotOnOrAfter) {
		t = saml_parse_timestamp(scd->NotOnOrAfter);
		if (t == 0) {
			fprintf(stderr,
				"Invalid timestamp in NotOnOrAfter in SubjectConfirmationData.\n");
			return -1;
		}
		if (now >= t + 60000000) {
			fprintf(stderr,
				"NotOnOrAfter in SubjectConfirmationData was in the past.\n");
			return -1;
		}
	}

	if (scd->Recipient) {
		if (strcmp(scd->Recipient, url)) {
			fprintf(stderr,
				"Wrong Recipient in SubjectConfirmationData. Current URL is: %s, Recipient is %s\n",
				url, scd->Recipient);
			return -1;
		}
	}

	return 0;
}

static int saml_auth_pass(void *_ctx, const char *saml_response,
			  unsigned pass_len)
{
	struct saml_ctx_st *ctx = _ctx;
	int rc;
	LassoSamlp2Response *response;
	LassoSaml2Assertion *assertion;
	const char *name_id;

	//rc = saml_urldecode(saml_response); // Parse function out in worker-auth.c does this for us, how kind

	rc = lasso_login_process_authn_response_msg(ctx->login,
						    (gchar *) saml_response);
	if (rc != 0) {
		fprintf(stderr, "Error processing authn response\n");
		fprintf(stderr, "lasso error: [%i] %s\n", rc,
			lasso_strerror(rc));
		goto auth_fail;
	}

	if (LASSO_PROFILE(ctx->login)->nameIdentifier == NULL) {
		fprintf(stderr,
			"No acceptable name identifier found in SAML 2.0 response.\n");
		goto auth_fail;
	}

	name_id =
	    LASSO_SAML2_NAME_ID(LASSO_PROFILE(ctx->login)->nameIdentifier)->
	    content;
	strncpy(ctx->username, name_id, strlen(name_id));
	response = LASSO_SAMLP2_RESPONSE(LASSO_PROFILE(ctx->login)->response);

	if (response->parent.Destination) {
		if (strcmp
		    (response->parent.Destination,
		     ctx->vctx->config->acs_url)) {
			fprintf(stderr,
				"Invalid Destination on Response. Should be %s, but was %s\n",
				ctx->vctx->config->acs_url,
				response->parent.Destination);
			goto auth_fail;
		}
	}

	if (g_list_length(response->Assertion) == 0) {
		fprintf(stderr, "No assertion in response.\n");
		goto auth_fail;
	}

	if (g_list_length(response->Assertion) > 1) {
		fprintf(stderr, "More than one assertion in response.\n");
		goto auth_fail;
	}

	assertion = g_list_first(response->Assertion)->data;
	if (!LASSO_IS_SAML2_ASSERTION(assertion)) {
		fprintf(stderr, "Wrong type of assertion node.\n");
		goto auth_fail;
	}

	rc = saml_validate_subject(assertion, ctx->vctx->config->acs_url);

	return 0;

 auth_fail:
	lasso_login_destroy(ctx->login);
	return ERR_AUTH_FAIL;
}

static int saml_auth_user(void *_ctx, char *username, int username_size)
{
	struct saml_ctx_st *ctx = _ctx;

	strlcpy(username, ctx->username, username_size);

	return 0;
}

void saml_auth_deinit(void *_ctx)
{
	struct saml_ctx_st *ctx = _ctx;

	lasso_login_destroy(ctx->login);
}

const struct auth_mod_st saml_auth_funcs = {
	.type = AUTH_TYPE_SAML,
	.vhost_init = saml_vhost_init,
	.auth_init = saml_auth_init,
//  .vhost_deinit = saml_vhost_deinit,
	.auth_deinit = saml_auth_deinit,
	.auth_msg = saml_auth_msg,
	.auth_pass = saml_auth_pass,
	.auth_user = saml_auth_user,
	.auth_group = NULL,
	.group_list = NULL
};

#endif