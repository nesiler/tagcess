package render

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var signOutClientID = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,128}$`)

const signOutFallback = "/oauth2/sign_out?rd=%2F"

// SignOutPath is the link that really signs a user out (J1): oauth2-proxy clears the shared gate
// cookie and then redirects (rd) to the Zitadel end_session endpoint, which ends the Zitadel session and
// returns to returnURL (a registered post-logout redirect URI). Without a client id it falls back to the
// plain oauth2-proxy sign-out, which leaves the Zitadel session open. Every input is validated and the
// result holds only unreserved characters and percent escapes, so it is safe in HTML and in a Caddyfile
// backtick string.
func SignOutPath(issuer, clientID, returnURL string) (string, error) {
	if clientID == "" {
		return signOutFallback, nil
	}
	if !signOutClientID.MatchString(clientID) {
		return "", fmt.Errorf("sign-out: invalid gate client id")
	}
	iss, err := url.Parse(issuer)
	if err != nil || iss.Scheme != "https" || iss.Host == "" || iss.User != nil || iss.RawQuery != "" || iss.Fragment != "" {
		return "", fmt.Errorf("sign-out: issuer must be a plain https URL")
	}
	ret, err := url.Parse(returnURL)
	if err != nil || ret.Scheme != "https" || ret.Host == "" || ret.User != nil || ret.Fragment != "" {
		return "", fmt.Errorf("sign-out: return URL must be an absolute https URL")
	}
	endSession := strings.TrimSuffix(iss.String(), "/") + "/oidc/v1/end_session?" + url.Values{
		"client_id":                {clientID},
		"post_logout_redirect_uri": {returnURL},
	}.Encode()
	return "/oauth2/sign_out?rd=" + url.QueryEscape(endSession), nil
}
